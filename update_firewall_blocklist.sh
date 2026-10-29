#!/usr/bin/env bash
#
# Apply an aggregated IPv4 blocklist to an ipset and two dedicated iptables chains.
#
# Design notes:
#   * the list must be root-owned: a file writable by an unprivileged account must
#     never reach the kernel firewall;
#   * every ipset/iptables call is checked, so a failed swap is a failed run;
#   * the block set is built out of band and swapped in atomically;
#   * management addresses come from ALLOW_FILE and are RETURNed before the DROP.
#
# Usage: update_firewall_blocklist.sh [LIST_FILE]

set -euo pipefail

LIST_FILE="${1:-/var/lib/ip-list-aggregator/merged-ip-list.txt}"
SET_NAME="${SET_NAME:-bad_ips_set}"
ALLOW_SET="${ALLOW_SET:-ip_allow_set}"
ALLOW_FILE="${ALLOW_FILE:-/etc/ip-list-allow.txt}"
CHAIN_IN="${CHAIN_IN:-IPBLOCK_IN}"
CHAIN_OUT="${CHAIN_OUT:-IPBLOCK_OUT}"
MAX_ELEMS="${MAX_ELEMS:-500000}"
MIN_PREFIX="${MIN_PREFIX:-8}"
LOCK_FILE="${LOCK_FILE:-/run/lock/ip-list-apply.lock}"
VALID_LINE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --- preconditions ---------------------------------------------------------
[[ ${EUID} -eq 0 ]] || die "must run as root (use sudo)"

if [[ -L ${LIST_FILE} ]]; then
    die "refusing symlinked list: ${LIST_FILE}"
fi
[[ -f ${LIST_FILE} ]] || die "list not found: ${LIST_FILE}"
[[ -s ${LIST_FILE} ]] || die "list is empty: ${LIST_FILE}"

list_owner=$(stat -c '%u' "${LIST_FILE}")
[[ ${list_owner} -eq 0 ]] || die "list must be owned by root, found uid ${list_owner}: ${LIST_FILE}"

# --- single instance -------------------------------------------------------
exec 9>"${LOCK_FILE}"
flock -n 9 || die "another apply is already running (lock: ${LOCK_FILE})"

# --- validate content before it reaches the kernel -------------------------
total=$(wc -l < "${LIST_FILE}")
[[ ${total} -gt 0 ]] || die "list has no entries: ${LIST_FILE}"

malformed=$(grep -cvE "${VALID_LINE}" "${LIST_FILE}" || true)
if [[ ${malformed} -ne 0 ]]; then
    first=$(grep -nvE "${VALID_LINE}" "${LIST_FILE}" | head -n 1)
    die "${malformed} malformed line(s) in ${LIST_FILE} (first: ${first})"
fi

wide=$(awk -F/ -v min="${MIN_PREFIX}" 'NF == 2 && $2 + 0 < min { print; exit }' "${LIST_FILE}")
[[ -z ${wide} ]] || die "implausible network rejected (prefix < /${MIN_PREFIX}): ${wide}"

unique=$(awk '!seen[$1]++' "${LIST_FILE}" | wc -l)

# --- allow set: never block management paths -------------------------------
ipset create "${ALLOW_SET}" hash:net family inet -exist || die "cannot create ${ALLOW_SET}"
ipset flush "${ALLOW_SET}" || die "cannot flush ${ALLOW_SET}"
if [[ -f ${ALLOW_FILE} ]]; then
    while read -r cidr _rest; do
        [[ -z ${cidr} || ${cidr} == \#* ]] && continue
        ipset add "${ALLOW_SET}" "${cidr}" -exist || die "cannot add ${cidr} to ${ALLOW_SET}"
    done < "${ALLOW_FILE}"
fi

# --- build the new block set out of band -----------------------------------
TEMP="${SET_NAME}_temp"
ipset create "${TEMP}" hash:net family inet maxelem "${MAX_ELEMS}" -exist || die "cannot create ${TEMP}"
ipset flush "${TEMP}" || die "cannot flush ${TEMP}"

if ! awk '!seen[$1]++ { print "add '"${TEMP}"' " $1 }' "${LIST_FILE}" | ipset restore; then
    ipset destroy "${TEMP}" || true
    die "failed to load entries into ${TEMP}; live set untouched"
fi

loaded=$(ipset list "${TEMP}" | awk '/Number of entries:/ { print $4 }')
if [[ ${loaded} -ne ${unique} ]]; then
    ipset destroy "${TEMP}" || true
    die "entry count mismatch for ${TEMP}: file=${unique} kernel=${loaded}"
fi

# --- swap atomically -------------------------------------------------------
if ipset -q list "${SET_NAME}" >/dev/null 2>&1; then
    if ! ipset swap "${TEMP}" "${SET_NAME}"; then
        ipset destroy "${TEMP}" || true
        die "swap failed; live set ${SET_NAME} left untouched"
    fi
    ipset destroy "${TEMP}" || log "warning: could not destroy ${TEMP}"
else
    if ! ipset rename "${TEMP}" "${SET_NAME}"; then
        ipset destroy "${TEMP}" || true
        die "rename failed; ${SET_NAME} not created"
    fi
fi

applied=$(ipset list "${SET_NAME}" | awk '/Number of entries:/ { print $4 }')
if [[ ${applied} -ne ${unique} ]]; then
    die "post-swap verification failed: ${SET_NAME} has ${applied} entries, expected ${unique}"
fi

# --- link to INPUT/OUTPUT through dedicated chains -------------------------
ensure_chain() {
    local parent=${1} chain=${2} direction=${3}
    if ! iptables -S "${chain}" >/dev/null 2>&1; then
        iptables -N "${chain}" || die "cannot create chain ${chain}"
    fi
    iptables -F "${chain}" || die "cannot flush chain ${chain}"
    iptables -A "${chain}" -m set --match-set "${ALLOW_SET}" "${direction}" -j RETURN \
        || die "cannot add allow rule to ${chain}"
    iptables -A "${chain}" -m set --match-set "${SET_NAME}" "${direction}" -j DROP \
        || die "cannot add drop rule to ${chain}"
    if ! iptables -C "${parent}" -j "${chain}" >/dev/null 2>&1; then
        iptables -I "${parent}" 1 -j "${chain}" || die "cannot jump ${parent} -> ${chain}"
    fi
}

ensure_chain INPUT "${CHAIN_IN}" src
ensure_chain OUTPUT "${CHAIN_OUT}" dst

# --- persistence, reported honestly ---------------------------------------
if command -v netfilter-persistent >/dev/null 2>&1; then
    if ! netfilter-persistent save; then
        log "warning: netfilter-persistent save failed; rules will not survive a reboot"
    fi
else
    log "note: netfilter-persistent not found; rules will not survive a reboot"
fi

log "Applied ${applied} entries to ${SET_NAME} (allow list: ${ALLOW_FILE})"
exit 0
