#!/usr/bin/env bash
#
# Applier scenarios against stubbed ipset/iptables.
#
# Verifies control flow and return-code handling without touching the real
# firewall: every failure path must exit non-zero and leave the live set alone.
#
# Usage: bash tests/scenarios.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="${HERE}/../update_firewall_blocklist.sh"
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT

pass=0
fail=0

check() { # description, got, want
    if [[ ${2} == "${3}" ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL  %s\n      got: %s\n      want: %s\n' "${1}" "${2}" "${3}"
    fi
}

check_contains() { # description, haystack, needle
    if [[ ${2} == *"${3}"* ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL  %s\n      missing: %s\n      in: %s\n' "${1}" "${3}" "${2}"
    fi
}

mkdir -p "${WORK}/bin" "${WORK}/state"

cat > "${WORK}/bin/ipset" <<'STUB'
#!/bin/bash
echo "ipset $*" >> "${FWLOG}"
cmd=$1; shift
case "${cmd}" in
    create)  touch "${FWSTATE}/${1:-x}"; exit 0 ;;
    flush)   : > "${FWSTATE}/${1:-x}"; exit 0 ;;
    add)     exit 0 ;;
    restore) data=$(cat)
             lines=$(printf '%s\n' "${data}" | grep -c . || true)
             lines=$(( lines - ${DROP_LINES:-0} ))
             target=$(printf '%s\n' "${data}" | awk 'NR==1{print $2}')
             echo "${lines}" > "${FWSTATE}/${target:-_orphan}"
             exit 0 ;;
    list)    printf 'Name: %s\nNumber of entries: %s\n' "${1}" "$(cat "${FWSTATE}/${1}" 2>/dev/null || echo 0)"
             exit 0 ;;
    -q)      if [[ -f "${FWSTATE}/${2}" ]]; then exit 0; else exit 1; fi ;;
    swap)    if [[ "${FAIL_SWAP:-0}" == 1 ]]; then echo "ipset: swap failed" >&2; exit 1; fi
             mv "${FWSTATE}/${1}" "${FWSTATE}/${2}" 2>/dev/null || true
             exit 0 ;;
    rename)  mv "${FWSTATE}/${1}" "${FWSTATE}/${2}" 2>/dev/null || true; exit 0 ;;
    destroy) rm -f "${FWSTATE}/${1}"; exit 0 ;;
    *)       exit 0 ;;
esac
STUB

cat > "${WORK}/bin/iptables" <<'STUB'
#!/bin/bash
echo "iptables $*" >> "${FWLOG}"
[[ "${1}" == "-S" ]] && exit "${CHAIN_EXISTS:-1}"
[[ "${1}" == "-C" ]] && exit "${RULE_EXISTS:-1}"
exit 0
STUB

chmod +x "${WORK}"/bin/*

python3 - "${SCRIPT}" "${WORK}/fw.sh" <<'PY'
"""Build the harness copy: same script, only the two privilege assertions relaxed."""
import pathlib
import sys

source, target = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
text = source.read_text(encoding="utf-8")
replacements = [
    ('[[ ${EUID} -eq 0 ]] || die "must run as root (use sudo)"',
     ': # [harness] euid check relaxed'),
    ("""list_owner=$(stat -c '%u' "${LIST_FILE}")\n[[ ${list_owner} -eq 0 ]] || die "list must be owned by root, found uid ${list_owner}: ${LIST_FILE}\"""",
     ': # [harness] ownership check relaxed'),
]
for old, new in replacements:
    if old not in text:
        sys.exit(f"harness: expected block not found, script changed:\n{old[:80]}")
    text = text.replace(old, new)
target.write_text(text, encoding="utf-8")
PY

[[ -f "${WORK}/fw.sh" ]] || { echo "harness setup failed"; exit 1; }
chmod +x "${WORK}/fw.sh"

allow="${WORK}/allow.txt"
: > "${allow}"

invoke() { # list file, then VAR=value pairs
    local list=$1
    shift
    : > "${WORK}/calls"
    (
        cd "${WORK}" || exit 1
        env FWLOG="${WORK}/calls" FWSTATE="${WORK}/state" LOCK_FILE="${WORK}/lock" \
            ALLOW_FILE="${allow}" PATH="${WORK}/bin:${PATH}" "$@" \
            bash "${WORK}/fw.sh" "${list}" > "${WORK}/out" 2> "${WORK}/err"
    )
    echo $?
}

printf '1.2.3.4/32\n5.6.7.8/32\n' > "${WORK}/list.txt"
printf '0.0.0.0/0\n1.2.3.4/32\n' > "${WORK}/wide.txt"
printf '1.2.3.4/32; rm -rf /\n' > "${WORK}/bad.txt"
: > "${WORK}/empty.txt"

# --- 1: happy path, first run (rename branch) -------------------------------
rc=$(invoke "${WORK}/list.txt" env)
check "happy path exits 0" "${rc}" "0"
check_contains "applier reports the applied count" "$(cat "${WORK}/out")" "Applied 2 entries"
check "allow rule precedes drop rule in the input chain" \
    "$(grep -n 'IPBLOCK_IN -m set' "${WORK}/calls" | cut -d: -f2- | tr '\n' '|')" \
    "iptables -A IPBLOCK_IN -m set --match-set ip_allow_set src -j RETURN|iptables -A IPBLOCK_IN -m set --match-set bad_ips_set src -j DROP|"
check "single jump into the input chain" \
    "$(grep -c 'iptables -I INPUT 1 -j IPBLOCK_IN' "${WORK}/calls")" "1"

# --- 2: failed swap must not report success --------------------------------
echo 1 > "${WORK}/state/bad_ips_set"
rc=$(invoke "${WORK}/list.txt" env FAIL_SWAP=1)
check "failed swap exits non-zero" "${rc}" "1"
check "live set untouched after failed swap" "$(cat "${WORK}/state/bad_ips_set")" "1"
check "no success message after failed swap" "$(grep -c 'Applied' "${WORK}/out")" "0"
check_contains "swap failure is explained" "$(cat "${WORK}/err")" "swap failed"

# --- 3: poisoned list ------------------------------------------------------
rc=$(invoke "${WORK}/wide.txt" env)
check "0.0.0.0/0 is rejected" "${rc}" "1"
check_contains "rejection names the prefix rule" "$(cat "${WORK}/err")" "implausible network rejected"
check "poisoned list never reaches ipset restore" "$(grep -c 'ipset restore' "${WORK}/calls")" "0"

# --- 4: malformed / injection attempt -------------------------------------
rc=$(invoke "${WORK}/bad.txt" env)
check "malformed line is rejected" "${rc}" "1"
check_contains "rejection quotes the offending line" "$(cat "${WORK}/err")" "malformed line"
check "malformed list never reaches ipset restore" "$(grep -c 'ipset restore' "${WORK}/calls")" "0"

# --- 5: kernel silently drops entries -------------------------------------
rc=$(invoke "${WORK}/list.txt" env DROP_LINES=1)
check "entry-count mismatch fails the run" "${rc}" "1"
check "no swap after a count mismatch" "$(grep -c 'ipset swap' "${WORK}/calls")" "0"
check_contains "mismatch is explained" "$(cat "${WORK}/err")" "entry count mismatch"

# --- 6: concurrent run ----------------------------------------------------
(
    exec 9>"${WORK}/lock"
    flock 9
    sleep 3
) &
locker=$!
sleep 0.5
rc=$(invoke "${WORK}/list.txt" env)
check "concurrent run is refused" "${rc}" "1"
check_contains "lock contention is explained" "$(cat "${WORK}/err")" "already running"
wait "${locker}" 2>/dev/null

# --- 7: idempotency -------------------------------------------------------
rc=$(invoke "${WORK}/list.txt" env CHAIN_EXISTS=0 RULE_EXISTS=0)
check "repeat run exits 0" "${rc}" "0"
check "chains are not recreated" "$(grep -c 'iptables -N' "${WORK}/calls")" "0"
check "jump is not inserted twice" "$(grep -c 'iptables -I' "${WORK}/calls")" "0"

# --- 8: empty list --------------------------------------------------------
rc=$(invoke "${WORK}/empty.txt" env)
check "empty list is refused" "${rc}" "1"
check "empty list touches no ipset" "$(grep -c 'ipset ' "${WORK}/calls")" "0"

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[[ ${fail} -eq 0 ]]
