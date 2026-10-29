#!/usr/bin/env bash
#
# Kernel-level acceptance test for update_firewall_blocklist.sh.
#
# Runs INSIDE a privileged container (its own network namespace), so it exercises
# real ipset/iptables: content replacement, allow-list ordering, and an actual
# blocked connection that recovers once the peer is allow-listed.
#
# Usage (from the repo root):
#   docker build -t ip_list_aggregator:test -f tests/Dockerfile .
#   docker run --rm --privileged -v "$PWD:/repo:ro" ip_list_aggregator:test \
#       bash /repo/tests/integration.sh

set -uo pipefail

SCRIPT="${SCRIPT:-/repo/update_firewall_blocklist.sh}"
WORK=$(mktemp -d)
PORT=18080
LISTENER_PID=""
pass=0
fail=0

cleanup() {
    [[ -n ${LISTENER_PID} ]] && kill "${LISTENER_PID}" 2>/dev/null
    ipset destroy bad_ips_set 2>/dev/null || true
    ipset destroy bad_ips_set_temp 2>/dev/null || true
    ipset destroy ip_allow_set 2>/dev/null || true
    iptables -D INPUT -j IPBLOCK_IN 2>/dev/null || true
    iptables -D OUTPUT -j IPBLOCK_OUT 2>/dev/null || true
    iptables -F IPBLOCK_IN 2>/dev/null || true
    iptables -F IPBLOCK_OUT 2>/dev/null || true
    iptables -X IPBLOCK_IN 2>/dev/null || true
    iptables -X IPBLOCK_OUT 2>/dev/null || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

check() {
    if [[ ${2} == "${3}" ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL  %s\n      got: %s\n      want: %s\n' "${1}" "${2}" "${3}"
    fi
}

check_positive() {
    if [[ ${2:-0} =~ ^[0-9]+$ ]] && (( ${2:-0} > 0 )); then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL  %s\n      got: %s\n      want: a positive count\n' "${1}" "${2:-}"
    fi
}

check_contains() {
    if [[ ${2} == *"${3}"* ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL  %s\n      missing: %s\n      in: %s\n' "${1}" "${3}" "${2}"
    fi
}

entries() { ipset list "$1" 2>/dev/null | awk '/Number of entries:/ {print $4}'; }

start_listener() {
    kill "${LISTENER_PID}" 2>/dev/null
    nc -l -p "${PORT}" >/dev/null 2>&1 &
    LISTENER_PID=$!
    sleep 0.4
}

# Can we reach the listener? 0 = yes, non-zero = rejected/dropped.
connect() {
    timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null
    echo $?
}

printf '=== environment ===\n'
ipset --version
iptables --version
printf '\n'

allow="${WORK}/allow.txt"
: > "${allow}"

# --- T1: first apply, loopback peer is in the blocklist ---------------------
printf '203.0.113.0/24\n127.0.0.1/32\n' > "${WORK}/list.txt"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/list.txt" \
    > "${WORK}/out" 2> "${WORK}/err"
rc=$?
check "T1 first apply exits 0" "${rc}" "0"
check "T1 live set has 2 entries" "$(entries bad_ips_set)" "2"
check_contains "T1 reports the applied count" "$(cat "${WORK}/out")" "Applied 2 entries"
check_contains "T1 allow set exists" "$(ipset list -t ip_allow_set 2>&1)" "hash:net"

rule_order=$(iptables -S IPBLOCK_IN | grep -n 'match-set' | cut -d: -f2- | tr '\n' '|')
check_contains "T1 allow rule precedes drop rule" "${rule_order}" "ip_allow_set src -j RETURN|"
check_contains "T1 drop rule is present" "${rule_order}" "bad_ips_set src -j DROP"

# --- T2: the blocked peer cannot connect -----------------------------------
start_listener
connect_rc=$(connect)
check "T2 blocked peer cannot connect (non-zero)" \
    "$([[ ${connect_rc} -ne 0 ]] && echo blocked || echo connected)" "blocked"
check "T2 packet was dropped, not refused (no immediate RST)" \
    "$([[ ${connect_rc} -ne 1 ]] && echo dropped || echo refused)" "dropped"
drop_packets=$(iptables -vnL IPBLOCK_OUT | awk '/bad_ips_set/ {print $1; exit}')
check_positive "T2 drop rule counted the blocked packet" "${drop_packets}"

# --- T3: allow-listing the peer restores the connection --------------------
printf '127.0.0.1/32\n' > "${allow}"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/list.txt" \
    > "${WORK}/out3" 2> "${WORK}/err3"
rc=$?
check "T3 apply with allow-list exits 0" "${rc}" "0"
check "T3 allow set holds the peer" "$(entries ip_allow_set)" "1"
start_listener
check "T3 allow-listed peer can connect (0 = ok)" "$(connect)" "0"

# --- T4: swap really replaces the content ---------------------------------
printf '198.51.100.0/24\n' > "${WORK}/list2.txt"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/list2.txt" \
    > "${WORK}/out4" 2> "${WORK}/err4"
rc=$?
check "T4 second apply exits 0" "${rc}" "0"
check "T4 live set now has 1 entry" "$(entries bad_ips_set)" "1"
ipset test bad_ips_set 198.51.100.0 >/dev/null 2>&1
check "T4 new entry is live" "$?" "0"
ipset test bad_ips_set 203.0.113.0 >/dev/null 2>&1
check "T4 old entry is gone (swap replaced it)" "$?" "1"

# --- T5: idempotency -------------------------------------------------------
before=$(iptables -S INPUT | grep -c 'IPBLOCK_IN')
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/list2.txt" \
    > /dev/null 2>&1
after=$(iptables -S INPUT | grep -c 'IPBLOCK_IN')
check "T5 jump count is stable" "${before}" "1"
check "T5 repeat run does not duplicate the jump" "${after}" "1"

# --- T6: poisoned list is refused before the kernel ------------------------
printf '0.0.0.0/0\n' > "${WORK}/wide.txt"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/wide.txt" \
    > "${WORK}/out6" 2> "${WORK}/err6"
check "T6 poisoned list exits non-zero" "$?" "1"
check_contains "T6 explains the rejection" "$(cat "${WORK}/err6")" "implausible network rejected"
check "T6 live set untouched" "$(entries bad_ips_set)" "1"

# --- T7: malformed line is refused ---------------------------------------
printf '1.2.3.4/32; rm -rf /\n' > "${WORK}/bad.txt"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/bad.txt" \
    > "${WORK}/out7" 2> "${WORK}/err7"
check "T7 malformed line exits non-zero" "$?" "1"
check_contains "T7 explains the rejection" "$(cat "${WORK}/err7")" "malformed line"

# --- T8: non-root-owned list is refused ----------------------------------
cp "${WORK}/list2.txt" "${WORK}/owned.txt"
chown 1000:1000 "${WORK}/owned.txt"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/owned.txt" \
    > "${WORK}/out8" 2> "${WORK}/err8"
check "T8 foreign-owned list exits non-zero" "$?" "1"
check_contains "T8 explains the ownership rule" "$(cat "${WORK}/err8")" "must be owned by root"

# --- T9: symlinked list is refused ---------------------------------------
ln -sf "${WORK}/list2.txt" "${WORK}/link.txt"
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock" bash "${SCRIPT}" "${WORK}/link.txt" \
    > "${WORK}/out9" 2> "${WORK}/err9"
check "T9 symlinked list exits non-zero" "$?" "1"
check_contains "T9 explains the symlink rule" "$(cat "${WORK}/err9")" "symlinked"

# --- T10: concurrent run is refused --------------------------------------
(
    exec 9>"${WORK}/lock2"
    flock 9
    sleep 3
) &
locker=$!
sleep 0.5
ALLOW_FILE="${allow}" LOCK_FILE="${WORK}/lock2" bash "${SCRIPT}" "${WORK}/list2.txt" \
    > "${WORK}/out10" 2> "${WORK}/err10"
check "T10 concurrent run exits non-zero" "$?" "1"
check_contains "T10 explains the lock" "$(cat "${WORK}/err10")" "already running"
wait "${locker}" 2>/dev/null

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[[ ${fail} -eq 0 ]]
