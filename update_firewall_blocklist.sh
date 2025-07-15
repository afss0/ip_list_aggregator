#!/bin/bash
#
# This script flushes and repopulates iptables rules from a blocklist file using the 'ipset' tool.
#
# MUST BE RUN AS ROOT. IT IS ADVISED TO COPY OR SYMLINK THIS FILE TO /usr/local/sbin/update_firewall_blocklist.sh AND MAKE IT EXECUTABLE
# ADD TO THE ROOT USER CRONTAB

# --- Configuration ---
IP_LIST_FILE="/var/tmp/ip_list_aggregator/merged-ip-list.txt"
SET_NAME="bad_ips_set"
MAX_ELEMS=500000

# --- Function to make rules persistent ---
make_rules_persistent() {
    echo "Attempting to make firewall rules persistent..."

    # Check for /etc/os-release to determine the Linux distribution
    if [ -f /etc/os-release ]; then
        # Source the os-release file to get variables like ID and ID_LIKE
        . /etc/os-release
    else
        echo "Warning: Cannot determine OS distribution. /etc/os-release not found."
        echo "Please save your iptables/ipset rules manually."
        return
    fi

    # Use a case statement based on the OS ID
    case "$ID" in
        debian|ubuntu)
            # For Debian/Ubuntu, check for netfilter-persistent
            if command -v netfilter-persistent &>/dev/null; then
                echo "Debian/Ubuntu detected. Saving rules with netfilter-persistent..."
                netfilter-persistent save
            else
                echo "Warning: 'netfilter-persistent' command not found."
                echo "To make rules persistent on Debian/Ubuntu, please install 'iptables-persistent' package:"
                echo "  sudo apt-get update && sudo apt-get install iptables-persistent"
                echo "After installation, the rules should be saved automatically by this script on the next run."
            fi
            ;;

        centos|rhel|fedora|rocky|almalinux)
            # For RHEL family, check for iptables-services and ipset-service
            if command -v service &>/dev/null && (systemctl list-unit-files | grep -q 'iptables.service') && (systemctl list-unit-files | grep -q 'ipset.service'); then
                echo "RHEL/CentOS/Fedora family detected. Saving rules with iptables and ipset services..."
                service iptables save
                service ipset save
            else
                echo "Warning: 'iptables.service' or 'ipset.service' not found or enabled."
                echo "To make rules persistent on RHEL/CentOS/Fedora, please install and enable the services:"
                echo "  sudo yum install iptables-services ipset-service"
                echo "  sudo systemctl enable iptables"
                echo "  sudo systemctl enable ipset"
                echo "After installation, the rules should be saved automatically by this script on the next run."
            fi
            ;;

        *)
            echo "Warning: Unsupported OS '$ID' for automatic persistence."
            echo "Please consult your OS documentation on how to make iptables and ipset rules persistent."
            ;;
    esac
}


# --- Safety Checks ---
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use 'sudo'."
   exit 1
fi

if [ ! -s "$IP_LIST_FILE" ]; then
    echo "Error: IP list file not found or is empty: $IP_LIST_FILE"
    exit 1
fi

echo "Updating ipset blocklist..."

# --- Main Logic ---

# 1. Create a new, temporary set with a specified max size.
TEMP_SET_NAME="${SET_NAME}_temp"
ipset create $TEMP_SET_NAME hash:net family inet maxelem $MAX_ELEMS -exist

# 2. Use 'ipset restore' to bulk-load the IPs into the temporary set.
echo "Loading entries into temporary set..."
if ! awk '{ print "add '"$TEMP_SET_NAME"' " $1 }' "$IP_LIST_FILE" | ipset restore; then
    echo "Error: Failed to load IPs into ipset. Aborting."
    ipset destroy $TEMP_SET_NAME
    exit 1
fi

# 3. Atomically update the main set.
if ipset -q list $SET_NAME >/dev/null 2>&1; then
    # The main set exists, so swap the temp set with the main set.
    echo "Main set exists. Swapping new blocklist into place..."
    ipset swap $TEMP_SET_NAME $SET_NAME
    ipset destroy $TEMP_SET_NAME
else
    # The main set does not exist (first run), so rename the temp set.
    echo "Main set does not exist. Renaming temporary set..."
    ipset rename $TEMP_SET_NAME $SET_NAME
fi

# --- Link the ipset to iptables (if not already linked) ---
RULE_COMMENT="Drop traffic from bad_ips_set"

# For inbound traffic (from source)
if ! iptables -C INPUT -m set --match-set $SET_NAME src -j DROP &>/dev/null; then
    echo "Adding iptables rule to block IPs in '$SET_NAME' on INPUT chain..."
    iptables -I INPUT 1 -m set --match-set $SET_NAME src -m comment --comment "$RULE_COMMENT" -j DROP
fi

# For outbound traffic (to destination)
if ! iptables -C OUTPUT -m set --match-set $SET_NAME dst -j DROP &>/dev/null; then
    echo "Adding iptables rule to block IPs in '$SET_NAME' on OUTPUT chain..."
    iptables -I OUTPUT 1 -m set --match-set $SET_NAME dst -m comment --comment "$RULE_COMMENT" -j DROP
fi

echo "Ipset blocklist update complete. Total entries: $(ipset list $SET_NAME | grep 'Number of entries' | cut -d' ' -f4)"

# --- Make Rules Persistent ---
make_rules_persistent

echo "Script finished."
exit 0