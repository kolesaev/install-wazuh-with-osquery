#!/bin/bash

# Usage:
# bash debian-based.sh <wazuh ip/host (required)> <arch for apt source (optional, if not amd64)>
# 

if [[ -z $1 ]]
then

    echo "Enter Wazuh-server ip or hostname (if you use it for non-amd64 system you should enter your arch as well)"
    echo "Usage example:"
    echo ""
    echo "    bash debian-based.sh wazuh-server.example.com arm64"
    exit 1

fi

WAZUH_MANAGER=$1
arch=$2

# Install osquery

if whoami | grep -qv root
then

    echo "You are not root, so sudo will be used for privileged commands"
    export sudo=sudo

fi

if [[ -z $arch ]]
then

    echo "You didn't change arch, so amd64 will be used as default"
    export arch=amd64

fi

export DEBIAN_FRONTEND=noninteractive
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
$sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $OSQUERY_KEY
echo "deb [arch=$arch] https://pkg.osquery.io/deb deb main" | $sudo tee /etc/apt/sources.list.d/osquery.list
$sudo apt-get update
$sudo apt-get -y install osquery curl

# Configure osquery

echo '{
    "options": {
        "config_plugin": "filesystem",
        "logger_plugin": "filesystem",
        "utc": "true"
    },

    "packs": {
         "custom-pack": "/opt/osquery/share/osquery/packs/custom_pack.conf"
    }
}' | $sudo tee /etc/osquery/osquery.conf

echo '--disable_audit=false
--audit_allow_config=true
--audit_persist=true
--audit_allow_process_events=true
#logrotate options
--logger_rotate=true
--logger_rotate_size=26214400
--logger_rotate_max_files=25' | $sudo tee /etc/osquery/osquery.flags

echo "{
  \"queries\":
  {
    \"execve\": {
      \"query\": \"SELECT * FROM process_events WHERE cmdline NOT IN ('cut -d : -f1', 'ip tuntap show', '/bin/sh /usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh', 'ip a s ', 'head -n 1', 'netstat -tulpn', 'last -n 20', 'df -P') AND path NOT IN ('/usr/bin/awk', '/usr/bin/sed', '/usr/bin/tr', '/usr/bin/sort', '/usr/bin/grep');\",
      \"interval\" : \"300\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Query to get process events every 300 seconds\",
      \"value\" : \"Identity malicious processes\"
    },
    \"crontab\": {
      \"query\" : \"select * from crontab;\",
      \"interval\" : \"60\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the jobs scheduled in crontab in the target system.\",
      \"value\" : \"Identify malware that uses this persistence mechanism to launch at a given interval\"
    },
    \"etc_hosts\": {
      \"query\" : \"select * from etc_hosts;\",
      \"interval\" : \"60\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the entries in the target system /etc/hosts file.\",
      \"value\" : \"Identify network communications that are being redirected. Example: identify if security logging has been disabled\"
    },
    \"kernel_modules\": {
      \"query\" : \"select * from kernel_modules;\",
      \"interval\" : \"7200\",
      \"platform\" : \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the information for the current kernel modules in the target Linux system.\",
      \"value\" : \"Identify malware that has a kernel module component.\"
    },
    \"last\": {
      \"query\" : \"select * from last;\",
      \"interval\" : \"60\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves the list of the latest logins with PID, username and timestamp.\",
      \"value\" : \"Useful for intrusion detection and incident response. Verify assumptions of what accounts should be accessing what systems and identify machines accessed during a compromise.\"
    },
    \"open_sockets\": {
      \"query\" : \"select distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path from process_open_sockets where path <> '' or remote_address <> '';\",
      \"interval\" : \"86400\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the open sockets per process in the target system.\",
      \"value\" : \"Identify malware via connections to known bad IP addresses as well as odd local or remote port bindings\"
    },
    \"open_files\": {
      \"query\" : \"select distinct pid, path from process_open_files where path not like '/private/var/folders%' and path not like '/System/Library/%' and path not in ('/dev/null', '/dev/urandom', '/dev/random');\",
      \"interval\" : \"86400\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the open files per process in the target system.\",
      \"value\" : \"Identify processes accessing sensitive files they shouldn't\"
    },
    \"logged_in_users\": {
      \"query\" : \"select liu.*, p.name, p.cmdline, p.cwd, p.root from logged_in_users liu, processes p where liu.pid = p.pid;\",
      \"interval\" : \"60\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves the list of all the currently logged in users in the target system.\",
      \"value\" : \"Useful for intrusion detection and incident response. Verify assumptions of what accounts should be accessing what systems and identify machines accessed during a compromise.\"
    },
    \"ip_forwarding\": {
      \"query\" : \"select * from system_controls where oid = '4.30.41.1' union select * from system_controls where oid = '4.2.0.1';\",
      \"interval\" : \"86400\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves the current status of IP/IPv6 forwarding.\",
      \"value\" : \"Identify if a machine is being used as relay.\"
    },
    \"process_env\": {
      \"query\" : \"select * from process_envs;\",
      \"interval\" : \"86400\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the environment variables per process in the target system.\",
      \"value\" : \"Insight into the process data: Where was it started from, was it preloaded...\"
    },
    \"mounts\": {
      \"query\" : \"select * from mounts;\",
      \"interval\" : \"3600\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves the current list of mounted drives in the target system.\",
      \"value\" : \"Scope for lateral movement. Potential exfiltration locations. Potential dormant backdoors.\"
    },
    \"shell_history\": {
      \"query\" : \"select * from users join shell_history using (uid);\",
      \"interval\" : \"10\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves the command history, per user, by parsing the shell history files.\",
      \"value\" : \"Identify actions taken. Useful for compromised hosts.\"
    },
    \"suid_bin\": {
      \"query\" : \"select * from suid_bin;\",
      \"interval\" : \"3600\",
      \"platform\": \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves all the files in the target system that are setuid enabled.\",
      \"value\" : \"Detect backdoor binaries (attacker may drop a copy of /bin/sh). Find potential elevation points / vulnerabilities in the standard build.\"
    },
    \"iptables\": {
      \"query\" : \"select * from iptables;\",
      \"interval\" : \"3600\",
      \"platform\" : \"linux\",
      \"version\" : \"1.4.5\",
      \"description\" : \"Retrieves the current filters and chains per filter in the target system.\",
      \"value\" : \"Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans\"
    }
  }
}" | $sudo tee /opt/osquery/share/osquery/packs/custom_pack.conf

# Starting osquery daemon

$sudo systemctl daemon-reload
$sudo systemctl enable osqueryd
$sudo systemctl restart osqueryd

# Install wazuh agent

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | $sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
$sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg arch=$arch] https://packages.wazuh.com/4.x/apt/ stable main" | $sudo tee /etc/apt/sources.list.d/wazuh.list
$sudo apt-get update

$sudo bash -c "DEBIAN_FRONTEND=noninteractive WAZUH_MANAGER=$WAZUH_MANAGER apt-get install -y wazuh-agent=4.9.2-1"

# Config wazuh agent to work with osquery

$sudo sed -i "63s|<disabled>yes</disabled>|<disabled>no</disabled>|" /var/ossec/etc/ossec.conf

# Starting wazuh agent

$sudo systemctl daemon-reload
$sudo systemctl enable wazuh-agent
$sudo systemctl restart wazuh-agent

# Disable repo sources to prevent updating

$sudo sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
$sudo sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/osquery.list

$sudo apt-get update

# Save bash history immediately
echo 'export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' | sudo tee /etc/profile.d/update-bash-history.sh > /dev/null
