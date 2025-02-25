# Wazuh agent with osquery installation and configuration scripts

## Description

This scripts will help you to install and add minimal configuration for described packages on fly.

It supports Debian-based and RHEL-based systems.

After installation it will disable added repositories to prevent automatic upgrade of this packages.

## Usage

To install it on debian-based or rhel-based system execute install.sh with Wazuh-server ip/hostname, like below
```
bash install.sh wazuh-server.example.com
```

## Debian-based non-amd64 arch system

If you are going to use it with Debian-based non-amd64 system you should add your arch for apt sources as well, like below
```
bash install.sh wazuh-server.example.com arm64
```

## PS

Currently scripts configured to install wazuh-agent with exact version 4.9.2-1. If you need another version, you should update scripts before execution