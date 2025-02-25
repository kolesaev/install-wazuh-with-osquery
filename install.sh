#!/bin/bash

if [[ -z $1 ]]
then

    echo "Enter Wazuh-server ip or hostname (if you use it for non-amd64 debian-based system you should also enter your arch)"
    echo "Usage example:"
    echo ""
    echo "    bash install.sh wazuh-server.example.com arm64"
    exit 1

fi

if which apt && [[ -d /etc/apt/sources.list.d ]]
then

    bash ./debian-based.sh $1 $2

fi

if which yum && [[ -d /etc/yum.repos.d ]]
then

    bash ./rhel-based.sh $1

fi