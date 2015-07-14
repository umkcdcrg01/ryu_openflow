#!/bin/bash

sudo apt-get update
sudo apt-get install -y vim

cd ~/installation_scripts
echo "Install OVS 2.3.9"
chmod +x openvswitch_installation.sh
sudo ./openvswitch_installation.sh


echo "Create ovs bridge: ofpbr"
chmod +x ovs_create_bridge.sh
sudo ./ovs_create_bridge.sh


echo "add controller key to authorized keys"
chmod +x add_controller_public_key_to_auth.sh
./add_controller_public_key_to_auth.sh