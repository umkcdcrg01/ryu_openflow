#!/bin/bash
ETH_OUTPUT="$(ifconfig | grep eth | awk '{if ($1 != "eth0") print $1}')"

# The OVS bridge you wanna create
OVS_BRIDGE=ofpbr
SWITCH_NUMBER=1
# interfaces array
ETHARRAY=("eth1" "eth2" "eth3" "eth4" "eth5" "eth6")

# configure the IP address for each switch
# sudo ifconfig eth1 192.168.1.x netmask 255.255.255.0
# sudo ifconfig eth2 192.168.1.x netmask 255.255.255.0
# sudo ifconfig eth3 192.168.1.x netmask 255.255.255.0

for i in ${ETH_OUTPUT} 
do
	echo $i
	sudo ifconfig $i 0
done

sudo ovs-vsctl add-br ${OVS_BRIDGE}
for i in "${ETHARRAY[@]}"
do
	sudo ovs-vsctl add-port ${OVS_BRIDGE} $i
done

sudo ovs-vsctl set-controller ${OVS_BRIDGE} tcp:192.1.242.160:6633
sudo ovs-vsctl set-fail-mode ${OVS_BRIDGE} secure
sudo ovs-vsctl set bridge ${OVS_BRIDGE} protocols=OpenFlow13
sudo ovs-vsctl show
echo "bridge ofpbr is up!!!"