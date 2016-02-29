#!/bin/bash
set -u
Switches="204.76.187.76 204.76.187.81 204.76.187.77 204.76.187.82 204.76.187.83"

# The OVS bridge you wanna create
OVS_BRIDGE=ofpbr

CMD1="hostname"
CMD2="sudo ovs-vsctl add-br ${OVS_BRIDGE}"
CMD3="sudo ovs-vsctl set-controller ${OVS_BRIDGE} tcp:192.1.242.160:6633"
CMD4="sudo ovs-vsctl set-fail-mode ${OVS_BRIDGE} secure"
CMD5="sudo ovs-vsctl set bridge ${OVS_BRIDGE} protocols=OpenFlow13"
CMD6="sudo ovs-vsctl show"

for ovs in ${Switches} ; do
		echo "Adding OVS bridge ${OVS_BRIDGE} on ${ovs}"
		ssh  ${ovs} "${CMD1}"
		ssh  ${ovs} "${CMD2}"

		if [ $ovs == "204.76.187.76" ]; then
			echo "1"
			ETHARRAY=( "eth1" "eth2" "eth3" "eth4" "eth5" "eth6" )
		fi
		if [ $ovs == "204.76.187.81" ]; then
			echo "2"
			ETHARRAY=("eth1" "eth2") 
		fi
		if [ $ovs == "204.76.187.77" ]; then
			echo "3"
			ETHARRAY=("eth1" "eth2" "eth3")
		fi
		if [ $ovs == "204.76.187.82" ]; then
			echo "4"
			ETHARRAY=("eth1" "eth2" "eth3")
		fi
		if [ $ovs == "204.76.187.83" ]; then
			echo "5"
			ETHARRAY=("eth1" "eth2" "eth3")
		fi

		echo "add ${#ETHARRAY[@]} ports onto ovs bridge"

		for i in ${ETHARRAY[@]} ; do
			ssh ${ovs} "sudo ovs-vsctl add-port ${OVS_BRIDGE} $i"
		done
		  
		  ssh  ${ovs} "${CMD3}"
		  ssh  ${ovs} "${CMD4}"
		  ssh  ${ovs} "${CMD5}"
		  ssh  ${ovs} "${CMD6}"
	 	echo -e "\n"
done

