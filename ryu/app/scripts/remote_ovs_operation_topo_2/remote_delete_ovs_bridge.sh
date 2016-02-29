#!/bin/bash
Switches="204.76.187.76 204.76.187.81 204.76.187.77 204.76.187.82 204.76.187.83"

# The OVS bridge you wanna create
OVS_BRIDGE=ofpbr


CMD1="hostname"
CMD2="sudo ovs-vsctl del-br ${OVS_BRIDGE}"
CMD3="sudo ovs-vsctl show"
for ovs in ${Switches} ; do
	 echo "Deleting OVS bridge ${OVS_BRIDGE}"
   ssh  ${ovs} "${CMD1}"
  ssh  ${ovs} "${CMD2}"
  ssh  ${ovs} "${CMD3}"
 	echo -e "\n"
done

