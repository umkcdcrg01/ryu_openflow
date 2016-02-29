#!/bin/bash
Switches="s1 s2 s3 s4"

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

