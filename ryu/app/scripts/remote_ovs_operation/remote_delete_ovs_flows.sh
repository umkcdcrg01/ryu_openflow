#!/bin/bash
USERNAME=szb53
Switches="s1 s2 s3 s4"
OVS_BR=ofpbr
CMD_Delete_Flow="hostname; sudo ovs-ofctl -O Openflow13 del-flows ${OVS_BR}"

for ovs in ${Switches} ; do
   ssh  ${ovs} "${CMD_Delete_Flow}" 
   echo "Deleting flows"
   echo -e "\n"
done
