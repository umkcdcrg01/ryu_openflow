#!/bin/bash
USERNAME=szb53
Switches="204.76.187.76 204.76.187.81 204.76.187.77 204.76.187.82 204.76.187.83"
OVS_BR=ofpbr
CMD_Delete_Flow="hostname; sudo ovs-ofctl -O Openflow13 del-flows ${OVS_BR}"

for ovs in ${Switches} ; do
   ssh  ${ovs} "${CMD_Delete_Flow}" 
   echo "Deleting flows"
   echo -e "\n"
done
