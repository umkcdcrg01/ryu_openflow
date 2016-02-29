#!/bin/bash

USERNAME=szb53
Switches="204.76.187.76 204.76.187.81 204.76.187.77 204.76.187.82 204.76.187.83"
OVS_BR=ofpbr
CMD_Dump_Flow="hostname; sudo ovs-ofctl -O Openflow13 dump-flows ${OVS_BR}"


for ovs in ${Switches} ; do
   ssh  ${ovs} "${CMD_Dump_Flow}" 
   echo -e "\n"
done
