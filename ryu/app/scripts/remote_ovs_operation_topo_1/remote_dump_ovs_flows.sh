#!/bin/bash

USERNAME=szb53
Switches="s1 s2 s3 s4"
OVS_BR=ofpbr
CMD_Dump_Flow="hostname; sudo ovs-ofctl -O Openflow13 dump-flows ${OVS_BR}"


for ovs in ${Switches} ; do
   ssh  ${ovs} "${CMD_Dump_Flow}" 
   echo -e "\n"
done
