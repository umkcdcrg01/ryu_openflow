#!/bin/bash
USERNAME=szb53
Switches="s1 s2 s3 s4"
OVS_BR=ofpbr
CMD_check_Flow="hostname;ls; sudo ovs-vsctl show"

for ovs in ${Switches} ; do
   ssh  ${ovs} "${CMD_check_Flow}" 
   echo -e "\n"
done
