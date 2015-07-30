#!/bin/bash
USERNAME=szb53
Switches="204.76.187.76 204.76.187.81 204.76.187.77 204.76.187.82 204.76.187.83"
OVS_BR=ofpbr
CMD_Delete_Flow="hostname; sudo ovs-ofctl -O Openflow13 del-flows ${OVS_BR}"

echo "Remove ICMP_LOG"
rm /users/szb53/ryu/ryu/app/network-data2/ofp_icmp_log.db
echo "Remove IPERF_LOG"
rm /users/szb53/ryu/ryu/app/network-data2/ofp_iperf_log.db
echo "Remove ICMP REROUTE"
rm /users/szb53/ryu/ryu/app/network-data2/ofp_icmp_reroute_log.db

for ovs in ${Switches} ; do
   ssh  ${ovs} "${CMD_Delete_Flow}" 
   echo "Deleting flows"
   echo -e "\n"
done
