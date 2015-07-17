#!/bin/bash
#USERNAME=szb53
Switches="s1 s2 s3 s4"
OVS_BR=ofpbr
# change to OFP_SWITCHES_LIST=`pwd`/../../network-data/ofp_switches_list.db
# if you run this script in stand-alone mode

OFP_SWITCHES_LIST=/users/szb53/ryu/ryu/app/network-data/ofp_switches_list.db

if [ '${OFP_SWITCHES_LIST}' ]; then
	# echo "File Exist"
	rm  ${OFP_SWITCHES_LIST}
	# echo "deleted"
fi

if [ ! -e ${OFP_SWITCHES_LIST} ]; then
	# echo "Create new file"
	touch ${OFP_SWITCHES_LIST}
fi

CMD1="hostname" 
CMD2="sudo ovs-ofctl show ${OVS_BR} -O Openflow13"
for ovs in ${Switches} ; do
   H=`ssh  ${ovs} ${CMD1}`
   DPID=`ssh  ${ovs} ${CMD2}`
   H=`echo ${H} | awk -F. '{print $1}'`
   DPID=`echo ${DPID} | grep dpid | awk -F: '{print $3}'`
   DPID=`echo ${DPID} | awk '{print $1}'`
   echo ${H} ${DPID} >> ${OFP_SWITCHES_LIST}
   # echo "Switch List updated"
done
