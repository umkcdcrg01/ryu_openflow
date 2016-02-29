# Copyright (C) 2014 SDN Hub
#
# Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
# You may not use this file except in compliance with this License.
# You may obtain a copy of the License at
#
#    http://www.gnu.org/licenses/gpl-3.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.

import logging
import json
from webob import Response
import time
from threading import Timer

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
# from ryu.app.wsgi import ControllerBase, WSGIApplication

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet.lldp import LLDP_MAC_NEAREST_BRIDGE
from ryu.lib import hub
import os.path


OFP_HOST_SWITCHES_LIST = \
    './network-data/ofp_host_switches_list.db'


class HostTracker(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(HostTracker, self).__init__(*args, **kwargs)
        self.hosts = {}
        self.routers = []
        self.IDLE_TIMEOUT = 300
        self.count = 0
        self.host_switch_file_update = hub.spawn(self._update)

        Timer(self.IDLE_TIMEOUT, self.expireHostEntries).start()

    def _update(self):
        # wait fof around 10s until all the swtiches connected to controller
        self._update_host_switch_file()
        hub.sleep(2)
        while True:
            self._update_host_switch_file()
            hub.sleep(5)

    def _update_host_switch_file(self):
        #if os.path.exists(OFP_HOST_SWITCHES_LIST):
        # print "**"*20
        with open(OFP_HOST_SWITCHES_LIST, 'w') as outp:
            for srcIP, val in self.hosts.items():
                # print srcIP, val['dpid']
                outp.write("%s %s\n" % (srcIP, val['dpid']))



    def expireHostEntries(self):
        expiredEntries = []
        for key, val in self.hosts.iteritems():
            if int(time.time()) > val['timestamp'] + self.IDLE_TIMEOUT:
                expiredEntries.append(key)

        for ip in expiredEntries:
            del self.hosts[ip]

        Timer(self.IDLE_TIMEOUT, self.expireHostEntries).start()

    # The hypothesis is that a router will be the srcMAC
    # for many IP addresses at the same time
    def isRouter(self, mac):
        if mac in self.routers:
            return True

        ip_list = []
        for key, val in self.hosts.iteritems():
            if val['mac'] == mac:
                ip_list.append(key)

        if len(ip_list) > 1:
            for ip in ip_list:
                del self.hosts[ip]
            self.routers.append(mac)
            return true

        return False

    def updateHostTable(self, srcIP, dpid, port):
        self.hosts[srcIP]['timestamp'] = int(time.time())
        if 'dpid' not in self.hosts[srcIP]:
            self.hosts[srcIP]['dpid'] = dpid
        elif self.hosts[srcIP]['dpid'] != dpid:
            pass
        self.hosts[srcIP]['port'] = port

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        if dst != LLDP_MAC_NEAREST_BRIDGE:
            # print "LLDP Packet:"
                # self.logger.info("packet in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)
            if eth.ethertype == ether.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocols(arp.arp)[0]
                srcMac = arp_pkt.src_mac
                srcIP = arp_pkt.src_ip
            elif eth.ethertype == ether.ETH_TYPE_IP:
                ip = pkt.get_protocols(ipv4.ipv4)[0]
                srcMac = eth.src
                srcIP = ip.src
            else:
                return

            if self.isRouter(srcMac):
                return

            if srcIP not in self.hosts:
                self.hosts[srcIP] = {}

            # Always update MAC and switch-port location, just in case
            # DHCP reassigned the IP or the host moved
            self.hosts[srcIP]['mac'] = srcMac
            self.updateHostTable(srcIP, dpid_lib.dpid_to_str(datapath.id), in_port)
            # print "host:", self.hosts
            # self._update_host_switch_file()
                # self.count += 1
                # print "router:", self.routers
