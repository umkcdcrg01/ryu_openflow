# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# V5. 
# save ovs dataparping -f -I eth1  -s 10.10.5.2 10.10.5.3 -bath object
# control arp and icmp packet
# need to mannual start arp from host: szb53@h2:~$ 

# fix manuual arp will be in version v7



from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, \
    MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, icmp, arp
from ryu.ofproto import inet
from ryu.controller import dpset
from ryu.lib.packet.lldp import LLDP_MAC_NEAREST_BRIDGE
# from ryu.lib.packet.ether_types import ETH_TYPE_LLDP
import array
from ryu.lib import hub
from operator import attrgetter
import json
import shutil
import os
import subprocess
import time
import networkx as nx
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import pickle

# output ovs switch hostname and DPID pairs
OFP_SWITCHES_LIST = \
    './network-data/ofp_switches_list.db'
OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data/ofp_switches_list_prev.db'
OFP_SWITCHES_LIST_SCRIPT = \
    './scripts/remote_ovs_operation/get_switch_ofpbr_datapath_id.sh'
OFP_SWITCHES_FLOW_STATS = \
    './network-data/ofp_switches_{0}_flow_stats.db'
OFP_SWITCHES_FLOW_STATS_PREVIOUS = \
    './network-data/ofp_switches_{0}_flow_stats_prev.db'
OFP_SWITCHES_PORT_STATS = \
    './network-data/ofp_switches_{0}_port_stats.db'
OFP_SWITCHES_PORT_STATS_PREVIOUS = \
    './network-data/ofp_switches_{0}_port_stats_prev.db'
OFP_SINGLE_SHOREST_PATH = './network-data/ofp_single_shortest_path.db'
OFP_ALL_PAIRS_SHOREST_PATH = './network-data/ofp_all_pairs_shortest_path.db'
OFP_ALL_PATHS_SHOREST_PATH = './network-data/ofp_all_paths_shortest_path.db'
OFP_MAC_TO_PORT = './network-data/ofp_mac_to_port.db'
OFP_LINK_PORT = './network-data/ofp_link_port.db'


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.datapaths = {}
        # create thread for traffic monitoring
        self.monitor_thread = hub.spawn(self._monitor)
        self.hostname_list = {}
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.topology_data_app = self
        self.arp_request = {}
        self.arp_reply = {}
        # port number between two OVS
        self.link_port = {}
        # save OVS datapath Object for later reference
        self.dpid_datapathObj = {}

    # Given DPID, output hostname in string
    def _hostname_Check(self, datapath):
        # Given decimal datapath ID, return hostname
        if os.path.exists(os.path.abspath(OFP_SWITCHES_LIST_PREVIOUS)):
            f = os.path.abspath(OFP_SWITCHES_LIST_PREVIOUS)
        else:
            f = os.path.abspath(OFP_SWITCHES_LIST)
        with open(f, 'r') as iff:
            for line in iff:
                hostname, dpid = line.split()
                self.hostname_list[int(dpid, 16)] = hostname

        # print self.hostname_list
        # NEED add some datapath check later
        if datapath not in self.hostname_list.keys():
            return datapath
        else:
            return self.hostname_list[datapath]

    ###################################################################
    # ofp_event.EventOFPSwitchFeatures
    ####################################################################
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self._update_switch_dpid_list()
        self.logger.info("Switch Feature reply")
        msg = ev.msg
        datapath = ev.msg.datapath
        dpid = datapath.id
        # save datapath object into dpid_datapath
        self.dpid_datapathObj[dpid] = ev.msg.datapath
        print self.dpid_datapathObj
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(
            "   datapath in decimal %s,in hex %s",
            datapath.id, hex(int(datapath.id)))
        self.logger.info('   OFPSwitchFeatures received: '
                         'datapath_id=0x%016x n_buffers=%d '
                         'n_tables=%d auxiliary_id=%d '
                         'capabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)
        # install table-miss flow entry when switch first connected
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    ###################################################################
    # update switch dpid every 10s
    # output to ./network-data/ofp_switches_list.db
    ####################################################################
    def _update_switch_dpid_list(self):
        # update and write to ./network-data/ofp_switches_list.db
        # it will be called when switch in and out
        subprocess.call([OFP_SWITCHES_LIST_SCRIPT])
        shutil.copyfile(OFP_SWITCHES_LIST, OFP_SWITCHES_LIST_PREVIOUS)

    def _udpate_switch_port_stats(self):
        # write to ./network-data/ofp-switch-port-stats.db
        pass

    ###################################################################
    # add flow
    ####################################################################
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # self.logger.info("add flow to %s", self._hostname_Check(datapath.id))
        # print type(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    ###################################################################
    # EventOFPPacketIn handler
    ####################################################################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # print "1:",pkt_ethernet
        # print "2:", eth

        dst = eth.dst
        src = eth.src
        # eth_proto = eth.protocol_name

        # do not forward LLCP packet in message
        # if not pkt_ethernet:
        #     return
        if dst == LLDP_MAC_NEAREST_BRIDGE:
            return

        dpid = hex(datapath.id)
        self.mac_to_port.setdefault(dpid, {})
        self.arp_reply.setdefault(dpid, [])
        self.arp_request.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # iterate all the switch datapath objects
        # for item in self.dpid_datapathObj:
        #     print item, " ", self.dpid_datapathObj[item].id
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        # print "mac_to_port\n %s" % self.mac_to_port

        if pkt_arp:
            # flood all the ARP packages and save all the requests in self.arp_request and self.arp_reply
            print "ARP: %s" % pkt_arp.opcode
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp, msg)
        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            return 0
            print "\nICMP From %d src_mac %s dst_mac %s" % (datapath.id, src, dst)
            shortest_path_list = (
                    self._handle_icmp(datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp))
            print shortest_path_list
            count = 0
            # origin_in_port = in_port
            if len(shortest_path_list) == 1:
                next_node = shortest_path_list[0]
                next_datapath = self.dpid_datapathObj[next_node]
                out_port = self.mac_to_port[hex(next_node)][dst]
                actions = [parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(next_datapath, 1, match, actions, msg.buffer_id)

            else:
                for node in shortest_path_list:
                    next_datapath = self.dpid_datapathObj[node]
                    next_node = shortest_path_list[count+1]
                    print "---%s %s" % (node, next_datapath)
                    out_port = self.link_port[node][next_node]
                    actions = [parser.OFPActionOutput(out_port)]
                    # print out_port

                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self.add_flow(next_datapath, 1, match, actions, msg.buffer_id)
                    reserse_match = parser.OFPMatch(in_port=out_port, eth_dst=src)
                    reserse_action = [parser.OFPActionOutput(in_port)]
                    self.add_flow(next_datapath, 1, reserse_match, reserse_action, msg.buffer_id)

                    print "in_port %s from dpid %s out_port %s To dpid %s" % (
                        in_port, self._hostname_Check(node),
                        out_port, self._hostname_Check(next_node))
                    count += 1
                    in_port = self.link_port[next_node][node]
                    if count == len(shortest_path_list)-1:
                        next_datapath = self.dpid_datapathObj[next_node]
                        out_port = self.mac_to_port[hex(node)][dst]
                        actions = [parser.OFPActionOutput(out_port)]
                        print "last stop %s" % out_port
                        in_port = self.link_port[next_node][node]
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                        print "in_port %s from dpid %s out_port %s To node %s" % (
                            in_port, self._hostname_Check(next_node), out_port, dst)
                        self.add_flow(next_datapath, 1, match, actions, msg.buffer_id)
                        reserse_match = parser.OFPMatch(in_port=out_port, eth_dst=src)
                        reserse_action = [parser.OFPActionOutput(in_port)]
                        self.add_flow(
                            next_datapath, 1, reserse_match, reserse_action, msg.buffer_id)
                        out = parser.OFPPacketOut(datapath=next_datapath, buffer_id=msg.buffer_id,
                                                    in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        break

                    out = parser.OFPPacketOut(datapath=next_datapath, buffer_id=msg.buffer_id,
                                                in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)

    ###################################################################
    # various  packet handler
    ####################################################################
    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp, msg):
        self.logger.info("_handle_arp:")
        dpid = hex(datapath.id)
        # self.logger.info("_handle_arp:")
        # print "arp_code=%s datapath=%s in_port=%s src_mac=%s dst_mac=%s src_ip=%s dst_ip=%s" % (
        #    pkt_arp.opcode, dpid, port, pkt_arp.src_mac, pkt_arp.dst_mac, pkt_arp.src_ip, pkt_arp.dst_ip)
        if pkt_arp.opcode == 1:  # arp.ARP_REQUEST
            print "\narp_reply: ", self.arp_reply
            self.arp_request[dpid]["src_mac"] = pkt_arp.src_mac
            self.arp_request[dpid]["dst_mac"] = pkt_arp.dst_mac
            self.arp_request[dpid]["src_ip"] = pkt_arp.src_ip
            self.arp_request[dpid]["dst_ip"] = pkt_arp.dst_ip
            # print "\narp_request: %s" % (self.arp_request)
        elif pkt_arp.opcode == 2:
            dict_temp ={}
            for dst_dpid in self.arp_reply:
                print "\narp_reply: ", self.arp_reply
                for dst_dpid in self.arp_reply:
                    # print "dst_dpid=%s dpid=%s" % (dst_dpid, dpid)
                    if dst_dpid == dpid:
                        # print "### dst_dpid=%s dpid=%s" % (dst_dpid, dpid)
                        if not self.arp_reply[dst_dpid]:
                            dict_temp["src_mac"] = pkt_arp.src_mac
                            dict_temp["dst_mac"] = pkt_arp.dst_mac
                            dict_temp["src_ip"] = pkt_arp.src_ip
                            dict_temp["dst_ip"] = pkt_arp.dst_ip
                            dict_temp["count"] = 1
                            # print "add new entry"
                            self.arp_reply[dpid].append(dict_temp)
                        else:
                            for arp_reply_entry in self.arp_reply[dst_dpid]:
                                if arp_reply_entry:
                                    if (pkt_arp.src_mac == arp_reply_entry["src_mac"] and
                                        pkt_arp.dst_mac == arp_reply_entry["dst_mac"] and
                                        pkt_arp.src_ip == arp_reply_entry["src_ip"] and
                                        pkt_arp.dst_ip == arp_reply_entry["dst_ip"]):
                                        continue
                                else:
                                    dict_temp["src_mac"] = pkt_arp.src_mac
                                    dict_temp["dst_mac"] = pkt_arp.dst_mac
                                    dict_temp["src_ip"] = pkt_arp.src_ip
                                    dict_temp["dst_ip"] = pkt_arp.dst_ip
                                    dict_temp["count"] = 1
                                    # print "add new entry"
                                    self.arp_reply[dpid].append(dict_temp)
                    elif dst_dpid != dpid:
                        for arp_reply_entry in self.arp_reply[dst_dpid]:
                            if arp_reply_entry:
                                if (pkt_arp.src_mac == arp_reply_entry["src_mac"] and
                                        pkt_arp.dst_mac == arp_reply_entry["dst_mac"] and
                                        pkt_arp.src_ip == arp_reply_entry["src_ip"] and
                                        pkt_arp.dst_ip == arp_reply_entry["dst_ip"]):
                                    # print "existed arp reply dst_dpid:", dst_dpid
                                    arp_reply_entry["count"] = 2

        # flood out arp packet
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                    buffer_id=0xffffffff, in_port=port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def _handle_icmp(self, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        """
        return shortest path
        """
        self.logger.info("_handle_icmp:")
        src_dpid = hex(datapath.id)
        if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            src_mac = pkt_ethernet.src
            dst_mac = pkt_ethernet.dst
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            print "%s %s %s %s %s " % (src_dpid, src_mac, dst_mac, src_ip, dst_ip)
            # print self.link_port

            # get the DPID which connected to dst_mac
            dst_dpid = self._return_destionation_dpid(src_dpid, self.arp_reply, src_mac, dst_mac)
            # print "src_dpid %s dst_dpid %s" % (src_dpid, dst_dpid)

            # find a shortest path for this icmp request
            print "%s %s %s %s" %(src_dpid, dst_dpid, type(src_dpid), type(dst_dpid))
            shortest_path_list = self._single_shortest_path(
                                                        int(src_dpid,16), int(dst_dpid,16))
            # print shortest_path_list
            return shortest_path_list

    def _return_destionation_dpid(self, src_dpid, arp_reply, src_mac, dst_mac):
        # return dst dpid based on arp_reply, src_mac, dst_mac
        self.logger.info("_return_destionation_dpid:")
        print "arp_reply:\n", self.arp_reply
        print "arp_request:\n", self.arp_request
        # print "arp_reply: %s" % self.arp_reply
        for dst_dpid in self.arp_reply:
            for arp_reply_entry in self.arp_reply[dst_dpid]:
                if arp_reply_entry:
                    print "src_mac=%s arp_reply_entry[dst_mac]=%s dst_mac=%s arp_reply_entry[src_mac]=%s" %(
                        src_mac, arp_reply_entry["dst_mac"], dst_mac, arp_reply_entry["src_mac"])
                    if(src_mac == arp_reply_entry["dst_mac"] and
                        dst_mac == arp_reply_entry["src_mac"] and
                        arp_reply_entry["count"] == 2):
                        print "found match at dpid=%s" % dst_dpid
                        return dst_dpid
                    else:
                        continue
    ###################################################################
    # output shortest path for all pairs for all switches (nodes) in every 10s
    ####################################################################
    def _single_shortest_path(self, src_dpid, dst_dpid):
        # return a shortestpath
        self.logger.info("_single_shortest_path:")
        try:
            shortest_path = nx.shortest_path(self.net, src_dpid, dst_dpid)
        except Exception as e:
            self.logger.info("_single_shortest_path %s", e)
        finally:
            return [i for i in shortest_path]

    def _all_single_shortest_path(self):
        # print "Printing shortest Path..."
        # print nx.shortest_path(self.net)
        # print "_single_shortest_path " # ,self.net.nodes(), self.net.edges()
        with open(OFP_SINGLE_SHOREST_PATH, 'w') as outp:
            for src in self.net.nodes():
                for dst in self.net.nodes():
                    if src != dst:
                        try:
                            shortest_path = nx.shortest_path(self.net, src, dst)
                        except Exception as e:
                            self.logger.info("_single_shortest_path %s", e)
                        finally:
                            outp.write("%s -> %s %s" % (self._hostname_Check(src),
                                                        self._hostname_Check(dst),
                                                        [self._hostname_Check(i) for i in shortest_path]))
                            outp.write("\n")
                        # print self._hostname_Check(src), " -> ",\
                        #     self._hostname_Check(dst), " ",\
                        #     [self._hostname_Check(i) for i in shortest_path]

    def _all_paris_shortest_path(self):
        # print one shortest path for all node pairs
        # print "_all_paris_shortest_path ", self.net
        with open(OFP_ALL_PAIRS_SHOREST_PATH, 'w') as outp:
            try:
                shortest_path = nx.all_pairs_dijkstra_path(self.net)
            except Exception as e:
                self.logger.info("_all_paris_shortest_path %s", e)
            finally:
                for src in shortest_path.keys():
                    for dst in shortest_path[src]:
                        outp.write("%s -> %s %s\n" % (self._hostname_Check(src),
                                                      self._hostname_Check(dst),
                                                      [self._hostname_Check(i) for i in shortest_path[src][dst]]))
                        # print self._hostname_Check(src), " -> ", self._hostname_Check(dst),\
                        #     " ", [self._hostname_Check(i)
                        #           for i in shortest_path[src][dst]]

    def _all_paths_shortest_path(self):
        # print all the shortest paths for each node pair
        # print "_all_paths_shortest_path ", self.net
        with open(OFP_ALL_PATHS_SHOREST_PATH, 'w') as outp:
            for src in self.net.nodes():
                for dst in self.net.nodes():
                    if src != dst:
                        try:
                            shortest_path = nx.all_shortest_paths(self.net, src, dst)
                        except Exception as e:
                            self.logger.info("_all_path_shortest_path %s", e)
                        finally:
                            for each_path_list in shortest_path:
                                outp.write("%s -> %s %s" % (self._hostname_Check(src),
                                                            self._hostname_Check(dst),
                                                            [self._hostname_Check(i) for i in each_path_list]))
                                outp.write("\n")

    ###################################################################
    # write mac_to_port in every 10s
    ####################################################################
    def _mac_to_port(self):
        # print "_mac_to_port updating"
        with open(OFP_MAC_TO_PORT, 'w') as outp:
            # outp.write("hello")
            for dpid in self.mac_to_port.keys():
                for src in self.mac_to_port[dpid]:
                    outp.write("dpid=%s src_mac=%s out_port=%s\n" %
                               (dpid, src, self.mac_to_port[dpid][src]))

    ###################################################################
    # Refresh Network nodes and links every 10s
    ####################################################################
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # self.logger.info("get_topology_data()")
        switch_list = get_switch(self.topology_data_app, None)
        switches = [switch.dp.id for switch in switch_list]
        # print "switches: ", switches
        self.net.add_nodes_from(switches)

        # print "net nodes: ", self.net.nodes()
        for node in self.net.nodes():
            self.link_port.setdefault(node, {})

        with open(OFP_LINK_PORT, 'wr') as outp:
            # src_dpid dst_dpid src_dpid_output_port dst_dpid_input_port
            links_list = get_link(self.topology_data_app, None)
            # print links_list

            # add link from one direction
            links = [(link.src.dpid, link.dst.dpid,
                      {'out_port': link.src.port_no}) for link in links_list]
            # print links
            self.net.add_edges_from(links)
            for link in links:
                # outp.write("%s %s %s\n" % (self._hostname_Check(link[0]),
                #                            self._hostname_Check(link[1]), link[2]['out_port']))
                outp.write("%s %s %s\n" % (link[0], link[1], link[2]['out_port']))
                self.link_port[link[0]][link[1]] = link[2]['out_port']

            # add links from oppsite direction
            links = [(link.dst.dpid, link.src.dpid,
                      {'out_port': link.dst.port_no}) for link in links_list]
            # print "reverse:", links
            self.net.add_edges_from(links)
            for link in links:
                # outp.write("%s %s %s\n" % (self._hostname_Check(link[0]),
                #                            self._hostname_Check(link[1]), link[2]['out_port']))
                outp.write("%s %s %s\n" % (link[0], link[1], link[2]['out_port']))
                self.link_port[link[0]][link[1]] = link[2]['out_port']

    ####################################################################
    # Traffc monitor section
    ####################################################################
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        # wait fof around 10s until all the swtiches connected to controller
        self._update_switch_dpid_list()
        hub.sleep(10)
        while True:
            for dp in self.datapaths.values():
                self._mac_to_port()
                self._request_stats(dp)
                self._update_switch_dpid_list()
                self._all_single_shortest_path()
                self._all_paris_shortest_path()
                self._all_paths_shortest_path()
            hub.sleep(10)

    # send flow and port stats request
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # flow stats request  C->S
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # port status request C->S
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        # print "flow body:", body[1]
        switch_name = self._hostname_Check(ev.msg.datapath.id)
        with open(OFP_SWITCHES_FLOW_STATS.format(switch_name), 'w') as iff:
            self.logger.debug("\n> Flow Stats:")
            self.logger.debug('datapath         '
                              'hostname         '
                              'in-port     duration_sec   duration_nsec       '
                              '   eth-dst  out-port packets  bytes')
            iff.write('datapath         '
                      'hostname         '
                      'in-port     duration_sec   duration_nsec       '
                      '   eth-dst          out-port packets  bytes\n')
            self.logger.debug('---------------- '
                              '---------------- '
                              '-------- ---------------- -------------- '
                              '---------------- -------- -------- --------')
            iff.write('---------------- '
                      '---------------- '
                      '-------- ---------------- -------------- '
                      '---------------- -------- -------- --------\n')
            for stat in sorted([flow for flow in body if flow.priority == 1],
                               key=lambda flow: (flow.match['in_port'],
                                                 flow.match['eth_dst'])):
                iff.write('%16d %16s %8x %16d %16d %17s %8x %8d %8d' %
                          (ev.msg.datapath.id,
                           self._hostname_Check(ev.msg.datapath.id),
                           stat.match['in_port'], stat.duration_sec,
                           stat.duration_nsec, stat.match['eth_dst'],
                           stat.instructions[0].actions[0].port,
                           stat.packet_count, stat.byte_count))
                iff.write("\n")
                self.logger.debug('%16d %16s %8x %16d %16d %17s %8x %8d %8d',
                                  ev.msg.datapath.id,
                                  self._hostname_Check(ev.msg.datapath.id),
                                  stat.match['in_port'], stat.duration_sec,
                                  stat.duration_nsec, stat.match['eth_dst'],
                                  stat.instructions[0].actions[0].port,
                                  stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.get_topology_data(ev)
        # print "port body:", body[1]
        switch_name = self._hostname_Check(ev.msg.datapath.id)
        with open(OFP_SWITCHES_PORT_STATS.format(switch_name), 'w') as iff:
            self.logger.debug("\n> Port Stats:")
            self.logger.debug('datapath         '
                              'hostname       '
                              'port     duration_sec  duration_nsec '
                              'rx-pkts  rx-bytes rx-error '
                              'tx-pkts  tx-bytes tx-error')
            iff.write('datapath         '
                      'hostname       '
                      'port     duration_sec  duration_nsec '
                      'rx-pkts  rx-bytes rx-error '
                      'tx-pkts  tx-bytes tx-error\n')
            self.logger.debug('---------------- '
                              '-------------- '
                              '-------- ---------------- -------------- '
                              '-------- -------- -------- '
                              '-------- -------- --------')
            iff.write('---------------- '
                      '-------------- '
                      '-------- ------------ -------------- '
                      '-------- -------- -------- '
                      '-------- -------- --------\n')
            for stat in sorted(body, key=attrgetter('port_no')):
                self.logger.debug('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d',
                                  ev.msg.datapath.id,
                                  self._hostname_Check(ev.msg.datapath.id),
                                  stat.port_no, stat.duration_sec, stat.duration_nsec,
                                  stat.rx_packets, stat.rx_bytes,
                                  stat.rx_errors, stat.tx_packets,
                                  stat.tx_bytes, stat.tx_errors)
                iff.write('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d' %
                          (ev.msg.datapath.id,
                           self._hostname_Check(ev.msg.datapath.id),
                           stat.port_no, stat.duration_sec, stat.duration_nsec,
                           stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                           stat.tx_packets, stat.tx_bytes, stat.tx_errors))
                iff.write("\n")

    # The switch notifies controller of change of ports.
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


# This will turn on Web restAPI
app_manager.require_app('ryu.app.rest_topology')
app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
# app_manager.require_app('my_traffic_monitor')
app_manager.require_app('ryu.app.gui_topology.gui_topology')
# print "Project Path", PATH
