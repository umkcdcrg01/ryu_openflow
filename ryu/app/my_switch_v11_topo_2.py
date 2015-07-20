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
# Simple switch V11 for topology 2
# Jack Zhao
# s.zhao.j@gmail.com# 
# szb53@h4:~/ryu/ryu/app$ ryu-manager --observe-links my_switch_v11_topo_2.py host_tracker_topo_2.py my_arp_v3_topo_2.py my_monitor_v3_topo_2.py
# How to run:
# issue: Web http://192.1.242.160:8080 does not show any topology
# debug: 

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, \
    MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
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
from ryu.topology.api import get_switch, get_link
from ryu.topology import event, switches
import pickle
from ryu import utils
import traceback
# from ryu.app.wsgi import ControllerBase, WSGIApplication, route

# output ovs switch hostname and DPID pairs
# updated by OFP_SWITCHES_LIST_SCRIPT
OFP_SWITCHES_LIST = \
    './network-data2/ofp_switches_list.db'
OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data2/ofp_switches_list_prev.db'

OFP_SWITCHES_LIST_SCRIPT = \
    './scripts/remote_ovs_operation_topo_2/get_switch_ofpbr_datapath_id.sh'
# OFP_SWITCHES_FLOW_STATS = \
#     './network-data2/ofp_switches_{0}_flow_stats.db'
# OFP_SWITCHES_FLOW_STATS_PREVIOUS = \
#     './network-data2/ofp_switches_{0}_flow_stats_prev.db'
# OFP_SWITCHES_PORT_STATS = \
#     './network-data2/ofp_switches_{0}_port_stats.db'
# OFP_SWITCHES_PORT_STATS_PREVIOUS = \
#     './network-data2/ofp_switches_{0}_port_stats_prev.db'
OFP_SINGLE_SHOREST_PATH = './network-data2/ofp_single_shortest_path.db'
OFP_ALL_PAIRS_SHOREST_PATH = './network-data2/ofp_all_pairs_shortest_path.db'
OFP_ALL_PATHS_SHOREST_PATH = './network-data2/ofp_all_paths_shortest_path.db'
OFP_MAC_TO_PORT = './network-data2/ofp_mac_to_port.db'
OFP_LINK_PORT = './network-data2/ofp_link_port.db'
OFP_HOST_SWITCHES_LIST = './network-data2/ofp_host_switches_list.db'  # upadate by host_tracker.py
OFP_HOST_SWITCHES_LIST_BACK = \
    './network-data2/ofp_host_switches_list_backup.db'

ICMP_PRIORITY = 3


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
        # port number between two OVS
        self.link_port = {}
        # save OVS datapath Object for later reference
        self.dpid_datapathObj = {}
        # self._update_switch_dpid_list()

    # Given DPID, output hostname in string
    def _hostname_Check(self, datapath):
        # Given decimal datapath ID, return hostname
        # datapath should be in integer format
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
        # self._update_switch_dpid_list()
        self.logger.info("switch_features_handler: ")
        msg = ev.msg
        datapath = ev.msg.datapath
        dpid = datapath.id
        # save datapath object into dpid_datapath
        # here dpid is a integer, not Hex number
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
    # output to ./network-data2/ofp_switches_list.db
    ####################################################################
    def _update_switch_dpid_list(self):
        # update and write to ./network-data2/ofp_switches_list.db
        # it will be called when switch in and out
        subprocess.call([OFP_SWITCHES_LIST_SCRIPT])
        shutil.copyfile(OFP_SWITCHES_LIST, OFP_SWITCHES_LIST_PREVIOUS)

    def _udpate_switch_port_stats(self):
        # write to ./network-data2/ofp-switch-port-stats.db
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
    # OFP error handler
    ####################################################################
    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug(
            'OFPErrorMsg received: type=0x%02x code=0x%02x '
            'message=%s', msg.type, msg.code, utils.hex_array(msg.data))

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
        dst = eth.dst
        src = eth.src

        if dst == LLDP_MAC_NEAREST_BRIDGE:
            return

        dpid = hex(datapath.id)
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        if src in self.mac_to_port[dpid].keys():
            pass
        else:
            self.mac_to_port[dpid][src] = in_port

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        # print "mac_to_port: OVS_name(dpid): {src_mac: in_port}"
        # for key, value in self.mac_to_port.items():
        #     print self._hostname_Check(datapath.id), value

        # header_list = dict(
        #     (p.protocol_name, p)for p in pkt.protocols if type(p) != str)

        # processing icmp packet only
        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            print "\nICMP From %s src_mac %s dst_mac %s" % (self._hostname_Check(datapath.id), src, dst)

            shortest_path_list = (
                self._handle_icmp(datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp))
            if shortest_path_list == None:
                print "\tCould not find Destination IP. Exit Now"
                return
            else:
                #print "\tfound shortest Path list", shortest_path_list
                print "\tfound shortest Path list", [self._hostname_Check(path) for path in shortest_path_list]

            self.logger.info("Starts to installation flows")

            count = 0
            # origin_in_port = in_port
            if len(shortest_path_list) == 1:
                # if hosts are belong to the same switch
                print "\tbelong to same switch"
                next_node = shortest_path_list[0]
                next_datapath = self.dpid_datapathObj[next_node]
                self.logger.info("\tnext_node: %s" % next_node)
                # self.logger.info("next_datapath Obj %d" % next_datapath)
                self.logger.info("\tnext_datapath %s" % next_datapath.id)
                # out_port = self.mac_to_port[hex(next_node)][dst]
                output_port = int(self._get_output_port(next_datapath.id, dst))
                if output_port == None:
                    self.logger.info("\tCould not find output_port at %s" % self._hostname_Check(next_datapath.id))
                    return
                actions = [parser.OFPActionOutput(output_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                print "\t", "in_port:", in_port, type(in_port), " output_port: ", output_port, type(output_port)
                try:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    reserse_match = parser.OFPMatch(in_port=output_port, eth_dst=src)
                    reserse_action = [parser.OFPActionOutput(in_port)]
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(next_datapath, ICMP_PRIORITY, match, actions, msg.buffer_id)
                        self.add_flow(next_datapath, ICMP_PRIORITY, reserse_match, reserse_action, msg.buffer_id)
                    else:
                        self.add_flow(next_datapath, ICMP_PRIORITY, match, actions)
                        self.add_flow(next_datapath, ICMP_PRIORITY, reserse_match, reserse_action)
                    # self.add_flow(next_datapath, ICMP_PRIORITY, match, actions, msg.buffer_id)
                    # self.add_flow(next_datapath, ICMP_PRIORITY, reserse_match, reserse_action, msg.buffer_id)
                    out = parser.OFPPacketOut(datapath=next_datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return
                except Exception as e:
                    print "\tInstalling flow errors:", e
                    print(traceback.format_exc())

            else:
                # more than one nodes in the shortest path list
                print "\tGo through each node to install flows"
                for node in shortest_path_list:
                    next_datapath = self.dpid_datapathObj[node]
                    next_node = shortest_path_list[count + 1]
                    print "\tworking on node %s" % (self._hostname_Check(node),)
                    output_port = self.link_port[node][next_node]
                    actions = [parser.OFPActionOutput(output_port)]
                    # print output_port

                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    print "\tinstall flow at node: %s" % (self._hostname_Check(node),)
                    print "\t", "in_port %s from dpid %s output_port %s" % (
                        in_port, self._hostname_Check(node),
                        output_port)
                    self.add_flow(next_datapath, ICMP_PRIORITY, match, actions, msg.buffer_id)

                    reserse_match = parser.OFPMatch(in_port=output_port, eth_dst=src)
                    reserse_action = [parser.OFPActionOutput(in_port)]
                    print "\tinstall reverse flow at node: %s" % (self._hostname_Check(node),)
                    print "\t", "in_port %s from dpid %s output_port %s" % (
                        output_port, self._hostname_Check(node),
                        in_port)
                    self.add_flow(next_datapath, ICMP_PRIORITY, reserse_match, reserse_action, msg.buffer_id)

                    count += 1
                    in_port = self.link_port[next_node][node]
                    if count == len(shortest_path_list) - 1:
                        last_node = shortest_path_list[-1]
                        next_datapath = self.dpid_datapathObj[last_node]
                        print "\t working on node %s and this is the last stop" % (self._hostname_Check(last_node),)
                        # print self.mac_to_port
                        # output_port = self.mac_to_port[hex(last_node)][dst]
                        output_port = int(self._get_output_port(last_node, dst))
                        actions = [parser.OFPActionOutput(output_port)]
                        in_port = self.link_port[last_node][node]
                        output_port = int(self._get_output_port(next_datapath.id, dst))
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                        print "\tinstall flow at node: %s" % (self._hostname_Check(last_node),)
                        print "\t", "in_port %s from dpid %s output_port %s To node %s" % (
                            in_port, self._hostname_Check(next_node), output_port, dst)
                        self.add_flow(next_datapath, ICMP_PRIORITY, match, actions, msg.buffer_id)

                        reserse_match = parser.OFPMatch(in_port=output_port, eth_dst=src)
                        reserse_action = [parser.OFPActionOutput(in_port)]
                        print "\tinstall reverse flow at node: %s" % (last_node,)
                        print "\t", "in_port %s from dpid %s output_port %s" % (
                            output_port, self._hostname_Check(last_node),
                            in_port)
                        self.add_flow(
                            next_datapath, ICMP_PRIORITY, reserse_match, reserse_action, msg.buffer_id)
                        out = parser.OFPPacketOut(datapath=next_datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        break

                out = parser.OFPPacketOut(datapath=next_datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

    ###################################################################
    # Get output port
    ####################################################################
    def _get_output_port(self, dpid, dst_mac):
        """
        passed dpid is a integet number
        the dpid saved at OFP_HOST_SWITCHES_LIST is hex number
        so number format need to be transferred
        """
        self.logger.info("MySwitch: _get_output_port:")
        try:
            with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
                for line in inp:
                    target_dpid, target_dst_mac = line.split()[1], line.split()[3]
                    if int(str(target_dpid), 16) == dpid and target_dst_mac == dst_mac:
                        output_port = line.split()[2]
                        self.logger.info("\t Find output_port %s at %s" % (output_port, self._hostname_Check(dpid)))
                        break
                    else:
                        output_port = None
        except Exception as e:
            print "\t Find Destination output_port Error", e
        finally:
            return output_port

    ###################################################################
    # ICMP  packet handler, return shortest path list
    ####################################################################
    def _handle_icmp(self, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        """
        return shortest path
        """
        self.logger.info("MySwitch: _handle_icmp:")
        src_dpid = hex(datapath.id)
        if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            src_mac = pkt_ethernet.src
            dst_mac = pkt_ethernet.dst
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            print "%s %s %s %s %s " % (self._hostname_Check(datapath.id), src_mac, dst_mac, src_ip, dst_ip)
            dst_dpid = None
            # with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            self.logger.info("\t Open ofp_host_switches_list_backup.db file, seaching dst_ip: %s" % dst_ip)
            with open(OFP_HOST_SWITCHES_LIST_BACK, 'r') as inp:
                for line in inp:
                    # print line
                    if dst_ip == line.split()[0]:
                        # print "find dst_ip from ofp_host_switches_list"
                        dst_dpid = line.split()[1]
                        print "\t dst dpid is:", self._hostname_Check(dst_dpid)
            # only continue search for 20 times then give up
            count = 1
            while dst_dpid == None:
                self.logger.info("\t No Luck for the %d time, keep searching..." % count)
                if count <= 20:
                    print "\t retry"
                    time.sleep(2)
                    count += 1
                    with open(OFP_HOST_SWITCHES_LIST_BACK, 'r') as inp:
                        for line in inp:
                            print line
                            if dst_ip == line.split()[0]:
                                dst_dpid = line.split()[1]
                                print "\t dst dpid is:", self._hostname_Check(dst_dpid)
                else:
                    print "\t GVING UP"
                    return None

            # find a shortest path for this icmp request
            # print "%s %s %s %s" %(src_dpid, dst_dpid, type(src_dpid), type(dst_dpid))
            shortest_path_list = self._single_shortest_path(
                int(src_dpid, 16), int(dst_dpid, 16))
            # print shortest_path_list
            # self._all_paths_shortest_path()
            return shortest_path_list

    ###################################################################
    # output shortest path for all pairs for all switches (nodes) in every 10s
    ####################################################################

    def _single_shortest_path(self, src_dpid, dst_dpid):
        # return a shortestpath
        self.logger.info("_single_shortest_path:")
        try:
            shortest_path = nx.shortest_path(self.net, src_dpid, dst_dpid)
        except Exception as e:
            self.logger.info("\t _single_shortest_path %s", e)
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
                            self.logger.info("\t _single_shortest_path %s", e)
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
        # print "my_switch_13_v9: _all_paths_shortest_path:"
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
                                # print("%s -> %s %s" % (self._hostname_Check(src),
                                #                        self._hostname_Check(dst),
                                #                        [self._hostname_Check(i) for i in each_path_list]))

    ###################################################################
    # write mac_to_port in every 10s
    ####################################################################
    def _mac_to_port(self):
        self.logger.info("MySwitch: _mac_to_port updating")
        # print "mac_to_port: OVS_name(dpid): {src_mac: in_port}"
        self.logger.debug("MySwitch: mac_to_port Update every 10s   mac_to_port: OVS_name(dpid): {src_mac: in_port}")
        for key, value in self.mac_to_port.items():
            self.logger.info("\t %s %s %s " % (self._hostname_Check(int(key, 16)), key, value))

        with open(OFP_MAC_TO_PORT, 'w') as outp:
            # outp.write("hello")
            for dpid in self.mac_to_port.keys():
                for src in self.mac_to_port[dpid]:
                    outp.write("dpid=%s src_mac=%s output_port=%s\n" %
                               (dpid, src, self.mac_to_port[dpid][src]))

    def _link_port(self):
        """
        saving dpid as integer
        """
        self.logger.debug("MySwitch: mac_to_port Update every 10s")
        with open(OFP_LINK_PORT, 'w') as outp:
            # outp.write("hello")
            for dpid in self.link_port.keys():
                for dst_dpid, output_port in self.link_port[dpid].items():
                    # self.logger.info("%s %s %s\n" % (dpid, dst_dpid, output_port))
                    outp.write("%s %s %s\n" % (dpid, dst_dpid, output_port))

    ###################################################################
    # Refresh Network nodes and links every 10s
    ####################################################################
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("get_topology_data()")
        self._update_switch_dpid_list()
        switch_list = get_switch(self.topology_data_app, None)
        switches = [switch.dp.id for switch in switch_list]
        # print "switches: ", switches
        self.net.add_nodes_from(switches)

        # print "~~~~~ FRONT ~~~~~~~"
        # print "switches:", [self._hostname_Check(s) for s in switches]
        # print "self.link_port: ", self.link_port
        # print "self.net.nodes():", self.net.nodes()
        # print "self.net.edges():", self.net.edges()

        # print "net nodes: ", self.net.nodes()
        for node in self.net.nodes():
            self.link_port.setdefault(node, {})

        # with open(OFP_LINK_PORT, 'w') as outp:
            # src_dpid dst_dpid src_dpid_output_port dst_dpid_input_port
        links_list = get_link(self.topology_data_app, None)
        # print "links_list: ", links_list

        # add link from one direction
        links = [(link.src.dpid, link.dst.dpid,
                  {'out_port': link.src.port_no}) for link in links_list]
        # print "links:", links
        self.net.add_edges_from(links)
        for link in links:
            # self.logger.info("%s %s %s\n" % (self._hostname_Check(link[0]),
            #                                  self._hostname_Check(link[1]), link[2]['out_port']))
            # self.logger.info("%s %s %s\n" % (link[0], link[1], link[2]['out_port']))
            # outp.write("%s %s %s\n" % (link[0], link[1], link[2]['out_port']))
            self.link_port[link[0]][link[1]] = link[2]['out_port']

            # add links from oppsite direction
            # links = [(link.dst.dpid, link.src.dpid,
            #           {'out_port': link.dst.port_no}) for link in links_list]

            # print "reverse:", links
            # self.net.add_edges_from(links)
            # for link in links:
            #     self.logger.info("%s %s %s\n" % (self._hostname_Check(link[0]),
            #                                      self._hostname_Check(link[1]), link[2]['out_port']))
            #     outp.write("%s %s %s\n" % (link[0], link[1], link[2]['out_port']))
            #     self.link_port[link[0]][link[1]] = link[2]['out_port']

        # print "~~~~~ BACK ~~~~~~~"
        # print "switches:", [self._hostname_Check(s) for s in switches]
        # print "self.link_port: ", self.link_port
        # print "self.net.nodes():", self.net.nodes()
        # print "self.net.edges():", self.net.edges()

    ####################################################################
    # Switch status monitor section
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
        # self._update_switch_dpid_list()
        hub.sleep(10)
        while True:
            for dp in self.datapaths.values():
                self._mac_to_port()
                # self._request_stats(dp)
                # self._update_switch_dpid_list()
                # self._all_single_shortest_path()
                # self._all_paris_shortest_path()
                # self._all_paths_shortest_path()
                self._link_port()
            hub.sleep(10)

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
app_manager.require_app('ryu.app.gui_topology.gui_topology')
# app_manager.require_app('ryu.app.my_arp_v2')
# app_manager.require_app('host_tracker')
# app_manager.require_app('ryu.app.my_monitor_v1')
