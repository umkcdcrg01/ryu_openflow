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
# V4. fixing shortest Path algorithms


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

    # Given DPID, output hostname in string
    def _hostname_Check(self, datapath):
        # Given decimal datapath ID, return hostname
        with open(OFP_SWITCHES_LIST, 'r') as iff:
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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(
            "   datapath in decimal %s,in hex %s",
            datapath.id, hex(int(datapath.id)))
        self.logger.info('     OFPSwitchFeatures received: '
                         'datapath_id=0x%016x n_buffers=%d '
                         'n_tables=%d auxiliary_id=%d '
                         'capabilities=0x%08x',
                         msg.datapath_id, msg.n_buffers, msg.n_tables,
                         msg.auxiliary_id, msg.capabilities)
        # install table-miss flow entry
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
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        # eth_proto = eth.protocol_name

        # do not forward LLCP packet in message
        if dst == LLDP_MAC_NEAREST_BRIDGE:
            return

        dpid = hex(datapath.id)
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # pkt_ipv4 = ipv4.ipv4(dst='192.0.2.1',
        #              src='192.0.2.2',
        #              proto=inet.IPPROTO_UDP)
        # print pkt_ipv4.dst
        # print pkt_ipv4.src
        # print pkt_ipv4.proto

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_arp:
            self.logger.info(
                "ARP Packet: %s %s %s", pkt_arp.src_mac, pkt_arp.dst_mac, pkt_arp.proto)
        if pkt_icmp:
            self.logger.info("ICMP Packet: %s %s %s", pkt_icmp.type, pkt_icmp.code, pkt_icmp.csum)
        if pkt_ipv4:
            self.logger.info("IPv4 Packet: %s %s %s", pkt_ipv4.src, pkt_ipv4.dst, pkt_ipv4.proto)

        self.logger.info("packet in dpid=%s src_mac=%s dst_mac=%s \
                    in_port=%s, out_port=%s",
                         dpid, src, dst, in_port, out_port)

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        print "mac_to_port:", self.mac_to_port

    ###################################################################
    # output shortest path for all pairs for all switches (nodes) in every 10s
    ####################################################################
    def _single_shortest_path(self):
        # print "Printing shortest Path..."
        # print nx.shortest_path(self.net)
        print "_single_shortest_path " # ,self.net.nodes(), self.net.edges()
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
        print "_all_paris_shortest_path ", self.net
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
        print "_all_paths_shortest_path ", self.net
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
        print "_mac_to_port updating"
        with open(OFP_MAC_TO_PORT, 'w') as outp:
            # outp.write("hello")
            for dpid in self.mac_to_port.keys():
                for src in self.mac_to_port[dpid]:
                    outp.write("dpid=%s src_mac=%s out_port=%s\n" %
                               (self._hostname_Check(dpid), src, self.mac_to_port[dpid][src]))

    ###################################################################
    # Refresh Network nodes and links every 10s
    ####################################################################
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("get_topology_data()")
        switch_list = get_switch(self.topology_data_app, None)
        switches = [switch.dp.id for switch in switch_list]
        print "switches: ", switches
        self.net.add_nodes_from(switches)
        print "net nodes: ", self.net.nodes()

        with open(OFP_LINK_PORT, 'w') as outp:
            # src_dpid dst_dpid src_dpid_output_port dst_dpid_input_port
            links_list = get_link(self.topology_data_app, None)
            # print links_list

            # add link from one direction
            links = [(link.src.dpid, link.dst.dpid,
                      {'out_port': link.src.port_no}) for link in links_list]
            # print links
            self.net.add_edges_from(links)
            for link in links:
                outp.write("%s %s %s\n" % (self._hostname_Check(link[0]),
                                           self._hostname_Check(link[1]), link[2]['out_port']))

            # add links from oppsite direction
            links = [(link.dst.dpid, link.src.dpid,
                      {'out_port': link.dst.port_no}) for link in links_list]
            # print links
            self.net.add_edges_from(links)
            for link in links:
                outp.write("%s %s %s\n" % (self._hostname_Check(link[0]),
                                           self._hostname_Check(link[1]), link[2]['out_port']))

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
                self._single_shortest_path()
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
