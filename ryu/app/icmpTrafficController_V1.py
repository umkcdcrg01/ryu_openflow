#  icmpTrafficController_V1
#  Jack Zhao
#  s.zhao.j@gmail.com
# fix negative output values

from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import os.path
import os
import pickle
# from my_switch_v11_topo_2 import SimpleSwitch13

OFP_SWITCHES_FLOW_STATS = \
    './network-data2/ofp_switches_{0}_flow_stats.db'
OFP_SWITCHES_FLOW_STATS_PREVIOUS = \
    './network-data2/ofp_switches_{0}_flow_stats_prev.db'
OFP_SWITCHES_PORT_STATS = \
    './network-data2/ofp_switches_{0}_port_stats.db'
OFP_SWITCHES_PORT_STATS_PREVIOUS = \
    './network-data2/ofp_switches_{0}_port_stats_prev.db'
OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data2/ofp_switches_list_prev.db'
OFP_SWITCHES_LIST = \
    './network-data2/ofp_switches_list.db'

OFP_ICMP_LOG = \
    './network-data2/ofp_icmp_log.db'

ICMP_PRIORITY = 3
IPERF_PRIORITY = 4
PRIORITY_LIST = [ICMP_PRIORITY, IPERF_PRIORITY]
STATS_UPDATE_TIMER = 2
ICMP_MATCH_LIST = "in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=1"
IPERF_TCP_MATCH_LIST = "in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,\
                                                                                   ipv4_dst=dst_ip, ip_proto=6, tcp_dst=dst_port, tcp_src=src_port"
IPERF_UDP_MATCH_LIST = "in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip, \
                                                                                   ipv4_dst=dst_ip, ip_proto=17, udp_dst=dst_port, udp_src=src_port"
OFP_ICMP_LOG = \
    './network-data2/ofp_icmp_log.db'
OFP_IPERF_LOG = \
    './network-data2/ofp_iperf_log.db'


class ICMPTrafficController(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(ICMPTrafficController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.hostname_list = {}
        self.sleep = 10
        # length of saved dictionary value
        self.state_len = 3
        self.icmp_stats = {}
        self.iperf_stats = {}

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(STATS_UPDATE_TIMER)

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

    def _request_stats(self, datapath):
        self.logger.info("icmpTrafficController: ")
        if(os.path.exists(OFP_ICMP_LOG)):
            with open(OFP_ICMP_LOG, 'r') as inp:
                for line in inp:
                    # self.logger.info("\t%s %s" % (line.strip(), type(line)))
                    icmp_path = line.split()[1:]
                    self.logger.info("\t%s" % (icmp_path))

        if(os.path.exists(OFP_ICMP_LOG)):
            with open(OFP_IPERF_LOG, 'r') as inp:
                for line in inp:
                    # self.logger.info("\t%s %s" % (line.strip(), type(line)))
                    iperf_path = line.split()[1:]
                    self.logger.info("\t%s" % (iperf_path))
