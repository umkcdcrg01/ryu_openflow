#  icmpTrafficController_V1
#  Jack Zhao
#  s.zhao.j@gmail.com
# fix negative output values

from __future__ import division
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import os.path
import os
# import pickle
from utilityLib_v1 import Utilites
import time
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
OFP_HOST_SWITCHES_LIST = './network-data2/ofp_host_switches_list.db'  # upadate by host_tracker.py

STATS_UPDATE_TIMER = 2
ICMP_PRIORITY = 3
IPERF_PRIORITY = 4
ICMP_IDLE_TIMER = 60
ICMP_REROUTE_IDLE_TIME = 70
HARD_TIMER = 0
IPERF_KEY_LEARNING_TIMER = 15
IPERF_TRACK_LIMIT = 1


ICMP_MATCH_LIST = "in_port=in_port, eth_dst=dst, eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=1"
IPERF_TCP_MATCH_LIST = "in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,\
                                                                                   ipv4_dst=dst_ip, ip_proto=6, tcp_dst=dst_port, tcp_src=src_port"
IPERF_UDP_MATCH_LIST = "in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip, \
                                                                                   ipv4_dst=dst_ip, ip_proto=17, udp_dst=dst_port, udp_src=src_port"
OFP_ICMP_LOG = \
    './network-data2/ofp_icmp_log.db'
OFP_IPERF_LOG = \
    './network-data2/ofp_iperf_log.db'
OFP_ICMP_REROUTE_LOG = \
    './network-data2/ofp_icmp_reroute_log.db'


class ICMPTrafficController(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(ICMPTrafficController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.hostname_list = {}
        self.sleep = 10
        # length of saved dictionary value
        self.state_len = 3
        self.icmp_stats = {}
        self.iperf_stats = {}
        self.traffic_checked_list = []
        self.util = Utilites()
        self.dpid_datapathObj = {}

    ###################################################################
    # ofp_event.EventOFPSwitchFeatures
    ####################################################################
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # self._update_switch_dpid_list()
        self.logger.debug("switch_features_handler: ")
        msg = ev.msg
        datapath = ev.msg.datapath
        dpid = datapath.id
        # save datapath object into dpid_datapath
        # here dpid is a integer, not Hex number
        self.dpid_datapathObj[dpid] = ev.msg.datapath
        # print self.dpid_datapathObj
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser

        # self.logger.debug(
        #     "   datapath in decimal %s,in hex %s",
        #     datapath.id, hex(int(datapath.id)))
        # self.logger.debug('   OFPSwitchFeatures received: '
        #                  'datapath_id=0x%016x n_buffers=%d '
        #                  'n_tables=%d auxiliary_id=%d '
        #                  'capabilities=0x%08x',
        #                  msg.datapath_id, msg.n_buffers, msg.n_tables,
        #                  msg.auxiliary_id, msg.capabilities)

    def _monitor(self):
        while True:
            self._request_stats()
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

    def _request_stats(self):
        self.logger.debug("icmpTrafficController: ")
        if(not os.path.exists(OFP_ICMP_LOG)):
            icmp_detail = ""
            icmp_path = []
        else:
            with open(OFP_ICMP_LOG, 'r') as inp:
                for line in inp:
                    # self.logger.debug("\t%s %s" % (line.strip(), type(line)))
                    icmp_path = line.split()[2:-1]
                    icmp_detail = line
                    self.logger.debug("\tICMP %s" % (icmp_path))

        if(not os.path.exists(OFP_IPERF_LOG)):
            iperf_detail = ""
            iperf_path = []
        else:
            with open(OFP_IPERF_LOG, 'r') as inp:
                for line in inp:
                    iperf_detail = line
                    # self.logger.debug("\t%s %s" % (line.strip(), type(line)))
                    iperf_path = line.split()[6:]
                    self.logger.debug("\tIPERF %s" % (iperf_path))

        # self.traffic_checked_list only save one icmp traffic and iperf traffic,
        # icmp/iperf detailed get update for every different ping/iperf_client
        if icmp_path and iperf_path:
            if len(self.traffic_checked_list) == 0:
                self.traffic_checked_list.insert(0, icmp_detail)
                self.traffic_checked_list.insert(1, iperf_detail)
                if self.check_if_path_overlape(icmp_path, iperf_path):
                    self.logger.debug("\t1. Path OVerlap, Now check if Iperf traffic is over 50Mbits/s~~~~~~~~~~~~~~~~~~~~~~~")
                    if self.check_iperf_traffic_on_path(iperf_path) > 50:
                        self.logger.debug("\t1. Install new flows for ICMP traffic from %s to %s" % (icmp_path[0], icmp_path[-1]))
                        if self.check_if_icmp_traffic_on(icmp_path):
                            self.icmp_reroute(icmp_path, icmp_detail)
                return
            elif(icmp_detail not in self.traffic_checked_list):
                self.traffic_checked_list.pop(0)
                self.traffic_checked_list.insert(0, icmp_detail)
                if self.check_if_path_overlape(icmp_path, iperf_path):
                    self.logger.debug("\t2. Path OVerlap, Now check if Iperf traffic is over 50Mbits/s~~~~~~~~~~~~~~~~~~~~~~~")
                    if self.check_iperf_traffic_on_path(iperf_path) > 50:
                        self.logger.debug("\t2. Install new flows for ICMP traffic from %s to %s" % (icmp_path[0], icmp_path[-1]))
                        if self.check_if_icmp_traffic_on(icmp_path):
                            self.icmp_reroute(icmp_path, icmp_detail)
                return
            elif(iperf_detail not in self.traffic_checked_list):
                self.traffic_checked_list.pop(1)
                self.traffic_checked_list.insert(1, iperf_detail)
                if self.check_if_path_overlape(icmp_path, iperf_path):
                    self.logger.debug("\t3. Path OVerlap, Now check if Iperf traffic is over 50Mbits/s~~~~~~~~~~~~~~~~~~~~~~~")
                    if self.check_iperf_traffic_on_path(iperf_path) > 50:
                        self.logger.debug("\t3. Install new flows for ICMP traffic from %s to %s" % (icmp_path[0], icmp_path[-1]))
                        if self.check_if_icmp_traffic_on(icmp_path):
                            self.icmp_reroute(icmp_path, icmp_detail)
                return

            # icmp and iperf happens at the same time

    def icmp_reroute(self, icmp_path, icmp_detail):
        self.logger.debug("ICMPTrafficController:")
        # find the current icmp_path flows
        # based on recored icmp packge information, find a new path which is different from the currernt one, install new flows, delete all the flows
        icmp_info = icmp_detail.split()[-1]
        src_mac, dst_mac, src_ip, dst_ip = icmp_info.split('-')[1], icmp_info.split('-')[2],\
            icmp_info.split('-')[3], icmp_info.split('-')[4]
        self.logger.debug("\tFinding the second shortest path for %s %s %s %s %s" % (icmp_path[0], src_mac, dst_mac, src_ip, dst_ip))
        src_dpid_name = icmp_path[0]
        dst_dpid_name = icmp_path[-1]
        all_shortest_path = self.util.return_all_shortest_paths(src_dpid_name, dst_dpid_name)
        self.logger.debug("\tAll all_shortest_path: %s", all_shortest_path)
        for path in all_shortest_path:
            if icmp_path != path:
                second_new_path = path

        self.logger.debug("\tFound the second new path %s" % second_new_path)
        hosts = [src_mac, dst_mac]
        # install flows bettween host and switches
        self.install_flows_for_hosts_and_attached_switches(hosts, second_new_path, src_ip, dst_ip, src_mac, dst_mac)
        # install flow for the rest of switches
        if len(second_new_path) > 2:
            self.util.install_flows_for_rest_of_switches(
              second_new_path, 'ICMP', ICMP_PRIORITY, src_ip, dst_ip, src_mac, dst_mac, self.dpid_datapathObj, ICMP_IDLE_TIMER, HARD_TIMER)

        # write to the icmp rereoute log
        with open(OFP_ICMP_REROUTE_LOG, 'w') as inp:
            inp.write("%s %s %s" % (src_mac, dst_mac, second_new_path))

        # delete previous flows
        self.logger.debug("delete old icmp flows along the prevous path")
        for node in icmp_path:
            self.logger.debug("\tDelete Flows From %s" % node)
            # match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=0x0800, ipv4_src=src_ip,
            #                                 ipv4_dst=dst_ip, ip_proto=1)
            previous_flows = self.util.return_flows_info_based_on_switch_name(node, 'ICMP', ICMP_PRIORITY)
            self.logger.debug("\t previous_flows details %s" % previous_flows)
            node_dpid = self.util.return_decimalDPID_baseON_swithName(node)
            node_datapath_obj = self.dpid_datapathObj[int(node_dpid)]
            for each_path in previous_flows:
                # in_port, src_mac, dst_mac, ip_proto, idle_timeout, src_ip, dst_ip, output_port, priorit
                # ['2', '02:26:11:36:df:68', '02:39:2f:fa:2f:a9', '1', '60', '192.168.1.9', '192.168.1.21', '3', '3']
                match = node_datapath_obj.ofproto_parser.OFPMatch(in_port=int(each_path[0]), eth_src=each_path[1], eth_dst=each_path[2], eth_type=0x0800, ipv4_src=each_path[5],
                                                                  ipv4_dst=each_path[6], ip_proto=1)
                actions = [node_datapath_obj.ofproto_parser.OFPActionOutput(int(each_path[7]))]
                self.util.del_flow(node_datapath_obj, ICMP_PRIORITY, match, actions, ICMP_IDLE_TIMER, HARD_TIMER, int(each_path[7]))
                self.logger.debug("\tDeleted at %s %s %s %s %s %s %s" % (node, each_path[0], each_path[1], each_path[2], each_path[5], each_path[6], each_path[7]))

    def install_flows_for_hosts_and_attached_switches(self, hosts, shortest_path, src_ip, dst_ip, src_mac, dst_mac):
        count = 0
        for h_mac in hosts:
            if count < len(hosts) and count == 0:
                self.util.install_flow_between_host_and_switch_for_ICMP(
                    h_mac, 'ICMP', shortest_path[count:count + 2], count, src_ip, dst_ip, src_mac, dst_mac, self.dpid_datapathObj)
                count += 1
            elif count < len(hosts) and count == 1:
                self.util.install_flow_between_host_and_switch_for_ICMP(
                     h_mac, 'ICMP', list([shortest_path[len(shortest_path) - 1], shortest_path[len(shortest_path) - 2]]),
                     count, src_ip, dst_ip, src_mac, dst_mac, self.dpid_datapathObj)
                count += 1

    def check_if_path_overlape(self, path1, path2):
        # return True is one of them is subset of another one
        # path1 and path2 are lists
        # path1 ('02:26:11:36:df:68', '02:39:2f:fa:2f:a9')  s1 s5 s4
        # path2 ('02:63:ff:a5:b1:0f', '02:a5:6e:49:09:5d', '192.168.1.25', '192.168.1.8', 47409, 5001)  s5 s1
        path1_set = set(path1)
        path2_set = set(path2)
        if path1_set.issubset(path2_set) or path2_set.issubset(path1_set):
            return True

    def check_iperf_traffic_on_path(self, iperf_path):
        # given a iperf path, return the size of the flow traffic on this path
        bandwidth_usage = 100  # for now we assume it always bigger than 100
        time.sleep(1)
        return bandwidth_usage

    def check_if_icmp_traffic_on(self, path1):
        # at this point, we assume icmp is always on
        return True
