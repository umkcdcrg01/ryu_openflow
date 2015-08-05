# utilityLib_v1.py
#  Shuai Jack Zhao#

import os
import time
from ryu.ofproto import ofproto_v1_3
import cPickle
# from ryu.controller.handler import set_ev_cls
# from ryu.controller import ofp_event
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# from ryu.base import app_manager
# from ryu.app.wsgi import ControllerBase, WSGIApplication, route

# output ovs switch hostname and DPID pairs
# updated by OFP_SWITCHES_LIST_SCRIPT
OFP_SWITCHES_LIST = \
    './network-data2/ofp_switches_list.db'
OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data2/ofp_switches_list_prev.db'

OFP_SWITCHES_LIST_SCRIPT = \
    './scripts/remote_ovs_operation_topo_2/get_switch_ofpbr_datapath_id.sh'
OFP_MAC_TO_PORT = './network-data2/ofp_mac_to_port.db'
OFP_LINK_PORT = './network-data2/ofp_link_port.db'
OFP_HOST_SWITCHES_LIST = './network-data2/ofp_host_switches_list.db'  # upadate by host_tracker.py
OFP_HOST_SWITCHES_LIST_BACK = \
    './network-data2/ofp_host_switches_list_backup.db'
OFP_SINGLE_SHOREST_PATH = './network-data2/ofp_single_shortest_path.db'
OFP_ALL_PAIRS_SHOREST_PATH = './network-data2/ofp_all_pairs_shortest_path.db'
OFP_ALL_SIMPLE_PATH = './network-data2/ofp_all_simple_path.db'
OFP_ALL_PATHS_SHOREST_PATH = './network-data2/ofp_all_paths_shortest_path.db'
OFP_IPERF_LOG = \
    './network-data2/ofp_iperf_log.db'
OFP_SWITCH_FLOWS_LIST_DETAILS = \
    './network-data2/ofp_switches_{0}_flow_details.db'
OFP_DATAPATH_OBJ_LOG = \
    './network-data2/ofp_datapath_obj.db'


ICMP_PRIORITY = 3
IPERF_PRIORITY = 4
SSH_PRIORITY = 5
ICMP_IDLE_TIMER = 60
ICMP_REROUTE_IDLE_TIME = 70
HARD_TIMER = 0
IPERF_KEY_LEARNING_TIMER = 15
IPERF_TRACK_LIMIT = 1


class Utilites():

    def __init__(self, *args, **kwargs):
        self.mac_to_port = {}
        self.datapaths = {}
        # create thread for traffic monitoring
        # self.monitor_thread = hub.spawn(self._monitor)
        self.hostname_list = {}
        self.iperf_learning = {}
        self.iperf_track_list = {}
        # self._update_switch_dpid_list()

    # Given DPID, output hostname in string
    def hostname_Check(self, datapath):
        # print("UtilityLib:")
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
    # add flow
    ####################################################################
    def add_flow(self, datapath, priority, match, actions, idle_timer, hard_timer, buffer_id=0xffffffff):
        print("UtilityLib: ADD flow to %s %d" % (self.hostname_Check(datapath.id), datapath.id))
        # print type(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timer, hard_timeout=hard_timer,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timer, hard_timeout=hard_timer, instructions=inst)
        datapath.send_msg(mod)
        print("\tFlow installed!!!!!!!!!")

    def del_flow(self, datapath, priority, match, actions, idle_timer, hard_timer, output_port):
        print("UtilityLib: Delete flow from %s %d" % (self.hostname_Check(datapath.id), datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=datapath.ofproto.OFPFC_DELETE_STRICT,
                                out_group=datapath.ofproto.OFPP_ANY, out_port=output_port,
                                match=match, idle_timeout=idle_timer, hard_timeout=hard_timer, instructions=inst)
        datapath.send_msg(mod)

    # def unpickle_datapath_obj_file(self):
    #     print("UtilityLib: unpickle_datapath_obj_file")
    #     with open(OFP_DATAPATH_OBJ_LOG, 'rb') as inp:
    #         datapath_dict = cPickle.load(inp)
    #     print datapath_dict

    def install_flows_for_same_switch(self, switchname, traffic_mode, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, dpid_datapathObj, idle_timer, hard_timer):
        print("UtilityLib: install_flows_for_same_switch:")
        if traffic_mode == 'TCP' or traffic_mode == 'UDP':
            ipProto = 6
        if traffic_mode == 'ICMP':
            ipProto = 1
        src_inport = dst_inport = ''
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                host_ip, dpid, inport, mac = line.split()
                if src_mac == mac:
                    print("\tFound attached switch at %s for mac %s" % (self.hostname_Check(int(str(dpid), 16)), src_mac))
                    try:
                        datapath_obj = dpid_datapathObj[int(str(dpid), 16)]
                    finally:
                        print dpid_datapathObj
                    src_inport = int(inport)
                if dst_mac == mac:
                    dst_inport = int(inport)

                if src_inport and dst_inport:
                    print("\tAt %s  inport=%s another inport=%s" % (switchname, src_inport, dst_inport))
                    match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(src_inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                           ipv4_dst=dst_ip, ip_proto=ipProto, tcp_dst=dst_port, tcp_src=src_port)
                    actions = [datapath_obj.ofproto_parser.OFPActionOutput(dst_inport)]
                    self.add_flow(datapath_obj, SSH_PRIORITY, match_to_switch, actions, idle_timer, hard_timer)

                    # match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, ipv4_src=dst_ip,
                    #                                                      ipv4_dst=src_ip, tcp_src=dst_port, tcp_dst=src_port
                    match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=dst_inport, eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                           ipv4_dst=src_ip, ip_proto=ipProto, tcp_dst=src_port, tcp_src=dst_port)
                    reverse_actions = [datapath_obj.ofproto_parser.OFPActionOutput(int(src_inport))]
                    print("\tInstall reserse Flow from %s to %s inport=%s output_port=%s" % (self.hostname_Check(int(str(dpid), 16)), dst_mac, dst_inport, src_inport))
                    self.add_flow(datapath_obj, SSH_PRIORITY, match_to_switch, reverse_actions, idle_timer, hard_timer)

                    out = datapath_obj.ofproto_parser.OFPPacketOut(datapath=datapath_obj, buffer_id=0xffffffff,
                                                                   in_port=int(src_inport), actions=actions, data=None)
                    datapath_obj.send_msg(out)
                    return

    def install_flows_for_same_switch_v2(self, switchname, traffic_mode, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, dpid_datapathObj, idle_timer, hard_timer, msg):
        print("UtilityLib: install_flows_for_same_switch_v2: Reverse Install")
        if traffic_mode == 'TCP' or traffic_mode == 'UDP':
            ipProto = 6
        if traffic_mode == 'ICMP':
            ipProto = 1
        src_inport = dst_inport = ''
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                host_ip, dpid, inport, mac = line.split()
                if dst_mac == mac:
                    print("\tFound attached switch at %s for mac %s" % (self.hostname_Check(int(str(dpid), 16)), src_mac))
                    try:
                        datapath_obj = dpid_datapathObj[int(str(dpid), 16)]
                    finally:
                        print dpid_datapathObj
                    dst_inport = int(inport)
                if src_mac == mac:
                    src_inport = int(inport)

                if src_inport and dst_inport:
                    print("\tInstall Flow from %s to %s inport=%s output_port=%s" % (self.hostname_Check(int(str(dpid), 16)), dst_mac, dst_inport, src_inport))
                    match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(dst_inport), eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                           ipv4_dst=src_ip, ip_proto=ipProto, tcp_dst=src_port, tcp_src=dst_port)
                    actions = [datapath_obj.ofproto_parser.OFPActionOutput(src_inport)]
                    if msg.buffer_id != datapath_obj.ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath_obj, SSH_PRIORITY, match_to_switch, actions, idle_timer, hard_timer, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, SSH_PRIORITY, match_to_switch, actions, idle_timer, hard_timer)

                    # match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, ipv4_src=dst_ip,
                    #                                                      ipv4_dst=src_ip, tcp_src=dst_port, tcp_dst=src_port
                    match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=src_inport, eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                           ipv4_dst=dst_ip, ip_proto=ipProto, tcp_dst=dst_port, tcp_src=src_port)
                    reverse_actions = [datapath_obj.ofproto_parser.OFPActionOutput(int(dst_inport))]
                    print("\tInstall reserse Flow from %s to %s inport=%s output_port=%s" % (self.hostname_Check(int(str(dpid), 16)), src_mac, src_inport, dst_inport))
                    if msg.buffer_id != datapath_obj.ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath_obj, SSH_PRIORITY, match_to_switch, reverse_actions, idle_timer, hard_timer, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, SSH_PRIORITY, match_to_switch, reverse_actions, idle_timer, hard_timer)

                    data = None
                    if msg.buffer_id == datapath_obj.ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = datapath_obj.ofproto_parser.OFPPacketOut(datapath=datapath_obj, buffer_id=msg.buffer_id,
                                                                   in_port=int(src_inport), actions=actions, data=data)
                    datapath_obj.send_msg(out)

    def install_flows_for_rest_of_switches(self, shorestPath, traffic_mode, priority, src_ip, dst_ip, src_mac, dst_mac, dpid_datapathObj, idle_timer, hard_timer):
        # shortest path is list of strings
        print("UtilityLib: install_flows_for_rest_of_switches:")
        count = len(shorestPath)
        switch_dpid_list = {}
        print("\tRead switch name and dpid into switch_dpid_list")
        with open(OFP_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                switch_name = line.split()[0]
                dpid = int(line.split()[1], 16)
                switch_dpid_list[switch_name] = dpid

        print("\t switch_dpid_list %s" % switch_dpid_list)

        if traffic_mode == 'TCP' or traffic_mode == 'UDP':
            ipProto = 6
        if traffic_mode == 'ICMP':
            ipProto = 1

        for i in xrange(count):
            if i != 0 and i != count - 1:
                current_switch_name = shorestPath[i]
                previsou_switch_name = shorestPath[i - 1]
                next_switch_name = shorestPath[i + 1]
                datapath_obj = dpid_datapathObj[switch_dpid_list[current_switch_name]]
                in_port = int(self.return_switch_connection_port(current_switch_name, previsou_switch_name))
                out_port = int(self.return_switch_connection_port(current_switch_name, next_switch_name))
                print("\tInstall Flow at %s inport=%s output_port=%s" % (current_switch_name, in_port, out_port))
                match = datapath_obj.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                             ipv4_dst=dst_ip, ip_proto=ipProto)
                actions = [datapath_obj.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath_obj, priority, match, actions, idle_timer, hard_timer)

                print("\tInstall Reverse Flow at %s  inport=%s output_port=%s" % (current_switch_name, out_port, in_port))
                reverse_match = datapath_obj.ofproto_parser.OFPMatch(in_port=out_port, eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                     ipv4_dst=src_ip, ip_proto=ipProto)
                reverse_actions = [datapath_obj.ofproto_parser.OFPActionOutput(in_port)]
                self.add_flow(datapath_obj, priority, reverse_match, reverse_actions, idle_timer, hard_timer)

    def install_flow_between_host_and_switch_for_TCP_UDP(
            self, h_mac, traffic_mode, pritority, shorestPath,
            host_position, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, dpid_datapathObj, idle_timer, hard_timer, msg=None):
        print("> UtilityLib: Install flows between host and switch for TCP and UDP")
        # 192.168.1.25 0000ae7e24cd5e40 2 02:63:ff:a5:b1:0f
        # first found out which switch does this host attach to
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                host_ip, dpid, inport, mac = line.split()
                if h_mac == mac:
                    print("\tFound attached switch at %s for mac %s" % (self.hostname_Check(int(str(dpid), 16)), h_mac))

                    datapath_obj = dpid_datapathObj[int(str(dpid), 16)]
                    print("\t%s %s %s %s %s %s %s" % (type(inport), type(dst_mac), type(src_mac), type(src_ip), type(dst_ip), type(src_port), type(dst_port)))
                    # match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, ipv4_src=src_ip,
                    #                                                        ipv4_dst=dst_ip, tcp_src=src_port, tcp_dst=dst_port)
                    if host_position == 0:
                        if traffic_mode == 'TCP':
                            match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                                   ipv4_dst=dst_ip, ip_proto=6, tcp_dst=dst_port, tcp_src=src_port)
                        if traffic_mode == 'UDP':
                            match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                                   ipv4_dst=dst_ip, ip_proto=17, udp_dst=dst_port, udp_src=src_port)
                    elif host_position == 1:
                        if traffic_mode == 'TCP':
                            match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                                   ipv4_dst=src_ip, ip_proto=6, tcp_dst=src_port, tcp_src=dst_port)
                        if traffic_mode == 'UDP':
                            match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                                   ipv4_dst=src_ip, ip_proto=17, udp_dst=src_port, udp_src=dst_port)

                    # found out output port
                    output_port = int(self.return_switch_connection_port(shorestPath[0], shorestPath[1]))
                    actions = [datapath_obj.ofproto_parser.OFPActionOutput(output_port)]
                    print("\tInstall Flow from %s to %s inport=%s output_port=%s" % (h_mac, self.hostname_Check(int(str(dpid), 16)), inport, output_port))
                    if msg.buffer_id != datapath_obj.ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath_obj, pritority, match_to_switch, actions, idle_timer, hard_timer, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, pritority, match_to_switch, actions, idle_timer, hard_timer)

                    # match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, ipv4_src=dst_ip,
                    #                                                      ipv4_dst=src_ip, tcp_src=dst_port, tcp_dst=src_port)
                    if host_position == 0:
                        if traffic_mode == 'TCP':
                            match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                                 ipv4_dst=src_ip, ip_proto=6, tcp_src=dst_port, tcp_dst=src_port)
                        if traffic_mode == 'UDP':
                            match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                                 ipv4_dst=src_ip, ip_proto=17, udp_src=dst_port, udp_dst=src_port)
                    elif host_position == 1:
                        if traffic_mode == 'TCP':
                            match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                                 ipv4_dst=dst_ip, ip_proto=6, tcp_src=src_port, tcp_dst=dst_port)
                        if traffic_mode == 'UDP':
                            match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                                 ipv4_dst=dst_ip, ip_proto=17, udp_src=src_port, udp_dst=dst_port)

                    reverse_actions = [datapath_obj.ofproto_parser.OFPActionOutput(int(inport))]
                    print("\tInstall reserse Flow from %s to %s inport=%s output_port=%s" % (self.hostname_Check(int(str(dpid), 16)), h_mac, output_port, inport))
                    if msg.buffer_id != datapath_obj.ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath_obj, pritority, match_to_host, reverse_actions, idle_timer, hard_timer, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, pritority, match_to_host, reverse_actions, idle_timer, hard_timer)

                    out = datapath_obj.ofproto_parser.OFPPacketOut(datapath=datapath_obj, buffer_id=0xffffffff,
                                                                   in_port=int(inport), actions=actions, data=msg.data)
                    datapath_obj.send_msg(out)

    def install_flow_between_host_and_switch_for_ICMP(self, h_mac, traffic_mode, shorestPath, host_position, src_ip, dst_ip, src_mac, dst_mac, dpid_datapathObj):
        print("UtilityLib: Install flows between host and switch for ICMP")
        # 192.168.1.25 0000ae7e24cd5e40 2 02:63:ff:a5:b1:0f
        # first found out which switch does this host attach to
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                host_ip, dpid, inport, mac = line.split()
                if h_mac == mac:
                    print("\tFound attached switch at %s for mac %s" % (self.hostname_Check(int(str(dpid), 16)), h_mac))
                    try:
                        datapath_obj = dpid_datapathObj[int(str(dpid), 16)]
                    finally:
                        print dpid_datapathObj
                    print("\t%s %s %s %s %s" % (type(inport), type(dst_mac), type(src_mac), type(src_ip), type(dst_ip)))
                    # match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, ipv4_src=src_ip,
                    #                                                        ipv4_dst=dst_ip, tcp_src=src_port, tcp_dst=dst_port)
                    if host_position == 0:
                        match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                               ipv4_dst=dst_ip, ip_proto=1)
                    elif host_position == 1:
                        match_to_switch = datapath_obj.ofproto_parser.OFPMatch(in_port=int(inport), eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                               ipv4_dst=src_ip, ip_proto=1)

                    # found out output port
                    output_port = int(self.return_switch_connection_port(shorestPath[0], shorestPath[1]))
                    actions = [datapath_obj.ofproto_parser.OFPActionOutput(output_port)]
                    print("\tInstall Flow from %s to %s inport=%s output_port=%s" % (h_mac, self.hostname_Check(int(str(dpid), 16)), inport, output_port))
                    self.add_flow(datapath_obj, ICMP_PRIORITY, match_to_switch, actions, ICMP_REROUTE_IDLE_TIME, HARD_TIMER)

                    # match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, ipv4_src=dst_ip,
                    #                                                      ipv4_dst=src_ip, tcp_src=dst_port, tcp_dst=src_port)
                    if host_position == 0:
                        match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=src_mac, eth_src=dst_mac, eth_type=0x0800, ipv4_src=dst_ip,
                                                                             ipv4_dst=src_ip, ip_proto=1)
                    elif host_position == 1:
                        match_to_host = datapath_obj.ofproto_parser.OFPMatch(in_port=output_port, eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
                                                                             ipv4_dst=dst_ip, ip_proto=1)

                    reverse_actions = [datapath_obj.ofproto_parser.OFPActionOutput(int(inport))]
                    print("\tInstall reserse Flow from %s to %s inport=%s output_port=%s" % (self.hostname_Check(int(str(dpid), 16)), h_mac, output_port, inport))
                    self.add_flow(datapath_obj, ICMP_PRIORITY, match_to_host, reverse_actions, ICMP_REROUTE_IDLE_TIME, HARD_TIMER)

                    out = datapath_obj.ofproto_parser.OFPPacketOut(datapath=datapath_obj, buffer_id=0xffffffff,
                                                                   in_port=int(inport), actions=actions, data=None)
                    datapath_obj.send_msg(out)

    def return_decimalDPID_baseON_swithName(self, switchName):
        print("UtilityLib: return_decimalDPID_baseON_swithName:")
        # input switchName are strings: S1, S3 ....
        # return decimal dpid based on string names
        with open(OFP_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                if switchName == line.split()[0]:
                    # return a decimal DPID
                    print("\tfound dpid %s for switchname %s" % (int(str(line.split()[1]), 16), switchName))
                    return int(str(line.split()[1]), 16)

    def return_switch_connection_port(self, switch1, switch2):
        print("UtilityLib: return_switch_connection_por:")
        # return a port number from switch1 to switch2
        # switch1 and switch2 are switchnames: s1, s2
        # OFP_LINK_PORT file are decimal number based
        connection_port = None
        switch1_dpid = self.return_decimalDPID_baseON_swithName(switch1)
        switch2_dpid = self.return_decimalDPID_baseON_swithName(switch2)
        with open(OFP_LINK_PORT, 'r') as inp:
            for line in inp:
                if str(switch1_dpid) == line.split()[0] and str(switch2_dpid) == line.split()[1]:
                    connection_port = line.split()[2]
                    print("\tfound connection_port %s %s" % (connection_port, type(connection_port)))
                    break
        return connection_port

    def return_dst_dpid_hostname(self, dst_ip, dst_mac):
        # return destination switch's name (ex 'S1') based on given HOST's destination IP and mac address
        print("Utilites: return dstination DPID as Hostname")
        dst_dpid_name = None
        # time.sleep(2)
        # print("\tsleeping for another 2 s .......................")
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for lines in inp:
                ip_address, dpid, inport, host_mac = lines.split()
                if ip_address == dst_ip and host_mac == dst_mac:
                    dst_dpid_name = self.hostname_Check(int(str(dpid), 16))
                    print("\tFound at match at .....................................%s" % dst_dpid_name)
                    return dst_dpid_name

        if dst_dpid_name == None:
            print("\tsleeping for another 2 s ~~~~~~~.....................~~~~~")
            time.sleep(2)
            with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
                for lines in inp:
                    ip_address, dpid, inport, host_mac = lines.split()
                    if ip_address == dst_ip and host_mac == dst_mac:
                        dst_dpid_name = self.hostname_Check(int(str(dpid), 16))
                        print("\tFound at match at ~~~~~~~.....................~~~~~~%s" % dst_dpid_name)
                        return dst_dpid_name
        return dst_dpid_name

    def return_shortest_path(self, src_dpid_name, dst_dpid_name):
        # return a list of switch's name ['s1', 's2', 's3']
        print("UtilityLib: return_dst_dpid_hostname:")
        if src_dpid_name == dst_dpid_name:
            print("\tBelong to same switch")
            shortest_path = src_dpid_name
            return [shortest_path]

        # procceed only src switch name not equal to dst_dpid_name
        with open(OFP_SINGLE_SHOREST_PATH, 'r') as inp:
            # s4->s5 s4-s3-s2-s1-s5-
            for line in inp:
                if src_dpid_name == line.split()[0].split('->')[0] and dst_dpid_name == line.split()[0].split('->')[1]:
                    print("\tFount shortest path %s" % line.split()[1])
                    shortest_path = line.split()[1].rstrip('-').split('-')
                    print("\tshortestPath: %s" % shortest_path)
                    return shortest_path

    def return_all_shortest_paths(self, src_dpid_name, dst_dpid_name):
        # return a list of switch's name ['s1', 's2', 's3']
        print("UtilityLib: return_all_shortestPaths:")
        all_shortestPaths = []
        with open(OFP_ALL_SIMPLE_PATH, 'r') as inp:
            # s4->s5 s4-s3-s2-s1-s5-
            for line in inp:
                if src_dpid_name == line.split()[0].split('->')[0] and dst_dpid_name == line.split()[0].split('->')[1]:
                    print("\tFount shortest path %s" % line.split()[1])
                    shortest_path = line.split()[1].rstrip('-').split('-')
                    print("\tshortestPath: %s" % shortest_path)
                    all_shortestPaths.append(shortest_path)
        return all_shortestPaths

    def return_flows_info_based_on_switch_name(self, switchName, traffic_mode, priority):
        print("Utilites: return_flows_based_on_switch_name:")
        flow_info = []
        if traffic_mode == "ICMP" and priority == ICMP_PRIORITY:
            print("\tICMP Traffic")
            with open(OFP_SWITCH_FLOWS_LIST_DETAILS.format(switchName), 'r') as outp:
                for line in outp:
                    in_port, src_mac, dst_mac, ip_proto, idle_timeout, src_ip, dst_ip, output_port, priority =\
                        line.split()[1], line.split()[2], line.split()[3], line.split()[4],\
                        line.split()[5], line.split()[6], line.split()[7], line.split()[8], line.split()[9]
                    if int(idle_timeout) == ICMP_IDLE_TIMER:
                        flow_info.append([in_port, src_mac, dst_mac, ip_proto, idle_timeout, src_ip, dst_ip, output_port, priority])
        return flow_info

    def delete_flow_along_path(self, path):
        pass
