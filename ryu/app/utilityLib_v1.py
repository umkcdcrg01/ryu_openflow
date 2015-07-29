# utilityLib_v1.py
#  Shuai Jack Zhao#

import os
import time

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

ICMP_PRIORITY = 3
IPERF_PRIORITY = 4
IDLE_TIMER = 120
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
        self.dpid_datapathObj = {}
        self.iperf_learning = {}
        self.iperf_track_list = {}
        # self._update_switch_dpid_list()

    # Given DPID, output hostname in string
    def hostname_Check(self, datapath):
        print("UtilityLib:")
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
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print("UtilityLib: add flow to %s %d" % (self.hostname_Check(datapath.id), datapath.id))
        # print type(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=IDLE_TIMER, hard_timeout=HARD_TIMER,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=IDLE_TIMER, hard_timeout=HARD_TIMER, instructions=inst)
        datapath.send_msg(mod)
        print("\tFlow installed!!!!!!!!!")

    def install_flow_between_switches(self, switch1, switch2, src_ip, dst_ip, src_port, dst_port, in_port, src_mac, dst_mac, msg):
        # input switch1 and switch2 are string: 's1', 's2'
        # print("Install Flow from %s to %s" % (switch1, switch2))
        # connection_port = self.return_switch_connection_port(switch1, switch2)
        print("HAVE NOT INPLMENETED when shortest_path is longer than 2!!!!!!!!")
        pass

    def install_flow_between_host_and_switch(self, h_mac, traffic_mode, shorestPath, host_position, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg):
        print("> UtilityLib: Install flows between host and switch")
        # 192.168.1.25 0000ae7e24cd5e40 2 02:63:ff:a5:b1:0f
        # first found out which switch does this host attach to
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                host_ip, dpid, inport, mac = line.split()
                if h_mac == mac:
                    print("\tFound attached switch at %s for mac %s" % (self.hostname_Check(int(str(dpid), 16)), h_mac))

                    datapath_obj = self.dpid_datapathObj[int(str(dpid), 16)]
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
                        self.add_flow(datapath_obj, IPERF_PRIORITY, match_to_switch, actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, IPERF_PRIORITY, match_to_switch, actions)

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
                        self.add_flow(datapath_obj, IPERF_PRIORITY, match_to_host, reverse_actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, IPERF_PRIORITY, match_to_host, reverse_actions)

                    out = datapath_obj.ofproto_parser.OFPPacketOut(datapath=datapath_obj, buffer_id=0xffffffff,
                                                                   in_port=int(inport), actions=actions, data=msg.data)
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
        self.logger.debug("return dstination DPID as Hostname")
        dst_dpid_name = None
        # print("\tsleeping for another 10 s .......................")
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for lines in inp:
                ip_address, dpid, inport, host_mac = lines.split()
                if ip_address == dst_ip and host_mac == dst_mac:
                    dst_dpid_name = self.hostname_Check(int(str(dpid), 16))
                    print("\tFound at match at .....................................%s" % dst_dpid_name)
                    break
        if dst_dpid_name == None:
            print("\tsleeping for another 10 s ........................")
            time.sleep(10)
            with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
                for lines in inp:
                    ip_address, dpid, inport, host_mac = lines.split()
                    if ip_address == dst_ip and host_mac == dst_mac:
                        dst_dpid_name = self.hostname_Check(int(str(dpid), 16))
                        print("\tFound at match at .......................................%s" % dst_dpid_name)
                        break
        return dst_dpid_name

    def return_shortest_path(self, src_dpid_name, dst_dpid_name):
        # return a list of switch's name ['s1', 's2', 's3']
        print("UtilityLib: return_dst_dpid_hostname:")
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
    