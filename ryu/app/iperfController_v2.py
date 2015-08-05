# Iperf_controller_v1.py
#  Shuai Jack Zhao
# Iperf Match filed
# in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
#                                                                               ipv4_dst=dst_ip, ip_proto=6, tcp_dst=dst_port, tcp_src=src_port
#
#
# updated install_flow_between_switches functions
# update UDP traffic function

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, tcp, udp
from ryu.controller import dpset
from ryu.lib.packet.lldp import LLDP_MAC_NEAREST_BRIDGE
# from ryu.lib.packet.ether_types import ETH_TYPE_LLDP
import os
import time
import pickle


# import myswitch_v13
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


class IperfController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(IperfController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.datapaths = {}
        # create thread for traffic monitoring
        # self.monitor_thread = hub.spawn(self._monitor)
        self.hostname_list = {}
        self.dpid_datapathObj = {}
        self.iperf_learning = {}
        self.iperf_track_list = {}
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

        # self.logger.info(
        #     "   datapath in decimal %s,in hex %s",
        #     datapath.id, hex(int(datapath.id)))
        # self.logger.info('   OFPSwitchFeatures received: '
        #                  'datapath_id=0x%016x n_buffers=%d '
        #                  'n_tables=%d auxiliary_id=%d '
        #                  'capabilities=0x%08x',
        #                  msg.datapath_id, msg.n_buffers, msg.n_tables,
        #                  msg.auxiliary_id, msg.capabilities)

    ###################################################################
    # add flow
    ####################################################################
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        self.logger.info("IperfController: add flow to %s %d" % (self._hostname_Check(datapath.id), datapath.id))
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
        self.logger.info("\tFlow installed!!!!!!!!!")

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
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst_mac = eth.dst
        if dst_mac == LLDP_MAC_NEAREST_BRIDGE:
            return

        if not pkt_ethernet:
            return
        else:
            pass
            self.logger.debug("IperfController: Packet-In:")
            # self.logger.info("\tether_packet: at %s %s " % (self._hostname_Check(datapath.id), pkt_ethernet))

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            pass
            return
        # pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        # if pkt_ipv4:
        #     self.logger.info("\tIPV4_packet: at %s %s " % (self._hostname_Check(datapath.id), pkt_ipv4))

        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_tcp or pkt_udp:
            # self.logger.info("\tTCP_packet: at %s %s " % (self._hostname_Check(datapath.id), pkt_tcp))
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            in_port = msg.match['in_port']
            src_mac = eth.src
            # parser = datapath.ofproto_parser
            if pkt_tcp:
                src_port = pkt_tcp.src_port
                dst_port = pkt_tcp.dst_port
            if pkt_udp:
                src_port = pkt_udp.src_port
                dst_port = pkt_udp.dst_port
            if str(dst_port) == '5001':
                self.logger.Info("IperfController: Packet-In:")
                self.logger.info("\tAt %s from %s to %s from src_port %s to dst_port %s from  port %s src_mac %s dst_mac %s" %
                             (self._hostname_Check(datapath.id), src_ip, dst_ip, src_port, dst_port, in_port, src_mac, dst_mac))
                key = (src_ip, dst_ip, src_mac, dst_mac, dst_port)
                if key not in self.iperf_learning.keys():
                    if pkt_tcp:
                        self.logger.info("\t############# TCP Iperf Traffic#####################")
                    if pkt_udp:
                        self.logger.info("\t############# UDP Iperf Traffic#####################")
                    self.logger.debug("\tOnly process the first IPERF client request")
                    self.logger.info("\tThis is a new Iperf client request!! Added to self.iperf_learning dict")
                    # if self.iperf_learning is empty

                    # this valuw will be used at a timer, This entry will be cleard after 2 mins
                    value = time.time()
                    self.iperf_learning[key] = value
                elif key in self.iperf_learning.keys():
                    if time.time() - self.iperf_learning[key] >= IPERF_KEY_LEARNING_TIMER:
                        self.logger.info("\t(src_ip, dst_ip, src_mac, dst_mac, dst_port, in_port) TIMEOUT from self.iperf_learning dict!!!")
                        del self.iperf_learning[key]
                        self.iperf_learning[key] = time.time()
                    else:
                        return
                else:
                    return
                src_dpid_name = self._hostname_Check(datapath.id)
                self.logger.info("\tInstall Iperf flow between IP address %s and %s \n\tsleeping for 5 s ........................" % (src_ip, dst_ip))
                time.sleep(5)
                # find dstination datapath id from host_tracker file
                dst_dpid_name = self.return_dst_dpid_hostname(dst_ip, dst_mac)
                if dst_dpid_name == None:
                    self.logger.info("\tcould not find destination switch..............")
                    return

                self.logger.info("\tInstall Iperf flow between %s and %s" % (src_dpid_name, dst_dpid_name))

                # Now only consider two end hosts
                hosts = [src_mac, dst_mac]
                # find shortest path between two switches, a list of hostnames ['s1','s2','s3']
                shortest_path = self.return_shortest_path(src_dpid_name, dst_dpid_name)

                self.logger.info("\tWrite to IPERF Log")
                final_named_list = ""
                if len(self.iperf_track_list.keys()) < IPERF_TRACK_LIMIT:
                    self.iperf_track_list[(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)] = shortest_path
                elif(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port) not in self.iperf_track_list.keys():
                    self.iperf_track_list = {}
                    self.iperf_track_list[(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)] = shortest_path
                with open(OFP_IPERF_LOG, 'w') as inp:
                    for key in self.iperf_track_list.keys():
                        shortest_path_name_list = [self._hostname_Check(i) for i in shortest_path]
                    for i in shortest_path_name_list:
                        final_named_list = final_named_list + " " + i
                    inp.write("%s %s" % (key, final_named_list))

                # install flows between hosts and switch
                count = 0
                for h_mac in hosts:
                    if count < len(hosts) and count == 0:
                        if pkt_tcp:
                            self.install_flow_between_host_and_switch(
                                h_mac, 'TCP', shortest_path[count:count + 2], count, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg)
                        if pkt_udp:
                            self.install_flow_between_host_and_switch(
                                h_mac, 'UDP', shortest_path[count:count + 2], count, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg)
                        count += 1
                    elif count < len(hosts) and count == 1:
                        if pkt_tcp:
                            self.install_flow_between_host_and_switch(
                                h_mac, 'TCP', list([shortest_path[len(shortest_path) - 1], shortest_path[len(shortest_path) - 2]]),
                                count, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg)
                        if pkt_udp:
                            self.install_flow_between_host_and_switch(
                                h_mac, 'UDP', list([shortest_path[len(shortest_path) - 1], shortest_path[len(shortest_path) - 2]]),
                                count, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg)
                        count += 1

                # install flows between shortest_path
                # only install flows between shortest_path if shortest list is longer than 2, otherwise install_flow_between_host_and_switch has been taken care the flows
                if len(shortest_path) > 2:
                    for index, dpid_name in enumerate(shortest_path):
                        if index + 1 < len(shortest_path):
                            src_dpid_obj = shortest_path[index]
                            index += 1
                            dst_dpi_obj = shortest_path[index]
                            self.install_flow_between_switches(src_dpid_obj, dst_dpi_obj, src_ip, dst_ip, src_port, dst_port, in_port, src_mac, dst_mac, msg)

        # pkt_udp = pkt.get_protocol(udp.udp)
        # if pkt_udp:
        # self.logger.info("##########################")
        #     self.logger.info("\tUDP_packet: at %s %s " % (self._hostname_Check(datapath.id), pkt_udp))

    def install_flow_between_switches(self, switch1, switch2, src_ip, dst_ip, src_port, dst_port, in_port, src_mac, dst_mac, msg):
        # input switch1 and switch2 are string: 's1', 's2'
        # self.logger.info("Install Flow from %s to %s" % (switch1, switch2))
        # connection_port = self.return_switch_connection_port(switch1, switch2)
        self.logger.info("HAVE NOT INPLMENETED when shortest_path is longer than 2!!!!!!!!")
        pass

    def install_flow_between_host_and_switch(self, h_mac, traffic_mode, shorestPath, host_position, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg):
        self.logger.info("> IperfController: Install flows between host and switch")
        # 192.168.1.25 0000ae7e24cd5e40 2 02:63:ff:a5:b1:0f
        # first found out which switch does this host attach to
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                host_ip, dpid, inport, mac = line.split()
                if h_mac == mac:
                    self.logger.info("\tFound attached switch at %s for mac %s" % (self._hostname_Check(int(str(dpid), 16)), h_mac))

                    datapath_obj = self.dpid_datapathObj[int(str(dpid), 16)]
                    self.logger.info("\t%s %s %s %s %s %s %s" % (type(inport), type(dst_mac), type(src_mac), type(src_ip), type(dst_ip), type(src_port), type(dst_port)))
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
                    self.logger.info("\tInstall Flow from %s to %s inport=%s output_port=%s" % (h_mac, self._hostname_Check(int(str(dpid), 16)), inport, output_port))
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
                    self.logger.info("\tInstall reserse Flow from %s to %s inport=%s output_port=%s" % (self._hostname_Check(int(str(dpid), 16)), h_mac, output_port, inport))
                    if msg.buffer_id != datapath_obj.ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath_obj, IPERF_PRIORITY, match_to_host, reverse_actions, msg.buffer_id)
                    else:
                        self.add_flow(datapath_obj, IPERF_PRIORITY, match_to_host, reverse_actions)

                    out = datapath_obj.ofproto_parser.OFPPacketOut(datapath=datapath_obj, buffer_id=0xffffffff,
                                                                   in_port=int(inport), actions=actions, data=msg.data)
                    datapath_obj.send_msg(out)

    def return_decimalDPID_baseON_swithName(self, switchName):
        self.logger.info("IperfController: return_decimalDPID_baseON_swithName:")
        # input switchName are strings: S1, S3 ....
        # return decimal dpid based on string names
        with open(OFP_SWITCHES_LIST, 'r') as inp:
            for line in inp:
                if switchName == line.split()[0]:
                    # return a decimal DPID
                    self.logger.info("\tfound dpid %s for switchname %s" % (int(str(line.split()[1]), 16), switchName))
                    return int(str(line.split()[1]), 16)

    def return_switch_connection_port(self, switch1, switch2):
        self.logger.info("IperfController: return_switch_connection_por:")
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
                    self.logger.info("\tfound connection_port %s %s" % (connection_port, type(connection_port)))
                    break
        return connection_port

    def return_dst_dpid_hostname(self, dst_ip, dst_mac):
        # return destination switch's name (ex 'S1') based on given HOST's destination IP and mac address
        self.logger.info("return dstination DPID as Hostname")
        dst_dpid_name = None
        # self.logger.info("\tsleeping for another 10 s .......................")
        with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
            for lines in inp:
                ip_address, dpid, inport, host_mac = lines.split()
                if ip_address == dst_ip and host_mac == dst_mac:
                    dst_dpid_name = self._hostname_Check(int(str(dpid), 16))
                    self.logger.info("\tFound at match at .....................................%s" % dst_dpid_name)
                    break
        if dst_dpid_name == None:
            self.logger.info("\tsleeping for another 10 s ........................")
            time.sleep(10)
            with open(OFP_HOST_SWITCHES_LIST, 'r') as inp:
                for lines in inp:
                    ip_address, dpid, inport, host_mac = lines.split()
                    if ip_address == dst_ip and host_mac == dst_mac:
                        dst_dpid_name = self._hostname_Check(int(str(dpid), 16))
                        self.logger.info("\tFound at match at .......................................%s" % dst_dpid_name)
                        break
        return dst_dpid_name

    def return_shortest_path(self, src_dpid_name, dst_dpid_name):
        # return a list of switch's name ['s1', 's2', 's3']
        self.logger.info("IperfController: return_dst_dpid_hostname:")
        with open(OFP_SINGLE_SHOREST_PATH, 'r') as inp:
            # s4->s5 s4-s3-s2-s1-s5-
            for line in inp:
                if src_dpid_name == line.split()[0].split('->')[0] and dst_dpid_name == line.split()[0].split('->')[1]:
                    self.logger.info("\tFount shortest path %s" % line.split()[1])
                    shortest_path = line.split()[1].rstrip('-').split('-')
                    self.logger.info("\tshortestPath: %s" % shortest_path)
                    return shortest_path
