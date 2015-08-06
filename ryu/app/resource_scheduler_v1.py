# resource_scheduler_v1.py
#  Shuai Jack Zhao
# hdfs file system
# in_port=int(inport), eth_dst=dst_mac, eth_src=src_mac, eth_type=0x0800, ipv4_src=src_ip,
#                                                                               ipv4_dst=dst_ip, ip_proto=6, tcp_dst=dst_port, tcp_src=src_port
#
# tcp_src=54310
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
from utilityLib_v1 import Utilites

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
OFP_SSH_LOG = \
    './network-data2/ofp_ssh_log.db'

ICMP_PRIORITY = 3
IPERF_PRIORITY = 4
SSH_PRIORITY = 5
HDFS_PRIORITY = 6
RESOURCE_TRACKER_PRIORITY = 7


RESOURCE_TRACKER_IDLE_TIMER = 100
RESOURCE_TRACKER_HARD_TIMER = 0


IDLE_TIMER = 120
HARD_TIMER = 0
SSH_KEY_LEARNING_TIMER = 1
SSH_TRACK_LIMIT = 10

SSH_IDLE_TIMER = 10
SSH_HARD_TIMER = 0

HDFS_IDLE_TIMER = 0
HDFS_HARD_TIMER = 0


class ResourceScheduler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(ResourceScheduler, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.datapaths = {}
        # create thread for traffic monitoring
        # self.monitor_thread = hub.spawn(self._monitor)
        self.hostname_list = {}
        self.dpid_datapathObj = {}
        self.ssh_learning = {}
        self.ssh_track_list = {}
        self.util = Utilites()
        # self._update_switch_dpid_list()

    ###################################################################
    # ofp_event.EventOFPSwitchFeatures
    ####################################################################
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # self._update_switch_dpid_list()
        self.logger.debug("switch_features_handler: ")
        datapath = ev.msg.datapath
        dpid = datapath.id
        # save datapath object into dpid_datapath
        # here dpid is a integer, not Hex number
        self.dpid_datapathObj[dpid] = ev.msg.datapath

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
            self.logger.debug("ResourceScheduler: Packet-In:")
            # self.logger.info("\tether_packet: at %s %s " % (self.util.hostname_Check(datapath.id), pkt_ethernet))

        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            return

        pkt_tcp = pkt.get_protocol(tcp.tcp)
        # pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_tcp:
            # self.logger.info("\tTCP_packet: at %s %s " % (self.util.hostname_Check(datapath.id), pkt_tcp))
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            in_port = msg.match['in_port']
            src_mac = eth.src
            # parser = datapath.ofproto_parser
            if pkt_tcp:
                src_port = pkt_tcp.src_port
                dst_port = pkt_tcp.dst_port
            if str(dst_port) == '8030' or str(dst_port) == '54311':
                key = (src_ip, dst_ip, src_mac, dst_mac, dst_port)
                self.logger.debug("ResourceScheduler: Packet-In:")
                self.logger.info("\t############################# Resource_Scheduler Traffic #####################################")
                self.logger.info("\tAt %s from %s to %s from src_port %s to dst_port %s from  port %s src_mac %s dst_mac %s" %
                                 (self.util.hostname_Check(datapath.id), src_ip, dst_ip, src_port, dst_port, in_port, src_mac, dst_mac))
                if key not in self.ssh_learning.keys():
                    # self.logger.info("\t############################# HDFS Traffic #####################################")
                    # self.logger.info("\tAt %s from %s to %s from src_port %s to dst_port %s from  port %s src_mac %s dst_mac %s" %
                    #                 (self.util.hostname_Check(datapath.id), src_ip, dst_ip, src_port, dst_port, in_port, src_mac, dst_mac))
                    # this valuw will be used at a timer, This entry will be cleard after 1 second
                    value = time.time()
                    self.ssh_learning[key] = value
                elif key in self.ssh_learning.keys():
                    if time.time() - self.ssh_learning[key] >= SSH_KEY_LEARNING_TIMER:
                        self.logger.info("\t(src_ip, dst_ip, src_mac, dst_mac, dst_port, in_port) TIMEOUT from self.hdfs_learning dict!!!")
                        del self.ssh_learning[key]
                        self.ssh_learning[key] = time.time()
                    else:
                        return
                else:
                    return
                src_dpid_name = self.util.hostname_Check(datapath.id)
                # self.logger.info("\tInstall SSH flow between IP address %s and %s \n\tsleeping for 5 s ........................" % (src_ip, dst_ip))
                # time.sleep(5)
                # find dstination datapath id from host_tracker file
                dst_dpid_name = self.util.return_dst_dpid_hostname(dst_ip, dst_mac)
                if dst_dpid_name == None:
                    self.logger.info("\tcould not find destination switch..............")
                    return

                self.logger.info("\tInstall Resource_tracker flow between %s and %s" % (dst_dpid_name, src_dpid_name))

                # Now only consider two end hosts
                # hosts = [src_mac, dst_mac]
                hosts = [dst_mac, src_mac]
                # find shortest path between two switches, a list of hostnames ['s1','s2','s3']
                shortest_path = self.util.return_shortest_path(dst_dpid_name, src_dpid_name)
                # install flows between hosts and switch
                # self.install_flows_for_hosts_and_attached_switches(hosts, shortest_path, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg)

                if len(shortest_path) == 1:
                    self.util.install_flows_for_same_switch_v2(
                        shortest_path, 'TCP', src_ip, dst_ip, src_mac, dst_mac,
                        src_port, dst_port, self.dpid_datapathObj, RESOURCE_TRACKER_IDLE_TIMER, RESOURCE_TRACKER_HARD_TIMER, msg)
                else:
                    # install flows between hosts and switch
                    self.install_flows_for_hosts_and_attached_switches(hosts, shortest_path, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg)

                # install flow for the rest of switches if the length of shortest path is greater than 2
                if len(shortest_path) > 2:
                    # self.util.install_flows_for_rest_of_switches(
                    #     shortest_path, 'TCP', SSH_PRIORITY, src_ip, dst_ip, src_mac, dst_mac, self.dpid_datapathObj, SSH_IDLE_TIMER, SSH_HARD_TIMER)
                    self.util.install_flows_for_rest_of_switches(
                        shortest_path, 'TCP', HDFS_PRIORITY, dst_ip, src_ip, dst_mac, src_mac, self.dpid_datapathObj, SSH_IDLE_TIMER, SSH_HARD_TIMER)

    def install_flows_for_hosts_and_attached_switches(self, hosts, shortest_path, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, msg):
        count = 0
        for h_mac in hosts:
            if count < len(hosts) and count == 0:
                self.util.install_flow_between_host_and_switch_for_TCP_UDP(
                    h_mac, 'TCP', RESOURCE_TRACKER_PRIORITY, shortest_path[count:count + 2],
                    count, dst_ip, src_ip, dst_port, src_port, dst_mac, src_mac, self.dpid_datapathObj, SSH_IDLE_TIMER, SSH_HARD_TIMER,  msg)
                count += 1
            elif count < len(hosts) and count == 1:
                self.util.install_flow_between_host_and_switch_for_TCP_UDP(
                    h_mac, 'TCP', RESOURCE_TRACKER_PRIORITY, list([shortest_path[len(shortest_path) - 1], shortest_path[len(shortest_path) - 2]]),
                    count, dst_ip, src_ip, dst_port, src_port, dst_mac, src_mac, self.dpid_datapathObj, SSH_IDLE_TIMER, SSH_HARD_TIMER, msg)
                count += 1
