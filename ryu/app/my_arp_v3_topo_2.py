#  Simple Arp Handler v3 for topology 2
#  Jack Zhao
#  s.zhao.j@gmail.com

from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
import time
import os
from ryu.lib.packet.lldp import LLDP_MAC_NEAREST_BRIDGE
# config logging
# LOG = logging.getLogger('SimpleArp')
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig()

OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data2/ofp_switches_list_prev.db'
OFP_SWITCHES_LIST = \
    './network-data2/ofp_switches_list.db'
# OFP_SWITCHES_LIST_SCRIPT = \
#     './scripts/remote_ovs_operation/get_switch_ofpbr_datapath_id.sh'


class MySimpleArp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySimpleArp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_learning = {}  # self.arp_learning = {srcMAC:[dst_ip,in_port,time]}
        self.packetToport = {}
        self.hostname_list = {}
        self.dpset = kwargs['dpset']

    def _get_hwaddr(self, dpid, port_no):
        return self.dpset.get_port(dpid, port_no).hw_addr

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.debug("my_arp: _packet_in_handler:")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        # ofproto = datapath.ofproto
        inPort = msg.match['in_port']
        packets = Packet(msg.data)
        dpid = datapath.id

        eth = packets.get_protocols(ethernet)[0]
        src = eth.src
        dst = eth.dst

        self.mac_to_port.setdefault(hex(dpid), {})
        self.arp_learning.setdefault(dpid, [])
        self.packetToport.setdefault(dpid, {})

        if dst == LLDP_MAC_NEAREST_BRIDGE:
            return

        if src in self.mac_to_port[hex(dpid)].keys():
            pass
        else:
            self.mac_to_port[hex(dpid)][src] = inPort
        data = msg.data

        etherFrame = packets.get_protocol(ethernet)

        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.logger.debug("\n:")
            # arpPacket = packets.get_protocol(arp)
            # arpArriveTime = time.time()
            # srcMac = etherFrame.src
            # arp_dstIP = arpPacket.dst_ip
            dst = eth.dst

            self.receive_arp(datapath, packets, etherFrame, inPort, data)
            return 0
        else:
            self.logger.debug("Drop packet")
            return 1

    def receive_arp(self, datapath, packets, etherFrame, inPort, data):
        self.logger.info("MySimpleArp: receive_arp: ")
        arpPacket = packets.get_protocol(arp)
        arp_dstIP = arpPacket.dst_ip
        arp_srcIP = arpPacket.src_ip
        # self.logger.info("packet in %s %s %s %s", self._hostname_Check(datapath.id), etherFrame.src, etherFrame.dst, inPort)
        self.logger.info("\t %s: receive ARP PACKET %s => %s (in_port=%d) From %s to %s"
                         % (self._hostname_Check(datapath.id),
                            etherFrame.src, etherFrame.dst, inPort, arp_srcIP, arp_dstIP))
        if arpPacket.opcode == 1:
            print "\t ARP Requst: Test if it is repeated Broadcasting"
            if self.anti_arp_brodcast(datapath, etherFrame, inPort, arp_dstIP):
                # self.logger.info("%s: receive new ARP request %s => %s (port%d) src_ip=%s dst_ip=%s"
                #                  % (self._hostname_Check(datapath.id), etherFrame.src, etherFrame.dst, inPort, arp_srcIP, arp_dstIP))
                # print "-----packetToport: ", self.packetToport
                # print "-----arp_learning: ", self.arp_learning
                self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)
            else:
                self.logger.info("\t  Not ARP Broadcasting No Action is taken!!!!!~~~~")
                # self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)
        elif arpPacket.opcode == 2:
            self.logger.info("\t ARP_reply: then Forwarding this ARP reply packet !!!!!!!!!!!!!!")
            self.logger.info("\t packet in %s %s %s %s", self._hostname_Check(
                datapath.id), etherFrame.src, etherFrame.dst, inPort)
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)

    def anti_arp_brodcast(self, datapath, etherFrame, inPort, arp_dstIP):
        test = False
        self.logger.info("MySimpleArp: anti_arp_brodcast:")
        if etherFrame.dst == "ff:ff:ff:ff:ff:ff":
            # self.logger.info("self.packetToport:", self.packetToport)
            # self.logger.info(self.packetToport[datapath.id].keys())
            # self.logger.info(self.packetToport[datapath.id])
            if not self.packetToport[datapath.id]:
                # self.logger.info("Another muticast packet form %s at %i port in %s " % (
                #     etherFrame.src, inPort, self._hostname_Check(datapath.id)))
                # self.logger.info("packetToport: ", self.packetToport)
                # self.logger.info("arp_learning: ", self.arp_learning
                self.packetToport[datapath.id][(etherFrame.src, arp_dstIP, inPort)] = time.time()
                self.logger.info("\t1 Added (%s %s %s): %s to self.packetToport and Forwarding ARP Broadcasting" %
                                 (etherFrame.src, arp_dstIP, inPort, time.time()))
                test = True
                return test
            elif ((etherFrame.src, arp_dstIP, inPort) in self.packetToport[datapath.id].keys()):
                self.logger.info("\t2 ARP BLOCKING, No Further transfer")
                # self.logger.info("Another muticast packet form %s at %i port in %s " % (
                #     etherFrame.src, inPort, self._hostname_Check(datapath.id)))
                # self.logger.info("{DPID: { (src_mac, dst_ip, in_port): arpArriveTime, ():time }")
                self.logger.info("\t %s %s" % (self._hostname_Check(datapath.id), self.packetToport[datapath.id].keys()))
                test = False
                return test
            else:
                # same ARP broadcast but from inport number is diffeernt from original port nubmer, block
                for keys in self.packetToport[datapath.id].keys():
                    if ((etherFrame.src, arp_dstIP) == keys[0:2]) and (inPort != keys[2]):
                        self.logger.info("\t 4 same ARP packet coming from differe port. So not Forwarding ARP Broadcasting. Detail: (%s %s %s): %s" %
                                         (etherFrame.src, arp_dstIP, inPort, time.time()))
                        # add this entry, avoid if else checking next time
                        self.packetToport[datapath.id][(etherFrame.src, arp_dstIP, inPort)] = time.time()
                        test = False
                        return test
                if ((etherFrame.src, arp_dstIP, inPort) not in self.packetToport[datapath.id].keys()):
                    self.packetToport[datapath.id][(etherFrame.src, arp_dstIP, inPort)] = time.time()
                    self.logger.info("\t 3  New ARP Broading casting. Added (%s %s %s): %s to self.packetToport and Forwarding ARP Broadcasting" %
                                     (etherFrame.src, arp_dstIP, inPort, time.time()))
                    test = True
                    return test
            return test

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort, data):
        # self.logger.info("flood")
        dst = etherFrame.dst
        dpid = hex(datapath.id)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("\t reply_arp: Reply To Port %s !!!!!!!!!!!!!!!!!" % out_port)
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
            self.logger.info("\t reply_arp: Flooding...")

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,
                                                   in_port=inPort, actions=actions, data=data)
        datapath.send_msg(out)

        # print mac_to_port for verification
        self.logger.info("MySimpleArp: self.mac_to_port")
        for key, value in self.mac_to_port.items():
            print "\t", self._hostname_Check(int(str(key), 16)), value
