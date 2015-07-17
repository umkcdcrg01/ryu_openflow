#  Simple Arp Handler v2
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
from my_switch_13_v10_topo_2 import SimpleSwitch13
# config logging
# LOG = logging.getLogger('SimpleArp')
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig()

OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data2/ofp_switches_list_prev.db'
# OFP_SWITCHES_LIST_SCRIPT = \
#     './scripts/remote_ovs_operation/get_switch_ofpbr_datapath_id.sh'


class MySimpleArp(SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySimpleArp, self).__init__(*args, **kwargs)
        # self.mac_to_port = {}
        self.arp_learning = {}  # self.arp_learning = {srcMAC:[dst_ip,in_port,time]}
        self.packetToport = {}
        self.hostname_list = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.info("my_arp: _packet_in_handler:")
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
        self.mac_to_port.setdefault(dpid, {})

        eth = packets.get_protocols(ethernet)[0]
        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = inPort
        data = msg.data

        self.arp_learning.setdefault(dpid, [])
        self.packetToport.setdefault(dpid, {})

        etherFrame = packets.get_protocol(ethernet)
        # if dst == LLDP_MAC_NEAREST_BRIDGE:
        #     return
        # print "packets: ", packets
        # print "packets.get_protocols(ethernet): ", packets.get_protocols(ethernet)

        # print "etherFrame######", etherFrame
        # etherFrame = packets.get_protocol(ethernet)
        etherFrame = packets.get_protocol(ethernet)
        # print etherFrame
        # print ether
        # print hex(etherFrame.ethertype)
        # print hex(ether.ETH_TYPE_ARP)
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            arpPacket = packets.get_protocol(arp)
            self.logger.info("packet in %s %s %s %s %s", self._hostname_Check(datapath.id), arpPacket.opcode, src, dst, inPort)
            arpArriveTime = time.time()
            srcMac = etherFrame.src
            arp_dstIP = arpPacket.dst_ip
            dst = eth.dst
            if dst == "ff:ff:ff:ff:ff:ff":
                self.packetToport[datapath.id][(srcMac, arp_dstIP, inPort)] = arpArriveTime
                self.logger.info("packet in %s %s %s %s", datapath.id, src, dst, inPort)
            # print "arp"
            # print "packets: ", packets
            # print "packets.get_protocols(ethernet): ", packets.get_protocols(ethernet)
            # print "ARP: %s" % arpPacket.opcode
            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            # if arpPacket.opcode == 1:
            #     print "ARP Requst"
            #     self.logger.info("packet in %s %s %s %s", datapath.id, srcMac, dst, inPort)
            # elif arpPacket.opcode == 2:
            #     print "ARP Reply"
            #     self.logger.info("packet in %s %s %s %s", datapath.id, srcMac, dst, inPort)

            self.receive_arp(datapath, packets, etherFrame, inPort, data)
            return 0
        else:
            self.logger.debug("Drop packet")
            return 1

    def receive_arp(self, datapath, packets, etherFrame, inPort, data):
        arpPacket = packets.get_protocol(arp)
        arp_dstIP = arpPacket.dst_ip
        arp_srcIP = arpPacket.src_ip
        if arpPacket.opcode == 1:
            # self.logger.info("%s: receive ARP request %s => %s (port%d)"
            #                  % (self._hostname_Check(datapath.id), etherFrame.src, etherFrame.dst, inPort))
            if self.anti_arp_brodcast(datapath, etherFrame, inPort, arp_dstIP):
                self.logger.info("%s: receive ARP request %s => %s (port%d) src_ip=%s dst_ip=%s"
                                 % (self._hostname_Check(datapath.id), etherFrame.src, etherFrame.dst, inPort, arp_srcIP, arp_dstIP))
                # print "-----packetToport: ", self.packetToport
                # print "-----arp_learning: ", self.arp_learning
                self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)
        elif arpPacket.opcode == 2:
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)

    def anti_arp_brodcast(self, datapath, etherFrame, inPort, arp_dstIP):
        if etherFrame.dst == "ff:ff:ff:ff:ff:ff":
            if self.packetToport[datapath.id]:
                if ((etherFrame.src, arp_dstIP, inPort) in self.packetToport[datapath.id].keys()):
                    print "1"
                    return False
                else:
                    print("Another muticast packet form %s at %i port in %s " % (
                       etherFrame.src, inPort, self._hostname_Check(datapath.id)))
                    print "packetToport: ", self.packetToport
                    print "arp_learning: ", self.arp_learning
                    self.packetToport[datapath.id][(etherFrame.src, arp_dstIP, inPort)] = time.time()
                    print "2"
                    return True
            # else:
            #     # add to dictionary self.packetToport
            #     arpArriveTime = time.time()
            #     srcMac = etherFrame.src
            #     self.packetToport[datapath.id] = [srcMac, arp_dstIP, inPort, arpArriveTime]
            #     self.arp_learning[datapath.id] = [srcMac, inPort, arpArriveTime]
            #     print "packetToport: ", self.packetToport
            #     print "arp_learning: ", self.arp_learning
            #     print "3"
            #     return True
        else:
            print "4"
            return True

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort, data):
        """flood the arp """
        # print "flood"
        dst = etherFrame.dst
        dpid = datapath.id
        if dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = datapath.ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,
                                                   in_port=inPort, actions=actions, data=data)
        datapath.send_msg(out)
