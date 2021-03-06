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
# config logging
# LOG = logging.getLogger('SimpleArp')
# LOG.setLevel(logging.DEBUG)
# logging.basicConfig()

OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data/ofp_switches_list_prev.db'
OFP_SWITCHES_LIST_SCRIPT = \
    './scripts/remote_ovs_operation/get_switch_ofpbr_datapath_id.sh'


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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ install table-miss flow entry """
        self.logger.debug("my_arp: switch_features_handler:")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # self.logger.info("###################  datapath in decimal %s", datapath.id)
        # self.logger.info("###################  datapath in hex %s", hex(int(datapath.id)))
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

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        self.logger.debug("my_arp:add_flow")
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
        self.mac_to_port.setdefault(dpid, {})

        eth = packets.get_protocols(ethernet)[0]
        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = inPort
        data = msg.data

        self.arp_learning.setdefault(dpid, [])
        self.packetToport.setdefault(dpid, [])

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
            arpArriveTime = time.time()
            srcMac = etherFrame.src
            arp_dstIP = arpPacket.dst_ip
            self.packetToport[datapath.id] = [srcMac, arp_dstIP, inPort, arpArriveTime]
            # print "arp"
            # print "packets: ", packets
            # print "packets.get_protocols(ethernet): ", packets.get_protocols(ethernet)
            # print "ARP: %s" % arpPacket.opcode
            # # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
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
        if arpPacket.opcode == 1:
            self.logger.info("%s: receive ARP request %s => %s (port%d)"
                             % (self._hostname_Check(datapath.id), etherFrame.src, etherFrame.dst, inPort))
            if self.anti_arp_brodcast(datapath, etherFrame, inPort, arp_dstIP):
                # self.logger.info("-----receive ARP request %s => %s (port%d)"
                #                  % (etherFrame.src, etherFrame.dst, inPort))
                # print "-----packetToport: ", self.packetToport
                # print "-----arp_learning: ", self.arp_learning
                self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)
        elif arpPacket.opcode == 2:
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIP, inPort, data)

    def anti_arp_brodcast(self, datapath, etherFrame, inPort, arp_dstIP):
        if self.packetToport[datapath.id]:
            if (etherFrame.src in self.packetToport[datapath.id][0]) and (arp_dstIP == self.packetToport[datapath.id][1]):
                if (inPort != self.packetToport[datapath.id][2]):
                    return False
                else:
                    # print("Another muticast packet form %s at %i port in %s " % (etherFrame.src, inPort, self._hostname_Check(datapath.id)))
                    return True
            else:
                arpArriveTime = time.time()
                srcMac = etherFrame.src
                self.packetToport[datapath.id] = [srcMac, arp_dstIP, inPort, arpArriveTime]
                self.arp_learning[datapath.id] = [srcMac, inPort, arpArriveTime]
                print "packetToport: ", self.packetToport
                print "arp_learning: ", self.arp_learning
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
