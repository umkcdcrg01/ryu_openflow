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

# basic library
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.controller import dpset
# for Topology GUI
from webob.static import DirectoryApp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import os
# for Topology discover
import json
from webob import Response
from ryu.topology import event, switches
from ryu.lib import dpid as dpid_lib
from ryu.topology.api import get_switch, get_link, get_all_link
from ryu.lib.packet.lldp import LLDP_MAC_NEAREST_BRIDGE
# from ryu.topology import api

# for traffic monitor
from operator import attrgetter
from ryu.lib import hub


# for testing LLDP protocols
from ryu.ofproto.ether import ETH_TYPE_LLDP 


PATH = os.path.dirname(__file__)


class MyLeanringSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    """
    A dictionary to specify contexts which this Ryu application wants to use.
    Its key is a name of context and its value is an ordinary class
    which implements the context.  The class is instantiated by app_manager
    and the instance is shared among RyuApp subclasses which has _CONTEXTS
    member with the same key.  A RyuApp subclass can obtain a reference to
    the instance via its __init__'s kwargs as the following.

    Example::

        _CONTEXTS = {
            'network': network.Network
        }

        def __init__(self, *args, *kwargs):
            self.network = kwargs['network']
    """
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication,
    }

    def __init__(self, *args, **kwargs):
        super(MyLeanringSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
        self.my_topology_api_app = self
        # init wsgi
        wsgi = kwargs['wsgi']
        wsgi.register(GUIServerController)
        wsgi.register(TopologyController, {'topology_api_app': self})
        # added for traffic monoitor
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    def _get_hwaddr(self, dpid, port_no):
        return self.dpset.get_port(dpid, port_no).hw_addr

    def hostname_Check(self, datapath):
        hostnames = {int("0000923d8a5ddd4c", 16): "OVS1",
                     int("0000aa6b9b1a6248", 16): 'OVS2',
                     int("0000ba56efa86f44", 16): 'OVS3',
                     int("00000eabe5b6fb47", 16): 'OVS4'}

        # NEED add some datapath check later
        if datapath not in hostnames.keys():
            return datapath
        else:
            return hostnames[datapath]

    @set_ev_cls(event.EventLinkAdd)
    def link_add(self, ev):
        print ev.link.src, ev.link.dst
        print self._get_hwaddr(ev.link.src.dpid, ev.link.src.port_no)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

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

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        pass
        """
        self.logger.info(
            "###############Flow Stats######################################")
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%10s %8x %17s %8x %8d %8d',
                             self.hostname_Check(ev.msg.datapath.id),
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
"""

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        pass
        """
        self.logger.info("******************Ports Stats*******************")
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%10s %8x %8d %8d %8d %8d %8d %8d',
                             self.hostname_Check(ev.msg.datapath.id),
                             stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)"""

    # handle feature reply from switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("###################  datapath in hex %s",
                         hex(int(datapath.id)))

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
        # self.get_topology_data(ev)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.info("my_ryu_application: _packet_in_handler")
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
        eth_proto = eth.protocol_name

        if dst == LLDP_MAC_NEAREST_BRIDGE:
            print "LLDP Packet:"
            print "     ETH_TYPE_LLDP:", hex(ETH_TYPE_LLDP)
            print "     Src_mac:", src
            return
        # print "eth_protoname:", eth_proto
        # print "eth_protoname_1:", eth_proto_1

        dpid = hex(datapath.id)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in dpid=%s src_mac=%s dst_mac=%s \
                        in_port=%s,",  dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                self.logger.info("Install Flood FLow to Switch %s", dpid)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.my_topology_api_app, None)
        all_switches = [switch.dp.id for switch in switch_list]
        # links_list = get_link(self.topology_api_app, None)
        links_list = get_link(self.my_topology_api_app)
        links = [(link.src.dpid, link.dst.dpid,
                  {'port': link.src.port_no}) for link in links_list]
        print ">> switches: ", all_switches
        print ">> links: ", links


class TopologyController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.topology_api_app = data['topology_api_app']
        # path = "%s/html/" % PATH
        # self.static_app = DirectoryApp(path)

    @route('topology', '/v1.0/topology/switches',
           methods=['GET'])
    def list_switches(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('topology', '/v1.0/topology/switches/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_switch(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('topology', '/v1.0/topology/links',
           methods=['GET'])
    # def list_links(self, req, **kwargs):
    def get_link(self, req, **kwargs):
        return self._links(req, **kwargs)

    @route('topology', '/v1.0/topology/links/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_links(self, req, **kwargs):
        return self._links(req, **kwargs)

    def _switches(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        switches = get_switch(self.topology_api_app, dpid)
        body = json.dumps([switch.to_dict() for switch in switches])
        return Response(content_type='application/json', body=body)

    def _links(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        links = get_link(self.topology_api_app, dpid)
        body = json.dumps([link.to_dict() for link in links])
        return Response(content_type='application/json', body=body)


class GUIServerController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(GUIServerController, self).__init__(req, link, data, **config)
        path = "%s/html/" % PATH
        self.static_app = DirectoryApp(path)

    @route('topology', '/{filename:.*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)

# This will turn on Web restAPI
app_manager.require_app('ryu.app.rest_topology')
# app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
print "Project Path", PATH
