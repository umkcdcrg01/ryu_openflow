from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


OFP_SWITCHES_FLOW_STATS = \
    './network-data/ofp_switches_{0}_flow_stats.db'
OFP_SWITCHES_FLOW_STATS_PREVIOUS = \
    './network-data/ofp_switches_{0}_flow_stats_prev.db'
OFP_SWITCHES_PORT_STATS = \
    './network-data/ofp_switches_{0}_port_stats.db'
OFP_SWITCHES_PORT_STATS_PREVIOUS = \
    './network-data/ofp_switches_{0}_port_stats_prev.db'


class SimpleMonitor(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

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
            hub.sleep(10)

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
        print "my_traffic_monitor: flow status reply:"
        body = ev.msg.body
        # print "flow body:", body[1]
        # switch_name = self._hostname_Check(ev.msg.datapath.id)
        switch_name = ev.msg.datapath.id
        with open(OFP_SWITCHES_FLOW_STATS.format(switch_name), 'w') as iff:
            self.logger.info("\n> Flow Stats:")
            self.logger.info('datapath         '
                             'hostname         '
                             'in-port     duration_sec   duration_nsec       '
                             '   eth-dst  out-port packets  bytes')
            iff.write('datapath         '
                      'hostname         '
                      'in-port     duration_sec   duration_nsec       '
                      '   eth-dst          out-port packets  bytes\n')
            self.logger.info('---------------- '
                             '---------------- '
                             '-------- ---------------- -------------- '
                             '---------------- -------- -------- --------')
            iff.write('---------------- '
                      '---------------- '
                      '-------- ---------------- -------------- '
                      '---------------- -------- -------- --------\n')
            for stat in sorted([flow for flow in body if flow.priority == 1],
                               key=lambda flow: (flow.match['in_port'],
                                                 flow.match['eth_dst'])):
                iff.write('%16d %16s %8x %16d %16d %17s %8x %8d %8d' %
                          (ev.msg.datapath.id,
                           self._hostname_Check(ev.msg.datapath.id),
                           stat.match['in_port'], stat.duration_sec,
                           stat.duration_nsec, stat.match['eth_dst'],
                           stat.instructions[0].actions[0].port,
                           stat.packet_count, stat.byte_count))
                iff.write("\n")
                self.logger.info('%16d %16s %8x %16d %16d %17s %8x %8d %8d',
                                 ev.msg.datapath.id,
                                 self._hostname_Check(ev.msg.datapath.id),
                                 stat.match['in_port'], stat.duration_sec,
                                 stat.duration_nsec, stat.match['eth_dst'],
                                 stat.instructions[0].actions[0].port,
                                 stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        print "my_traffic_monitor: port status reply:"
        body = ev.msg.body
        self.get_topology_data(ev)
        # print "port body:", body[1]
        # switch_name = self._hostname_Check(ev.msg.datapath.id)
        switch_name = ev.msg.datapath.id
        with open(OFP_SWITCHES_PORT_STATS.format(switch_name), 'w') as iff:
            self.logger.info("\n> Port Stats:")
            self.logger.info('datapath         '
                             'hostname       '
                             'port     duration_sec  duration_nsec '
                             'rx-pkts  rx-bytes rx-error '
                             'tx-pkts  tx-bytes tx-error')
            iff.write('datapath         '
                      'hostname       '
                      'port     duration_sec  duration_nsec '
                      'rx-pkts  rx-bytes rx-error '
                      'tx-pkts  tx-bytes tx-error\n')
            self.logger.info('---------------- '
                             '-------------- '
                             '-------- ---------------- -------------- '
                             '-------- -------- -------- '
                             '-------- -------- --------')
            iff.write('---------------- '
                      '-------------- '
                      '-------- ------------ -------------- '
                      '-------- -------- -------- '
                      '-------- -------- --------\n')
            for stat in sorted(body, key=attrgetter('port_no')):
                self.logger.info('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d',
                                 ev.msg.datapath.id,
                                 self._hostname_Check(ev.msg.datapath.id),
                                 stat.port_no, stat.duration_sec, stat.duration_nsec,
                                 stat.rx_packets, stat.rx_bytes,
                                 stat.rx_errors, stat.tx_packets,
                                 stat.tx_bytes, stat.tx_errors)
                iff.write('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d' %
                          (ev.msg.datapath.id,
                           self._hostname_Check(ev.msg.datapath.id),
                           stat.port_no, stat.duration_sec, stat.duration_nsec,
                           stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                           stat.tx_packets, stat.tx_bytes, stat.tx_errors))
                iff.write("\n")
