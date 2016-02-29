from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
import os.path

OFP_SWITCHES_FLOW_STATS = \
    './network-data/ofp_switches_{0}_flow_stats.db'
OFP_SWITCHES_FLOW_STATS_PREVIOUS = \
    './network-data/ofp_switches_{0}_flow_stats_prev.db'
OFP_SWITCHES_PORT_STATS = \
    './network-data/ofp_switches_{0}_port_stats.db'
OFP_SWITCHES_PORT_STATS_PREVIOUS = \
    './network-data/ofp_switches_{0}_port_stats_prev.db'


class MySimpleMonitor(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(MySimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.sleep = 10
        self.state_len = 3

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

    # get the ports' features.
    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def port_features_handler(self, ev):
        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        if key not in dist:
            dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        return (now - pre) / period

    def _get_time(self, sec, nsec):
        return sec + nsec / (10**9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        print "simple_monitor.flow_stats:"
        body = ev.msg.body
        switch_name = ev.msg.datapath.id
        with open(OFP_SWITCHES_FLOW_STATS.format(switch_name), 'w') as iff:
            print "writing to %s" % (os.path.abspath(OFP_SWITCHES_FLOW_STATS.format(switch_name)))
            self.logger.debug("\n> Flow Stats:")
            self.logger.debug('datapath         '
                              'hostname         '
                              'in-port     duration_sec   duration_nsec       '
                              '   eth-dst  out-port packets  bytes')
            iff.write('datapath         '
                      'hostname         '
                      'in-port     duration_sec   duration_nsec       '
                      '   eth-dst          out-port packets  bytes\n')
            self.logger.debug('---------------- '
                              '---------------- '
                              '-------- ---------------- -------------- '
                              '---------------- -------- -------- --------')
            iff.write('---------------- '
                      '---------------- '
                      '-------- ---------------- -------------- '
                      '---------------- -------- -------- --------\n')
            for stat in sorted([flow for flow in body if flow.priority == 3],
                               key=lambda flow: (flow.match['in_port'],
                                                 flow.match['eth_dst'])):

                key = (
                    stat.match['in_port'], stat.match['eth_dst'],
                    stat.instructions[0].actions[0].port,)
                value = (
                    stat.packet_count, stat.byte_count,
                    stat.duration_sec, stat.duration_nsec)
                self._save_stats(self.flow_stats, key, value, self.state_len)

                # Get flow's speed.
                pre = 0
                period = self.sleep
                tmp = self.flow_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][1]
                    period = self._get_period(
                        tmp[-1][2], tmp[-1][3],
                        tmp[-2][2], tmp[-2][3])

                speed = self._get_speed(
                    self.flow_stats[key][-1][1], pre, period)

                self._save_stats(self.flow_speed, key, speed, self.state_len)

                iff.write('%16d %16s %8x %16d %16d %17s %8x %8d %8d' %
                          (ev.msg.datapath.id,
                           str(ev.msg.datapath.id),
                           stat.match['in_port'], stat.duration_sec,
                           stat.duration_nsec, stat.match['eth_dst'],
                           stat.instructions[0].actions[0].port,
                           stat.packet_count, stat.byte_count))
                iff.write("\n")
                self.logger.debug('%16d %16s %8x %16d %16d %17s %8x %8d %8d',
                                  ev.msg.datapath.id,
                                  str(ev.msg.datapath.id),
                                  stat.match['in_port'], stat.duration_sec,
                                  stat.duration_nsec, stat.match['eth_dst'],
                                  stat.instructions[0].actions[0].port,
                                  stat.packet_count, stat.byte_count)
            print "\n%16d (%s  %s   %s )  [(%s  %s  %s  %s)]" % (ev.msg.datapath.id,
                                                                 'in_port', 'eth_dst', 'actions.port', 'packet_count', 'byte_count',
                                                                 'duration_sec', 'duration_nsec')
            # for key, val in self.flow_stats.items():
            #     print key, "        ", val
            # print "Flow speed"
            # for key, val in self.flow_speed.items():
            #     print key, val

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        print "simple_monitor.port_stats:"
        body = ev.msg.body
        switch_name = ev.msg.datapath.id
        with open(OFP_SWITCHES_PORT_STATS.format(switch_name), 'w') as iff:
            print "writing to %s" % (os.path.abspath(OFP_SWITCHES_PORT_STATS.format(switch_name)))
            self.logger.debug("\n> Port Stats:")
            self.logger.debug('datapath         '
                              'hostname       '
                              'port     duration_sec  duration_nsec '
                              'rx-pkts  rx-bytes rx-error '
                              'tx-pkts  tx-bytes tx-error')
            iff.write('datapath         '
                      'hostname       '
                      'port     duration_sec  duration_nsec '
                      'rx-pkts  rx-bytes rx-error '
                      'tx-pkts  tx-bytes tx-error\n')
            self.logger.debug('---------------- '
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
                key = (ev.msg.datapath.id, stat.port_no)
                value = (
                    stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                    stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, self.state_len)

                # Get port speed.
                pre = 0
                period = self.sleep
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][1]
                    period = self._get_period(
                        tmp[-1][3], tmp[-1][4],
                        tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][1], pre, period)

                self._save_stats(self.port_speed, key, speed, self.state_len)
                # print '\n Speed: %s bytes\/s\n' % (self.port_speed)

                self.logger.debug('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d',
                                  ev.msg.datapath.id,
                                  ev.msg.datapath.id,
                                  stat.port_no, stat.duration_sec, stat.duration_nsec,
                                  stat.rx_packets, stat.rx_bytes,
                                  stat.rx_errors, stat.tx_packets,
                                  stat.tx_bytes, stat.tx_errors)
                iff.write('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d' %
                          (ev.msg.datapath.id,
                           ev.msg.datapath.id,
                           stat.port_no, stat.duration_sec, stat.duration_nsec,
                           stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                           stat.tx_packets, stat.tx_bytes, stat.tx_errors))
                iff.write("\n")

            print "\n(%16d  %s) [(%s  %s  %s  %s  %s)]" % (ev.msg.datapath.id,
                                                           'stat_port_no', 'rx_packets',
                                                           'rx_bytes', 'rx_errors', 'duration_sec', 'duration_nsec')
            # for key, val in self.port_stats.items():
            #     print key, "        ", val
            # print "port speed"
            # for key, val in self.port_speed.items():
            #     print key, val
