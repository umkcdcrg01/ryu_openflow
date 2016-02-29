#  monitoring v3 for topology 2
#  Jack Zhao
#  s.zhao.j@gmail.com
from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
import os.path
import os
# from my_switch_v11_topo_2 import SimpleSwitch13

OFP_SWITCHES_FLOW_STATS = \
    './network-data2/ofp_switches_{0}_flow_stats.db'
OFP_SWITCHES_FLOW_STATS_PREVIOUS = \
    './network-data2/ofp_switches_{0}_flow_stats_prev.db'
OFP_SWITCHES_PORT_STATS = \
    './network-data2/ofp_switches_{0}_port_stats.db'
OFP_SWITCHES_PORT_STATS_PREVIOUS = \
    './network-data2/ofp_switches_{0}_port_stats_prev.db'
OFP_SWITCHES_LIST_PREVIOUS = \
    './network-data2/ofp_switches_list_prev.db'
OFP_SWITCHES_LIST = \
    './network-data2/ofp_switches_list.db'


ICMP_PRIORITY = 3
IPERF_PRIORITY = 4
PRIORITY_LIST = [ICMP_PRIORITY, IPERF_PRIORITY]
STATS_UPDATE_TIMER = 3


class MySimpleMonitor(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(MySimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.hostname_list = {}
        self.sleep = 10
        # length of saved dictionary value
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

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(STATS_UPDATE_TIMER)

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

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        """
        save 3 most recent flow stats/speed for each key: (in_port, dst_mac, output_port)
        each value is a list containing 3 most recently flow stats [(x.x.x.x), (x.x.x.x), (x.x.x.x)]
        """
        if key not in dist:
            dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        """
        return flow speed: bytes/sec
        abs((most recent flow's byte_count) - (previous flow's byte_count))  / period
        """
        if period == 0:
            # if flow stat does not change, return
            return
        return (now - pre) / period

    def _get_time(self, sec, nsec):
        """
        return combined secondes and nsec
        ex: sec = 2, nsec = 12000000
        return 2.12
        """
        return sec + nsec / (10**9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        """
        return the different difference between two adjancenty flows
        """
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.logger.debug("simple_monitor.flow_stats:")
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.debug("Switch Flow States Msg reply Details")
        # for entry in ev.msg.body:
        #     if type(entry) == {}:
        #         for key, value in entry.items():
        #             self.logg.debug(("%s: %s") % (key, value))
        #     self.logger.debug(entry)

        switch_name = self._hostname_Check(ev.msg.datapath.id)

        with open(OFP_SWITCHES_FLOW_STATS.format(switch_name), 'w') as iff:
            # print "writing to %s" % (os.path.abspath(OFP_SWITCHES_FLOW_STATS.format(switch_name)))
            self.logger.debug("\n> Flow Stats:")
            self.logger.debug('datapath         '
                              'hostname   '
                              'in-port       duration_sec   duration_nsec       '
                              '   eth-dst  out-port packets  bytes    speed(bits/sec)')
            self.logger.debug('---------------- '
                              '---------- '
                              '-------- ---------------- -------------- '
                              '------------------- -------- -------- -------- --------------')
            iff.write('datapath         '
                      'hostname   '
                      'in-port       duration_sec   duration_nsec       '
                      '      eth-dst  out-port packets  bytes    speed(bits/sec)   priority\n')
            iff.write('---------------- '
                      '---------- '
                      '-------- ------------------ -------------- '
                      '----------------------- -------- -------- -------- -------------- ----\n')
            for stat in sorted([flow for flow in body if flow.priority == ICMP_PRIORITY or flow.priority == IPERF_PRIORITY],
                               key=lambda flow: (flow.match['in_port'],
                                                 flow.match['eth_dst'])):
                # update flow stats
                # key (dpid, in_port, dst_mac, output_port)
                # key is a tuple
                key = (dpid,
                       stat.match['in_port'], stat.match['eth_dst'],
                       stat.instructions[0].actions[0].port,)
                # value (packet_count, byte_count, duration_sec, duration_msec)
                # value is a tuple, It will be appended to self.flow_stats[key]
                value = (
                    stat.packet_count, stat.byte_count,
                    stat.duration_sec, stat.duration_nsec)
                self._save_stats(self.flow_stats, key, value, self.state_len)

                # Update this flow's speed for every 10s
                pre = 0
                period = self.sleep
                tmp = self.flow_stats[key]
                if len(tmp) > 1:
                    # get previous flow's byte_count
                    pre = tmp[-2][1]
                    """
                    # tmp[-1][2]: current flow's duration seconds
                    # tmp[-1][3]: current flow's duration nsec
                    # tmp[-2][2]: previous flow's duration seconds
                    # tmp[-2][3]: previous flow's duration nseconds
                    # period: get the time difference between two adjanct flows stats
                    # if flow stats does change every 10s, period = 0
                    """
                    period = self._get_period(
                        tmp[-1][2], tmp[-1][3],
                        tmp[-2][2], tmp[-2][3])
                    self.logger.debug("%s %s %s %s" %
                                      (tmp[-1][2], tmp[-1][3], tmp[-2][2], tmp[-2][3]))
                # key[-1][1]: current flow's byte_count
                # speed: eacho flow's current speed (every 10s)
                speed = self._get_speed(
                    self.flow_stats[key][-1][1], pre, period)

                self.logger.debug("pre_byte=%s current_byte=%s  period=%s speed=%s" % (pre, self.flow_stats[key][-1][1], period, speed))
                if speed == None:
                    self.logger.debug("Speed == None ----------------------------------------------------------")
                    speed = 0.0

                self._save_stats(self.flow_speed, key, speed, self.state_len)

                iff.write('%16d %8s %8x %16d %16d %17s %8x %8d %8d %16d %10d' %
                          (ev.msg.datapath.id,
                           # str(ev.msg.datapath.id),
                           self._hostname_Check(ev.msg.datapath.id),
                           stat.match['in_port'], stat.duration_sec,
                           stat.duration_nsec, stat.match['eth_dst'],
                           stat.instructions[0].actions[0].port,
                           stat.packet_count, stat.byte_count, int(speed) * 8, stat.priority))
                iff.write("\n")
                self.logger.debug('%16d %8s %8x %16d %16d %17s %8x %8d %8d %16d',
                                  ev.msg.datapath.id,
                                  # str(ev.msg.datapath.id),
                                  self._hostname_Check(ev.msg.datapath.id),
                                  stat.match['in_port'], stat.duration_sec,
                                  stat.duration_nsec, stat.match['eth_dst'],
                                  stat.instructions[0].actions[0].port,
                                  stat.packet_count, stat.byte_count,
                                  int(speed) * 8)
        # print each key, value for verification
        # self.logger.debug("flow_sttas:")
        # for key, val in self.flow_stats.items():
        #     self.logger.debug("  key=%s    value=%s" % (key, val))

        # self.logger.debug("flow_speed:")
        # for key, val in self.flow_speed.items():
        #     self.logger.debug("  key=%s    value=%s" % (key, val))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        self.logger.debug("simple_monitor.port_stats:")
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.debug("Switch Port States Msg reply Details")
        # for entry in ev.msg.body:
        #     if type(entry) == {}:
        #         for key, value in entry.items():
        #             self.logg.debug(("%s: %s") % (key, value))
        #     self.logger.debug(entry)

        switch_name = self._hostname_Check(ev.msg.datapath.id)

        with open(OFP_SWITCHES_PORT_STATS.format(switch_name), 'w') as iff:
            # print "writing to %s" % (os.path.abspath(OFP_SWITCHES_PORT_STATS.format(switch_name)))
            self.logger.debug("\n> Port Stats:")
            self.logger.debug('datapath         '
                              'hostname       '
                              'port     duration_sec  duration_nsec'
                              ' rx-pkts    rx-bytes rx-error '
                              ' tx-pkts  tx-bytes tx-error    speed(bits/sec)')
            self.logger.debug('---------------- '
                              '-------------- '
                              '----- ------------- ---------------- '
                              '-------- -------- -------- '
                              '-------- -------- -------- --------------')
            iff.write('datapath         '
                      'hostname       '
                      'port     duration_sec  duration_nsec'
                      ' rx-pkts    rx-bytes rx-error '
                      ' tx-pkts  tx-bytes tx-error    speed(bits/sec)\n')
            iff.write('---------------- '
                      '-------------- '
                      '----- ------------- ---------------- '
                      '-------- -------- -------- '
                      '-------- -------- -------- --------------\n')
            for stat in sorted(body, key=attrgetter('port_no')):
                # key: (datapath.di,  switch_port_number)
                key = (dpid, stat.port_no)
                # value: (stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.duration_sec, stat.duration_nsec)
                # value is a tuple, It will be appended to self.port_stats[key]
                value = (
                    stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                    stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, self.state_len)

                # Get port speed.
                pre = 0
                period = self.sleep  # update every self.sleep timer
                # tmp: the port stats entry for this key (datapath.di,  switch_port_number)
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    # pre: the previous received_bytes (strx_bytes)
                    pre = tmp[-2][1]
                    # tmp[-1][3]: current port's duration seconds
                    # tmp[-1][4]: current port's duration nsec
                    # tmp[-2][3]: previous port's duration seconds
                    # tmp[-2][4]: previous port's duration nseconds
                    # period: get the time difference between two adjanct ports stats
                    # if port stats does change every 10s, period = 0
                    period = self._get_period(
                        tmp[-1][3], tmp[-1][4],
                        tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][1], pre, period)
                if speed == None:
                    speed = 0.0
                self._save_stats(self.port_speed, key, speed, self.state_len)
                # print '\n Speed: %s bytes\/s\n' % (self.port_speed)

                self.logger.debug('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d %16d',
                                  ev.msg.datapath.id,
                                  self._hostname_Check(ev.msg.datapath.id),
                                  stat.port_no, stat.duration_sec, stat.duration_nsec,
                                  stat.rx_packets, stat.rx_bytes,
                                  stat.rx_errors, stat.tx_packets,
                                  stat.tx_bytes, stat.tx_errors, int(speed) * 8)
                iff.write('%016x %8s %8x %16d %16d %8d %8d %8d %8d %8d %8d %16d' %
                          (ev.msg.datapath.id,
                           self._hostname_Check(ev.msg.datapath.id),
                           stat.port_no, stat.duration_sec, stat.duration_nsec,
                           stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                           stat.tx_packets, stat.tx_bytes, stat.tx_errors, int(speed) * 8))
                iff.write("\n")
        # print each key, value for verification
        # self.logger.debug("port_sttas:")
        # for key, val in self.port_stats.items():
        #     self.logger.debug("  key=%s    value=%s" % (key, val))

        # self.logger.debug("port_speed:")
        # for key, val in self.port_speed.items():
        #     self.logger.debug("  key=%s    value=%s" % (key, val))
