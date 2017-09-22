# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from oslo_config import cfg
from oslo_log import log
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller import ofp_handler
from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_3
from ryu import utils

from dragonflow.controller.common import constants
from dragonflow.controller import dispatcher
from ryu.topology import event, switches
from ryu.topology.api import get_link, get_switch
from dragonflow.db.models import l2
from dragonflow.db.models import core

LOG = log.getLogger(__name__)


class RyuDFAdapter(ofp_handler.OFPHandler):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OF_AUTO_PORT_DESC_STATS_REQ_VER = 0x04

    call_on_datapath_set = None
    ctrl = None
    chassis = core.Chassis(
        id='whoami',
        ip='172.24.4.50',
        tunnel_types=('vxlan',),
    )

    local_binding = l2.PortBinding(
        type=l2.BINDING_CHASSIS,
        chassis=chassis,
    )
    fake_lswitch_default_subnets = [l2.Subnet(dhcp_ip="192.168.123.0",
                                                   name="private-subnet",
                                                   enable_dhcp=True,
                                                   topic="fake_tenant1",
                                                   gateway_ip="192.168.123.1",
                                                   cidr="192.168.123.0/24",
                                                   id="fake_subnet1")]

    def __init__(self, vswitch_api, nb_api,
                 neutron_server_notifier=None):
        super(RyuDFAdapter, self).__init__()
        self.dispatcher = dispatcher.AppDispatcher(cfg.CONF.df.apps_list)
        # TODO: Remove vswitch api for standalone version
        self.vswitch_api = vswitch_api
        self.nb_api = nb_api
        self.neutron_server_notifier = neutron_server_notifier
        self._datapath = None
        self.table_handlers = {}
        self.first_connect = True


    @property
    def datapath(self):
        return self._datapath

    def start(self):
        super(RyuDFAdapter, self).start()

        self.load(self,
                  vswitch_api=self.vswitch_api,
                  nb_api=self.nb_api,
                  neutron_server_notifier=self.neutron_server_notifier)
        #self.wait_until_ready()

    def load(self, *args, **kwargs):
        self.dispatcher.load(*args, **kwargs)

    def is_ready(self):
        return self.datapath is not None

    def wait_until_ready(self):
        while not self.is_ready():
            LOG.debug("Not ready. Going to sleep 3")
            time.sleep(3)

    def register_table_handler(self, table_id, handler):
        if table_id in self.table_handlers:
            raise RuntimeError(
                _(
                    'Cannot register handler {new_handler} for table {table},'
                    'occupied by {existing_handler}'
                ).format(
                    table=table_id,
                    new_handler=handler,
                    existing_handler=self.table_handlers[table_id],
                ),
            )
        self.table_handlers[table_id] = handler

    def unregister_table_handler(self, table_id, handler):
        self.table_handlers.pop(table_id, None)

    def notify_ovs_sync_finished(self):
        self.dispatcher.dispatch('ovs_sync_finished')

    def notify_ovs_sync_started(self):
        self.dispatcher.dispatch('ovs_sync_started')


    @handler.set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath

    @handler.set_ev_handler(ofp_event.EventOFPSwitchFeatures,
                            handler.CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # TODO(oanson) is there a better way to get the datapath?
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self._datapath = datapath
        super(RyuDFAdapter, self).switch_features_handler(ev)
        version = self.datapath.ofproto.OFP_VERSION
        if version < RyuDFAdapter.OF_AUTO_PORT_DESC_STATS_REQ_VER:
            # Otherwise, this is done automatically by OFPHandler
            self._send_port_desc_stats_request(self.datapath)

        self.get_sw_async_msg_config()

        self.dispatcher.dispatch('switch_features_handler', ev)

        if not self.first_connect:
            # For reconnecting to the ryu controller, df needs a full sync
            # in case any resource added during the disconnection.
            self.nb_api.db_change_callback(None, None,
                                           constants.CONTROLLER_REINITIALIZE,
                                           None)
        self.first_connect = False
        #self.vswitch_api.initialize(self.nb_api)
        if RyuDFAdapter.call_on_datapath_set is not None:
            RyuDFAdapter.call_on_datapath_set(RyuDFAdapter.ctrl)
        # install table miss flow
        # match = parser.OFPMatch()
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                   ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath, 0, match, actions)

    def _send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @handler.set_ev_handler(ofp_event.EventOFPPortDescStatsReply,
                            handler.MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        self.dispatcher.dispatch('port_desc_stats_reply_handler', ev)

    @handler.set_ev_handler(ofp_event.EventOFPPacketIn,
                            handler.MAIN_DISPATCHER)
    def OF_packet_in_handler(self, event):
        msg = event.msg
        table_id = msg.table_id
        if table_id in self.table_handlers:
            handler = self.table_handlers[table_id]
            handler(event)
        else:
            LOG.info("No handler for table id %(table)s with message "
                     "%(msg)", {'table': table_id, 'msg': msg})

    @handler.set_ev_handler(ofp_event.EventOFPErrorMsg,
                            handler.MAIN_DISPATCHER)
    def OF_error_msg_handler(self, event):
        msg = event.msg
        try:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(msg.data)
            ryu_msg = ofproto_parser.msg(
                self._datapath, version, msg_type,
                msg_len - ofproto_common.OFP_HEADER_SIZE, xid, msg.data)
            LOG.error('OFPErrorMsg received: %s', ryu_msg)
        except Exception:
            LOG.error('Unrecognized OFPErrorMsg received: '
                      'type=0x%(type)02x code=0x%(code)02x '
                      'message=%(msg)s',
                      {'type': msg.type, 'code': msg.code,
                       'msg': utils.hex_array(msg.data)})

    @handler.set_ev_cls(ofp_event.EventOFPGetAsyncReply,
                        handler.MAIN_DISPATCHER)
    def get_async_reply_handler(self, event):
        msg = event.msg
        LOG.debug('OFPGetAsyncReply received: packet_in_mask=0x%08x:0x%08x '
                  'port_status_mask=0x%08x:0x%08x '
                  'flow_removed_mask=0x%08x:0x%08x',
                  msg.packet_in_mask[0], msg.packet_in_mask[1],
                  msg.port_status_mask[0], msg.port_status_mask[1],
                  msg.flow_removed_mask[0], msg.flow_removed_mask[1])
        self.set_sw_async_msg_config_for_ttl(msg)

    def get_sw_async_msg_config(self):
        """Get the configuration of current switch"""
        ofp_parser = self._datapath.ofproto_parser
        req = ofp_parser.OFPGetAsyncRequest(self._datapath)
        self._datapath.send_msg(req)

    def set_sw_async_msg_config_for_ttl(self, cur_config):
        """Configure switch for TTL

        Configure the switch to packet-in TTL invalid packets to controller.
        Note that this method only works in OFP 1.3, however, this ryu app
        claims that it only supports ofproto_v1_3.OFP_VERSION. So, no check
        will be made here.
        """
        dp = self._datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        if cur_config.packet_in_mask[0] & 1 << ofproto.OFPR_INVALID_TTL != 0:
            LOG.info('SW config for TTL error packet in has already '
                     'been set')
            return

        packet_in_mask = (cur_config.packet_in_mask[0] |
                          1 << ofproto.OFPR_INVALID_TTL)
        m = parser.OFPSetAsync(
            dp, [packet_in_mask, cur_config.packet_in_mask[1]],
            [cur_config.port_status_mask[0], cur_config.port_status_mask[1]],
            [cur_config.flow_removed_mask[0], cur_config.flow_removed_mask[1]])
        dp.send_msg(m)
        LOG.info('Set SW config for TTL error packet in.')

    @handler.set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)  # .topology_api_app
        for switch in switch_list:
            lswitch =self.create_switch(switch)
            for p in switch.ports:
                print 'create port {}'.format(p)
                self.create_port(switch.dp, p.hw_addr, p.port_no, lswitch)

    def create_switch(self, switch):
        return l2.LogicalSwitch(
            subnets= self.fake_lswitch_default_subnets,
            unique_key=1,
            name='private',
            is_external=False,
            segmentation_id=41,
            mtu=1450,
            topic='whoami',
            id='{}'.format(switch.dp.id),
            version=5)

    def create_port(self, dp, mac, port_no, lswitch):
        ips = ('0.0.0.0',)
        p_id = 'lport_{0}'.format(port_no)
        new_port = l2.LogicalPort(
            id=p_id,
            topic="debug-topic",
            name='logical_port',
            unique_key=2,
            version=2,
            ips=ips,
            subnets=None,
            macs=[mac],
            binding=self.local_binding,
            lswitch=lswitch,
            security_groups=['fake_security_group_id1'],
            allowed_address_pairs=[],
            port_security_enabled=False,
            device_owner='whoami',
            device_id='fake_device_id',
            # binding_vnic_type=binding_vnic_type,
            dhcp_params={},
        )
        self.nb_api.create(new_port)
        new_port.emit_created()
        new_port._emit(event=l2.EVENT_BIND_LOCAL)
        return new_port

