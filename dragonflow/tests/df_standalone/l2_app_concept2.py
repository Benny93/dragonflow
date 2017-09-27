from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_link, get_switch
from ryu.topology import event, switches

from dragonflow.common.exceptions import DBKeyNotFound
from dragonflow.db import db_store, api_nb
from dragonflow.db.models import l2

from dragonflow.tests.df_standalone import controller_concept

from dragonflow.neutron.common import config as common_config
import sys
from dragonflow.db.models import core

from oslo_log import log

LOG = log.getLogger(__name__)


# class dfs_app_base(app_manager.RyuApp):
#     def __init__(self, *args, **kwargs):
#         super(dfs_app_base, self).__init__(*args, **kwargs)



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    chassis = core.Chassis(
        id='whoami',
        ip='172.24.4.50',
        tunnel_types=('vxlan',),
    )

    local_binding = l2.PortBinding(
        type=l2.BINDING_CHASSIS,
        chassis=chassis,
    )

    cache_lports = {}
    cache_switches = {}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # self.mac_to_port = {}
        db_store._instance = None
        self.fake_lswitch_default_subnets = [l2.Subnet(dhcp_ip="192.168.123.0",
                                                       name="private-subnet",
                                                       enable_dhcp=True,
                                                       topic="fake_tenant1",
                                                       gateway_ip="192.168.123.1",
                                                       cidr="192.168.123.0/24",
                                                       id="fake_subnet1")]
        print (self.fake_lswitch_default_subnets[0].dhcp_ip)
        common_config.init(sys.argv[1:3])
        common_config.setup_logging()
        self.nb_api = api_nb.NbApi.get_instance(False)

        self.controller = controller_concept.DfStandaloneController(
            'df_standalone', self.nb_api)
        self.db_store = db_store.get_instance()
        self.controller.on_datapath_set()
        self.nb_api.on_db_change = self.db_change_callback

        self.cache_lports = {}
        lports = self.nb_api.get_all(l2.LogicalPort)
        lswitches = self.nb_api.get_all(l2.LogicalSwitch)
        for lswitch in lswitches:
            dpid = lswitch.id
            for lport in lports:
                if lport.lswitch == lswitch.id:
                    self.cache_switches[lswitch.id][lport.id] = lport

        for lport in lports:
            self.cache_lports[lport.id] = lport


        # TODO: switch leave
        #TODO: filter for datapath



        # TODO Controllername
        # self.controller.register_topic("fake_tenant1")

    def db_change_callback(self, table, key, action, value, topic=None):
        print("Received Update:")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        # self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port
        self.update_mac_to_port(dpid, src, in_port)

        #        if dst in self.mac_to_port[dpid]:
        #            out_port = self.mac_to_port[dpid][dst]
        #        else:
        #            out_port = ofproto.OFPP_FLOOD

        out_port = self.get_port_from_mac(dpid, dst)
        if out_port is None:
            # unknown
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
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
        switch_list = get_switch(self, None)  # .topology_api_app
        switches = [switch.dp.id for switch in switch_list]
        print "switches: ", switches

        links_list = get_link(self, switches[0])  # .topology_api_app ,None
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        print "links_list: ", links_list  # [0]
        print "links", links

        #TODO: Create only if not exisiting


        # # update store with ports
        # for switch in switch_list:
        #     for port in switch.ports:
        #         # mac = port.hw_addr
        #         # lo_port = l2.LogicalSimplePort(id=port.poert_no,
        #         #                                macs=(mac,),
        #         #                                name=port.name,
        #         #                                lswitch=switch.dp.id,
        #         #                                enabled=True,
        #         #                                version=2)
        #         #self.nb_api.driver.create_key(l2.LogicalPort.table_name, "{}:{}".format(switch.dp.id, port.port_no), port.hw_addr)
        for switch in switch_list:
            self.create_switch(switch)
            for p in switch.ports:
                print 'create port {}'.format(p)
                self.create_port(switch.dp, p.hw_addr, p.port_no)

        print ("Switch ENTER Done")

    def get_port_from_mac(self, dpid, mac):
        for _, lport in self.cache_lports.iteritems():
            if mac in lport.macs:
                return int(lport.port_no)
        # if nothing was found in cache
        # TODO check db???
        return None

    def update_mac_to_port(self, dpid, mac, port):
        port_id = "lport_{}".format(port)
        # check cache:
        # TODO: check for host migration
        if port_id in self.cache_lports:
            cport = self.cache_lports[port_id]
            if mac not in cport.macs:
                # update cache
                cport.macs.append(mac)
                # update db
                self.nb_api.update(cport)
        else:
            # new learned port!
            # write to database
            self.cache_lports[port_id] = self.create_port(dpid, mac, port)

    def create_port(self, dpid, mac, port_no):
        ips = ('0.0.0.0',)
        p_id = 'lport_{0}'.format(port_no)
        new_port = l2.LogicalPort(
            id=p_id,
            port_no=str(port_no),
            topic="debug-topic",
            name='logical_port',
            unique_key=2,
            version=2,
            ips=ips,
            subnets=None,
            macs=[mac],
            binding=self.local_binding,
            lswitch='{}'.format(dpid),
            security_groups=['fake_security_group_id1'],
            allowed_address_pairs=[],
            port_security_enabled=False,
            device_owner='whoami',
            device_id='fake_device_id',
            # binding_vnic_type=binding_vnic_type,
            dhcp_params={},
        )
        self.cache_lports[p_id] = new_port
        self.nb_api.create(new_port)
        new_port.emit_created()
        return new_port

    def create_switch(self, switch):
        local_switch = l2.LogicalSwitch(
            subnets=self.fake_lswitch_default_subnets,
            network_type='local',
            id='{}'.format(switch.dp.id),
            segmentation_id=41,
            mtu=1500,
            topic='fake_tenant1',
            unique_key=int(switch.dp.id),
            is_external=False,
            name='private')
        self.nb_api.create(local_switch)
