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
    # This cache will be shared with other apps in future development
    cache_ports_by_datapath_id = {}

    USE_CACHE = True

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
        #print (self.fake_lswitch_default_subnets[0].dhcp_ip)

        #common_config.init(sys.argv[1:3])
        #common_config.setup_logging()
        self.nb_api = api_nb.NbApi.get_instance(False)

        self.controller = controller_concept.DfStandaloneController(
            'df_standalone', self.nb_api)
        self.db_store = db_store.get_instance()
        self.controller.on_datapath_set()

        self.nb_api.on_db_change.append(self.db_change_callback)

        if self.USE_CACHE:
            self.sync_with_database()

    def sync_with_database(self):
        """
        After controller start/restart synchronize cache with db
        :return:
        """
        # learn from db
        lports = self.nb_api.get_all(l2.LogicalPort)
        lswitches = self.nb_api.get_all(l2.LogicalSwitch)
        for lswitch in lswitches:
            dpid = "{}".format(lswitch.id)
            for lport in lports:
                if lport.lswitch.id == dpid:
                    self.cache_ports_by_datapath_id.setdefault(dpid, {})
                    self.cache_ports_by_datapath_id[dpid][lport.id] = lport
                    # TODO Controller name as topic
                    # self.controller.register_topic("fake_tenant1")

    def db_change_callback(self, table, key, action, value, topic=None):
        """
        Called from nb_api on db update.

        :param table:
        :param key:
        :param action:
        :param value:
        :param topic:
        """
        print("L2 App: Received Update for table {} and key {} action {}".format(table, key, action))
        # These updates are only required if data is cached locally
        if self.USE_CACHE:
            if table == 'lport' and (action == 'create' or action == 'update'):
                # check if datapath of port can be found in cache
                cache_dpid = None
                for dpid, port_id in self.cache_ports_by_datapath_id.iteritems():
                    if port_id == key:
                        # this value needs to bee updated
                        # updating values while iterating isn't a good practice: Exit loop and apply update
                        cache_dpid = dpid
                        break
                if not cache_dpid is None:
                    # values was in cache -> update
                    self.cache_ports_by_datapath_id[cache_dpid][key] = self.nb_api.get(l2.LogicalPort(id=key))
                else:
                    # port not in cache
                    lport = self.nb_api.get(l2.LogicalPort(id=key))
                    dpid = lport.lswitch.id
                    self.cache_ports_by_datapath_id[dpid][lport.id] = lport

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

        # self.print_cache_ports_by_datapath_id()

        # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port
        self.update_mac_to_port(dpid, src, in_port, self.USE_CACHE)

        #        if dst in self.mac_to_port[dpid]:
        #            out_port = self.mac_to_port[dpid][dst]
        #        else:
        #            out_port = ofproto.OFPP_FLOOD

        out_port = self.get_port_from_mac(dpid, dst, self.USE_CACHE)
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
        """
        Called when a new switch connects to the controller.
        Creates switches and ports in the db (if the do not already exist)

        :param ev:
        """
        switch_list = get_switch(self, None)  # .topology_api_app
        # switches = [switch.dp.id for switch in switch_list]
        # print "switches: ", switches

        # links_list = get_link(self, switches[0])  # .topology_api_app ,None
        # links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # print "links_list: ", links_list  # [0]
        # print "links", links

        for switch in switch_list:
            self.create_switch(switch)
            for p in switch.ports:
                #print 'create port {}'.format(p)
                self.create_port(switch.dp.id,"", p.port_no, p.hw_addr)

        print ("L2 App: Switch ENTER Done")

    @set_ev_cls(event.EventSwitchLeave)
    def on_switch_leave(self, ev):
        dpid = "{}".format(ev.switch.dp.id)
        print "L2 App: Switch {} left".format(dpid)
        # Removing Switch from DB and Cache (optional)
        db_switch = self.nb_api.get(l2.LogicalSwitch(id=dpid))
        self.nb_api.delete(db_switch)
        lports = self.nb_api.get_all(l2.LogicalPort)
        for port in lports:
            if str(port.lswitch.id) == dpid:
                self.nb_api.delete(port)
        # Remove switch and ports from cache if cacheing is enabled
        if self.USE_CACHE:
            self.cache_ports_by_datapath_id.pop(dpid, None)

    # DATABASE and CACHE Access

    def create_port_id(self, dpid, port_no):
        """
        Create the id of a port with its datapath/switch id
        :rtype: Created ID: Used for key in store
        """
        return "{}:{}".format(dpid, port_no)

    def get_port_from_mac(self, dpid, mac, use_cache=True):
        """

        Can be inconsistent with db
        :param dpid:
        :param mac:
        :return:
        """

        dpid = str(dpid)
        if use_cache:
            if dpid in self.cache_ports_by_datapath_id.keys():
                for _, lport in self.cache_ports_by_datapath_id[dpid].iteritems():
                    if mac in lport.macs:
                        return int(lport.port_no)
        else:
            try:
                lports = self.nb_api.get_all(l2.LogicalPort)
                for port in lports:
                    if port.lswitch.id == dpid and mac in port.macs:
                        return int(port.port_no)
            except DBKeyNotFound:
                return None
        # if nothing was found in cache
        return None

    def update_mac_to_port(self, dpid, mac, port, use_cache=True):
        """
        Can be inconsistent with db
        :param dpid:
        :param mac:
        :param port:
        """
        port_id = self.create_port_id(dpid, port)
        dpid = str(dpid)
        # TODO: check for host migration
        if use_cache:
            # check cache:
            if dpid in self.cache_ports_by_datapath_id.keys():
                if port_id in self.cache_ports_by_datapath_id[dpid]:
                    cport = self.cache_ports_by_datapath_id[dpid][port_id]
                    if mac not in cport.macs:
                        # update cache
                        cport.macs.append(mac)
                        # update db
                        self.nb_api.update(cport)
            else:
                # new learned port!
                # write to database
                self.cache_ports_by_datapath_id.setdefault(dpid, {})  # create empty entry if key does not exists
                self.cache_ports_by_datapath_id[dpid][port_id] = self.create_port(dpid, mac, port)
        else:
            try:
                lport = self.nb_api.get(l2.LogicalPort(id=port_id))
                if lport is not None and mac not in lport.macs:
                    lport.macs.append(mac)
                    self.nb_api.update(lport)
            except DBKeyNotFound:
                self.create_port(dpid, mac, port)

    def create_port(self, dpid, mac, port_no, hw_addr=""):
        """
        Creates port in db if not exist
        :param dpid:
        :param mac:
        :param port_no:
        :return:
        """
        ips = ('0.0.0.0',)
        p_id = self.create_port_id(dpid, port_no)
        dpid = str(dpid)
        macs = []
        if mac is not "":
            macs.append(mac)


        if not self.nb_api.get(l2.LogicalPort(id=p_id)):
            new_port = l2.LogicalPort(
                id=p_id,
                port_no=str(port_no),
                topic="debug-topic",
                name='logical_port',
                unique_key=2,
                version=2,
                hw_addr=hw_addr,
                #ips=ips,
                subnets=None,
                macs=macs,
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
            self.cache_ports_by_datapath_id.setdefault(dpid, {})
            self.cache_ports_by_datapath_id[dpid][p_id] = new_port
            self.nb_api.create(new_port)
            new_port.emit_created()
            return new_port

    def create_switch(self, switch):
        """
        Creates switch in db if not exist
        :rtype: LogicalSwitch
        :param switch:
        """
        if not self.nb_api.get(l2.LogicalSwitch(id='{}'.format(switch.dp.id))):
            # switch does not exists in db
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
            return local_switch

    # Debug utils

    def print_cache_ports_by_datapath_id(self):
        for dpid, port_dict in self.cache_ports_by_datapath_id.iteritems():
            for key in port_dict.keys():
                print "\ndpid:{}".format(dpid)
                port = port_dict[key]
                print "\nPort_id: {}, macs:{}".format(port.id, port.macs)
