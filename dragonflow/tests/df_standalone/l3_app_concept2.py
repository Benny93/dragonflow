import logging

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.lib.packet.ipv4 import ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import hub
from netaddr.ip import IPNetwork

from dragonflow.db import db_store, api_nb
from dragonflow.db.models import l2
from dragonflow.db.models import l3
from dragonflow.common.exceptions import DBKeyNotFound
from ryu.topology.api import get_link, get_switch
from ryu.topology import event, switches

LOG = logging.getLogger(__name__)
# LOG.setLevel(logging.DEBUG)
logging.basicConfig()

"""
Concept for l3 routing with shared database and optional cache:

Topology

Host -- net1 -- Switch -- net2 -- Switch -- net3 -- Switch -- net4 -- host

Switch is called datapath (dp)

Base App for this concept was taken from:
https://github.com/ttsubo/simpleRouter/blob/master/ryu-app/openflowRouter.py

"""

DP1_PORT1_GATEWAY_IP = '192.168.33.1'
DP1_PORT2_GATEWAY_IP = '192.168.100.1'

DP2_PORT1_GATEWAY_IP = '192.168.100.254'
DP2_PORT2_GATEWAY_IP = '192.168.200.1'

DP3_PORT1_GATEWAY_IP = '192.168.200.254'
DP3_PORT2_GATEWAY_IP = '192.168.34.1'

SUBNET1 = '192.168.33.0/24'
SUBNET2 = '192.168.100.0/24'
SUBNET3 = '192.168.200.0/24'
SUBNET4 = '192.168.34.0/24'


class SimpleRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    nb_api = None

    USE_CACHE = False

    cache_datapath_by_dpid = {}

    cache_logical_router_by_dpid = {}
    cache_logical_port_by_port_id = {}

    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)
        self.ping_q = hub.Queue()
        # if self.nb_api is None:
        #    self.nb_api = api_nb.NbApi.get_instance(False)
        # register callback
        # self.nb_api.on_db_change.append(self.db_change_callback)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def on_datapath_event(self, ev):
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)
        self.nb_api.on_db_change.append(self.db_change_callback)

    def db_change_callback(self, table, key, action, value, topic=None):
        """
        Called from nb_api on db update.

        Routing:
        When logicalport is updated with a host ip (this happens while arp request/responses):
            for all routers
                install route to this ip

        :param table:
        :param key:
        :param action:
        :param value:
        :param topic:
        """
        if self.USE_CACHE:
            # Update cache
            if action == 'create' or action == 'set':
                if table == 'lport':
                    self.cache_logical_port_by_port_id[key] = self.nb_api.get(l2.LogicalPort(id=key))
                if table == 'lrouter':
                    self.cache_logical_router_by_dpid[key] = self.nb_api.get(l3.LogicalRouter(id=key))
            if action == 'del':
                if table == 'lport':
                    # default if key does not exists is None
                    self.cache_logical_port_by_port_id.pop(key, None)
                if table == 'lrouter':
                    self.cache_logical_router_by_dpid.pop(key, None)

        print("L3 App: Received Update for table {} and key {} action {}".format(table, key, action))
        if action == 'set':
            if table == 'lport':
                if self.USE_CACHE:
                    updated_port = self.cache_logical_port_by_port_id[key]
                else:
                    updated_port = self.nb_api.get(l2.LogicalPort(id=key))

                if len(updated_port.ips) is not 0:
                    for ip in updated_port.ips:
                        # new ip discovered
                        # install route on every datapath
                        # only update the other datapaths
                        for dpid, datapath in self.cache_datapath_by_dpid.iteritems():
                            out_port, new_src_mac, new_dst_mac = self.get_next_hop(dpid, ip)
                            if out_port is None:
                                continue
                            out_port_id = "{}:{}".format(dpid, out_port)
                            lout_port = self.nb_api.get(l2.LogicalPort(id=out_port_id))
                            if ip in lout_port.ips:
                                continue
                            # else add new ip and install flow
                            lout_port.ips.append(ip)
                            self.nb_api.update(lout_port)
                            # install flow
                            print "L3 IP via pubsub: installing flow on {}: out_port: {} src_mac:" \
                                  " {} dst_mac: {}, ip: {}".format(datapath.id, out_port, new_src_mac, new_dst_mac, ip)
                            self.add_flow_gateway_for_ip(datapath, int(out_port), ip, new_src_mac, new_dst_mac)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser

        if datapath.id == 2:
            self.add_flow_drop_arp(datapath)

        # TODO: Cache usage
        self.cache_datapath_by_dpid[str(datapath.id)] = datapath

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX,
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)
        return 0

    def install_table_miss(self, datapath, dpid):
        datapath.id = dpid

        match = datapath.ofproto_parser.OFPMatch()

        actions = [datapath.ofproto_parser.OFPActionOutput(
            datapath.ofproto.OFPP_CONTROLLER,
            datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=0xffffffff,
            match=match,
            instructions=inst)
        datapath.send_msg(mod)
        return 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Routing simplified for prototyping!!!
        Only works with Topology of testbed0/mininet_multi_switches_ipv4.py
        :param ev:
        :return:
        """
        msg = ev.msg
        datapath = msg.datapath
        inPort = msg.match['in_port']

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)

        if etherFrame.ethertype == ether.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.receive_arp(datapath, packet, etherFrame, inPort)
        elif etherFrame.ethertype == ether.ETH_TYPE_IP:
            self.receive_ip(datapath, packet, etherFrame, inPort)
        else:
            LOG.debug("receive Unknown packet %s => %s (port%d)"
                      % (etherFrame.src, etherFrame.dst, inPort))
            self.print_etherFrame(etherFrame)
            LOG.debug("Drop packet")
            return 1
        return 0

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

    def receive_ip(self, datapath, packet, etherFrame, inPort):
        ipPacket = packet.get_protocol(ipv4)
        LOG.debug("receive IP packet %s => %s (port%d)"
                  % (etherFrame.src, etherFrame.dst, inPort))
        self.print_etherFrame(etherFrame)
        self.print_ipPacket(ipPacket)
        if ipPacket.proto == inet.IPPROTO_ICMP:
            icmpPacket = packet.get_protocol(icmp.icmp)
            self.check_icmp(datapath, etherFrame, ipPacket, icmpPacket, inPort)
            return 0
        else:
            LOG.debug("Drop packet")
            return 1

        for portNo in self.arpInfo.keys():
            if portNo == inPort:
                break
        else:
            hostIpAddr = ipPacket.src
            hostMacAddr = etherFrame.src
            self.arpInfo[inPort] = ArpTable(hostIpAddr, hostMacAddr, inPort)
        return 0

    def check_icmp(self, datapath, etherFrame, ipPacket, icmpPacket, inPort):
        srcMac = etherFrame.src
        dstMac = etherFrame.dst
        srcIp = ipPacket.src
        dstIp = ipPacket.dst
        ttl = ipPacket.ttl
        type = icmpPacket.type
        try:
            id = icmpPacket.data.id
        except:
            id = 1
        try:
            seq = icmpPacket.data.seq
        except:
            seq = 1
        try:
            data = icmpPacket.data.data
        except:
            data = ''

        if icmpPacket.type == 0:
            self.print_icmp(icmpPacket)
            icmp_length = ipPacket.total_length - 20
            buf = (" %d bytes from %s: icmp_req=%d ttl=%d data=[%s] "
                   % (icmp_length, srcIp, seq, ttl, data))
            self.ping_q.put(buf)
        elif icmpPacket.type == 3:
            buf = "ping ng ( Detination Unreachable )"
            self.ping_q.put(buf)
        elif icmpPacket.type == 8:
            self.reply_icmp(datapath, srcMac, dstMac, srcIp, dstIp, ttl, type,
                            id, seq, data, inPort)
        elif icmpPacket.type == 11:
            buf = "ping ng ( Time Exceeded )"
            self.ping_q.put(buf)
        else:
            buf = "ping ng ( Unknown reason )"
            self.ping_q.put(buf)
        return 0

    def reply_icmp(self, datapath, srcMac, dstMac, srcIp, dstIp, ttl, type, id,
                   seq, data, inPort):
        """
         if dstip is the ip of the router-> reply
         if not forward to port of matching network
        :param datapath:
        :param srcMac:
        :param dstMac:
        :param srcIp:
        :param dstIp:
        :param ttl:
        :param type:
        :param id:
        :param seq:
        :param data:
        :param inPort:
        :return:
        """

        router_port = self.get_router_port_by_gateway_ip(datapath.id, dstIp)
        if router_port:
            # dstIp is the IP of one of the router ports
            # -> replay
            # data already available
            send_src_mac = dstMac
            send_dst_mac = srcMac
            send_src_ip = dstIp
            send_dst_ip = srcIp
            send_port = inPort
            self.send_icmp(datapath, send_src_mac, send_src_ip, send_dst_mac,
                           send_dst_ip, send_port, seq, data, id, 0, ttl)
            LOG.debug("send icmp echo reply %s => %s (port%d)"
                      % (send_src_mac, send_dst_mac, send_port))

        else:
            # if in own net.
            matching_port = self.get_port_by_ip(datapath, dstIp)
            if matching_port:
                # send ARP request opcode =1
                # A flow rule is created when receiving the arp reply from client
                # self.send_arp(datapath, 1, matching_port.mac, str(matching_port.gateway_ip), "00:00:00:00:00:00", dstIp,
                #               int(matching_port.port_no))
                pass
            else:
                print ("Forward ICMP to matching network")
                out_port, new_src_mac, new_dst_mac = self.get_next_hop(dpid=datapath.id, dstIP=dstIp)
                self.add_flow_gateway_for_ip(datapath, int(out_port), dstIp, new_src_mac, new_dst_mac)
                # self.add_flow_gateway(datapath,ether.ETH_TYPE_IP, new_src_mac,new_dst_mac,int(out_port),dstIp)

        return 0

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)
        hostIpAddr = arpPacket.src_ip
        hostMacAddr = arpPacket.src_mac
        if arpPacket.opcode == 1:
            operation = "ARP Request"
            arp_dstIp = arpPacket.dst_ip
        elif arpPacket.opcode == 2:
            operation = "ARP Reply"

        LOG.debug("receive %s %s => %s (port%d)"
                  % (operation, etherFrame.src, etherFrame.dst, inPort))

        self.update_port_ip(datapath.id, inPort, hostIpAddr)

        self.print_etherFrame(etherFrame)
        self.print_arpPacket(arpPacket)

        if arpPacket.opcode == 1:
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            # ARP Response from Host
            # Old: self.arpInfo[inPort] = ArpTable(hostIpAddr, hostMacAddr, inPort)
            # New: Create Flow rule that sends packets to the dstIP with matching mac adress pair
            # TODO: Can be removed. Host data is learned on ARP request
            # mac__of_router_port = self.get_hwaddr_of_router_port(datapath, inPort)
            # self.add_flow_gateway_for_ip(datapath, out_port=inPort, dst_ip=hostIpAddr, new_src_mac=mac__of_router_port,
            #                             new_dst_mac=hostMacAddr)

            return 0
        return 0

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):

        srcMac = None
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src

        # for portNo, port in self.portInfo.items():
        #     (routerIpAddr, routerMacAddr, routerPort, routeDist) = port.get_all()
        #     if arp_dstIp == routerIpAddr:
        #         srcMac = routerMacAddr
        #         outPort = portNo

        router_port = self.get_router_port_by_gateway_ip(datapath.id, arpPacket.dst_ip)
        if router_port:
            outPort = int(router_port.port_no)
            srcMac = router_port.mac

            self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
            # Create Rule from host knowledge
            self.add_flow_gateway_for_ip(datapath, out_port=inPort, dst_ip=dstIp, new_src_mac=srcMac,
                                         new_dst_mac=dstMac)

            print("send ARP reply %s => %s (port%d)" % (srcMac, dstMac, outPort))
            return 0
        else:
            print ("dpid {} : Unknown arp request received: Who has {} !".format(datapath.id, arpPacket.dst_ip))
            return 1

    def send_icmp(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_IP)
        iph = ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp)
        echo = icmp.echo(id, seq, data)
        icmph = icmp.icmp(type, 0, 0, echo)

        p = Packet()
        p.add_protocol(e)
        p.add_protocol(iph)
        p.add_protocol(icmph)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
        return 0

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort, RouteDist=None):
        if opcode == 1:
            # self.portInfo[outPort] = PortTable(outPort, srcIp, srcMac, RouteDist)
            # TODO: Update Database? This is not necessarily new data
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
        return 0

    def add_flow_gateway_for_ip(self, datapath, out_port, dst_ip, new_src_mac, new_dst_mac):
        """
        Creates a flow rule that matches on the destination ip and forwards the packets through the
        given port.
        While forwarding the source mac and destination mac of the packet is modified
        to make l2 switching work

        :param datapath:
        :param out_port:
        :param dst_ip:
        :param new_src_mac:
        :param new_dst_mac:
        :return:
        """
        parser = datapath.ofproto_parser
        # eth_type ip : 0x0800
        match = parser.OFPMatch(eth_type=0x0800,
                                ipv4_dst=dst_ip,
                                )
        actions = [parser.OFPActionSetField(eth_src=new_src_mac),
                   parser.OFPActionSetField(eth_dst=new_dst_mac),
                   parser.OFPActionOutput(out_port),
                   parser.OFPActionDecNwTtl()]

        self.add_flow(datapath, 1, match, actions)

    # Database Access

    # TODO: Provide cache option for faster responses.

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        """
        Called when a new switch connects to the controller.
        Creates switches and ports in the db (if the do not already exist)

        :param ev:
        """
        switch_list = get_switch(self, None)  # .topology_api_app

        # TODO: Create only if not exisiting
        for switch in switch_list:
            # self.create_switch(switch)
            self.create_logical_router(switch)

        print ("l3 Switch ENTER Done")

    @set_ev_cls(event.EventSwitchLeave)
    def on_switch_leave(self, ev):
        print "Switch left"
        dpid = "{}".format(ev.switch.dp.id)
        # Removing Switch from DB and Cache (optional)
        router = self.nb_api.get(l3.LogicalRouter(id=dpid))
        self.nb_api.delete(router)
        print ("l3 Switch LEAVE Done")

    def create_logical_router(self, switch):
        """
        Only works with testbed0/mininet_multi_switches_ipv4.py
        :param switch:
        :return:
        """
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)

        # TODO: lswitch from nb api
        router_ports = []
        dpid = str(switch.dp.id)

        for port in switch.ports:
            # network = "192.168.33.1/24",
            network = None
            ip = None
            if dpid == '1':
                if port.port_no == 1:
                    network = SUBNET1
                    ip = DP1_PORT1_GATEWAY_IP
                else:
                    network = SUBNET2
                    ip = DP1_PORT2_GATEWAY_IP
            elif dpid == '2':
                if port.port_no == 1:
                    network = SUBNET2
                    ip = DP2_PORT1_GATEWAY_IP
                else:
                    network = SUBNET3
                    ip = DP2_PORT2_GATEWAY_IP
            elif dpid == '3':
                if port.port_no == 1:
                    network = SUBNET3
                    ip = DP3_PORT1_GATEWAY_IP
                else:
                    network = SUBNET4
                    ip = DP3_PORT2_GATEWAY_IP
            else:
                print "Datapath {} not supported. Router not created!".format(dpid)
                return
            if network and ip:
                router_port = l3.LogicalRouterPort(lswitch="{}".format(switch.dp.id),
                                                   topic="fake_tenant1",
                                                   network=network,
                                                   gateway_ip=ip,
                                                   mac="{}".format(port.hw_addr),
                                                   port_no=str(port.port_no),
                                                   unique_key=4,
                                                   id="{}:{}".format(switch.dp.id, port.port_no))
                router_ports.append(router_port)

        router = l3.LogicalRouter(name="router_of_{}".format(switch.dp.id),
                                  topic="fake_tenant1",
                                  version=10,
                                  id="{}".format(switch.dp.id),
                                  unique_key=5,
                                  ports=router_ports)
        self.nb_api.create(router)

    def get_router_port_by_gateway_ip(self, dpid, gateway_ip):
        """
        Returns Port of Datapath with matching gateway ip
        :param dpid:
        :param gateway_ip:
        :return:
        """
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)

        dpid = str(dpid)
        if self.USE_CACHE:
            lrouter = self.cache_logical_router_by_dpid[dpid]
        else:
            lrouter = self.nb_api.get(l3.LogicalRouter(id=dpid))
        for router_port in lrouter.ports:
            if str(router_port.gateway_ip) == gateway_ip:
                # check all ports of this datapath
                return router_port
        return None

    def get_next_hop(self, dpid, dstIP):
        """
        This is a STUB!

        This is static implemented according to the test topology.
        In Future work this information is retrieved via routing protocols
        :param dpid:
        :param dstIP:
        :return: port number, new src mac, new dst mac
        """

        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)

        dstIP = str(dstIP)

        # TODO: THIS IS JUST A STUB: Use Database for this
        dpid = str(dpid)
        if self.USE_CACHE:
            lrouter = self.cache_logical_router_by_dpid[dpid]
        else:
            lrouter = self.nb_api.get(l3.LogicalRouter(id=dpid))
        if dpid == '1':
            if dstIP == "192.168.34.10":
                rport = lrouter.ports[1]
                if self.USE_CACHE:
                    nexthop_router = self.cache_logical_router_by_dpid["2"]
                else:
                    nexthop_router = self.nb_api.get(l3.LogicalRouter(id="2"))
                nh_port = nexthop_router.ports[0]
                return rport.port_no, rport.mac, nh_port.mac
            elif dstIP == "192.168.33.10":
                # host mac adress
                if self.USE_CACHE:
                    lport = self.cache_logical_port_by_port_id["{}:{}".format(dpid, 1)]
                else:
                    lport = self.nb_api.get(l2.LogicalPort(id="{}:{}".format(dpid, 1)))
                dst_mac = lport.macs[0]
                rport = lrouter.ports[0]
                return rport.port_no, rport.mac, dst_mac

        elif dpid == '2':
            if dstIP == "192.168.34.10":
                rport = lrouter.ports[1]  # second port
                if self.USE_CACHE:
                    nexthop_router = self.cache_logical_router_by_dpid["3"]
                else:
                    nexthop_router = self.nb_api.get(l3.LogicalRouter(id="3"))
                nh_port = nexthop_router.ports[0]
                return rport.port_no, rport.mac, nh_port.mac
            elif dstIP == "192.168.33.10":
                rport = lrouter.ports[0]  # first port
                if self.USE_CACHE:
                    nexthop_router = self.cache_logical_router_by_dpid["1"]
                else:
                    nexthop_router = self.nb_api.get(l3.LogicalRouter(id="1"))
                nh_port = nexthop_router.ports[1]  # second port
                return rport.port_no, rport.mac, nh_port.mac
        elif dpid == '3':
            if dstIP == "192.168.34.10":
                # host mac adress
                if self.USE_CACHE:
                    lport = self.cache_logical_port_by_port_id["{}:{}".format(dpid, 2)]
                else:
                    lport = self.nb_api.get(l2.LogicalPort(id="{}:{}".format(dpid, 2)))
                dst_mac = lport.macs[0]
                rport = lrouter.ports[1]  # second port
                return rport.port_no, rport.mac, dst_mac
            elif dstIP == "192.168.33.10":
                rport = lrouter.ports[0]
                if self.USE_CACHE:
                    nexthop_router = self.cache_logical_router_by_dpid["2"]
                else:
                    nexthop_router = self.nb_api.get(l3.LogicalRouter(id="2"))
                nh_port = nexthop_router.ports[1]
                return rport.port_no, rport.mac, nh_port.mac
        else:
            print "Datapath {} not supported. Cannot return nexthop information!"
            return None, None, None

    def update_port_ip(self, dpid, port, ip):
        """
        Update Database with learned IPs from port
        :param dpid:
        :param port:
        :param ip:
        :return:
        """
        # TODO Connection between mac and ip of host?
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)

        port_id = "{}:{}".format(dpid, port)
        try:
            lport = self.nb_api.get(l2.LogicalPort(id=port_id))
            for ip_addr_obj in lport.ips:
                if str(ip_addr_obj) == ip:
                    # already learned
                    return
            lport.ips.append(ip)
            self.nb_api.update(lport)
        # TODO: Remove old ips
        except DBKeyNotFound:
            # TODO: Create Port?
            print "Key not Found!!"

    def get_hwaddr_of_router_port(self, datapath, in_port):
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)

        if self.USE_CACHE:
            lrouter = self.cache_logical_router_by_dpid[datapath.id]
        else:
            lrouter = self.nb_api.get(l3.LogicalRouter(id=str(datapath.id)))
        for port in lrouter.ports:
            if port.port_no == in_port:
                return port.mac
        return None

    def get_port_by_ip(self, datapath, dstIp):
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)
        if self.USE_CACHE:
            lrouter = self.cache_logical_router_by_dpid[datapath.id]
        else:
            lrouter = self.nb_api.get(l3.LogicalRouter(id=str(datapath.id)))
        for port in lrouter.ports:
            if self.ip_matches_network(str(port.network), str(dstIp)):
                return port

    def ip_matches_network(self, network, ip):
        """

        '{:08b}'.format(254): Converts 254 in a string of its binary representation

        ip_bits[:net_mask] == net_ip_bits[:net_mask]: compare the ip bit streams

        :param network: string like '192.168.33.0/24'
        :param ip: string like '192.168.33.1'
        :return: if ip matches network
        """
        net_ip, net_mask = network.split('/')
        net_mask = int(net_mask)
        ip_bits = ''.join('{:08b}'.format(int(x)) for x in ip.split('.'))
        net_ip_bits = ''.join('{:08b}'.format(int(x)) for x in net_ip.split('.'))

        return ip_bits[:net_mask] == net_ip_bits[:net_mask]

    # Printing of packets
    def print_etherFrame(self, etherFrame):
        print("---------------------------------------")
        print("eth_dst_address :%s" % etherFrame.dst)
        print("eth_src_address :%s" % etherFrame.src)
        print("eth_ethertype :0x%04x" % etherFrame.ethertype)
        print("---------------------------------------")

    def print_arpPacket(self, arpPacket):
        print("arp_hwtype :%d" % arpPacket.hwtype)
        print("arp_proto :0x%04x" % arpPacket.proto)
        print("arp_hlen :%d" % arpPacket.hlen)
        print("arp_plen :%d" % arpPacket.plen)
        print("arp_opcode :%d" % arpPacket.opcode)
        print("arp_src_mac :%s" % arpPacket.src_mac)
        print("arp_src_ip :%s" % arpPacket.src_ip)
        print("arp_dst_mac :%s" % arpPacket.dst_mac)
        print("arp_dst_ip :%s" % arpPacket.dst_ip)
        print("---------------------------------------")

    def print_ipPacket(self, ipPacket):
        print("ip_version :%d" % ipPacket.version)
        print("ip_header_length :%d" % ipPacket.header_length)
        print("ip_tos :%d" % ipPacket.tos)
        print("ip_total_length :%d" % ipPacket.total_length)
        print("ip_identification:%d" % ipPacket.identification)
        print("ip_flags :%d" % ipPacket.flags)
        print("ip_offset :%d" % ipPacket.offset)
        print("ip_ttl :%d" % ipPacket.ttl)
        print("ip_proto :%d" % ipPacket.proto)
        print("ip_csum :%d" % ipPacket.csum)
        print("ip_src :%s" % ipPacket.src)
        print("ip_dst :%s" % ipPacket.dst)
        print("---------------------------------------")

    def print_icmp(self, icmpPacket):
        print("icmp_type :%d", icmpPacket.type)
        print("icmp_code :%d", icmpPacket.code)
        print("icmp_csum :%d", icmpPacket.csum)
        print("icmp_id :%d", icmpPacket.data.id)
        print("icmp_seq :%d", icmpPacket.data.seq)
        print("icmp_data :%s", icmpPacket.data.data)

    def add_flow_drop_arp(self, datapath):
        """
        This is used for the testing scenario to keep arp
        request from reaching the other networks beyond switch 2

        Dropping at the switch by clearing all actions (including the table
        miss action) from the flow.
        :param datapath:
        :return:
        """
        proto = datapath.ofproto
        parser = datapath.ofproto_parser
        # eth_type arp : 0x0806
        match = parser.OFPMatch(eth_type=0x0806, )

        instruction = [
            parser.OFPInstructionActions(proto.OFPIT_CLEAR_ACTIONS, [])
        ]

        msg = parser.OFPFlowMod(datapath,
                                # table_id=OFDPA_FLOW_TABLE_ID_ACL_POLICY,
                                priority=1,
                                command=proto.OFPFC_ADD,
                                match=match,
                                instructions=instruction
                                )
        datapath.send_msg(msg)
