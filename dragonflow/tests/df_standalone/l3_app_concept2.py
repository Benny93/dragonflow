import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
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

ROUTER_PORT1 = 1
ROUTER_PORT2 = 2


class PortTable(object):
    def __init__(self, routerPort, routerIpAddr, routerMacAddr):
        self.routerPort = routerPort
        self.routerIpAddr = routerIpAddr
        self.routerMacAddr = routerMacAddr

    def get_ip(self):
        return self.routerIpAddr

    def get_all(self):
        return self.routerIpAddr, self.routerMacAddr, self.routerPort


class ArpTable(object):
    def __init__(self, hostIpAddr, hostMacAddr, routerPort):
        self.hostIpAddr = hostIpAddr
        self.hostMacAddr = hostMacAddr
        self.routerPort = routerPort

    def get_mac(self):
        return self.hostMacAddr

    def get_all(self):
        return self.hostIpAddr, self.hostMacAddr, self.routerPort


class RoutingTable(object):
    def __init__(self, dpid, destNwAddr, netMask, hostIpAddr):
        self.dpid = dpid
        self.destNwAddr = destNwAddr
        self.netMask = netMask
        self.hostIpAddr = hostIpAddr


class SimpleRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    nb_api = None

    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)
        self.ping_q = hub.Queue()
        self.portInfo = {}
        self.arpInfo = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser

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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        inPort = msg.match['in_port']

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
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

        sendSrcMac = None

        for portNo, port in self.portInfo.items():
            routerIpAddr = port.get_ip()
            if routerIpAddr == dstIp:
                sendSrcMac = dstMac
                sendDstMac = srcMac
                sendSrcIp = dstIp
                sendDstIp = srcIp
                sendPort = inPort

        if sendSrcMac:
            self.send_icmp(datapath, sendSrcMac, sendSrcIp, sendDstMac,
                           sendDstIp, sendPort, seq, data, id, 0, ttl)
            LOG.debug("send icmp echo reply %s => %s (port%d)"
                      % (sendSrcMac, sendDstMac, sendPort))
        else:
            LOG.debug("Drop packet")
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

        self.update_port_ip(datapath.id,inPort,hostIpAddr)

        self.print_etherFrame(etherFrame)
        self.print_arpPacket(arpPacket)

        if arpPacket.opcode == 1:
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            self.arpInfo[inPort] = ArpTable(hostIpAddr, hostMacAddr, inPort)
        return 0

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):

        srcMac = None
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src

        for portNo, port in self.portInfo.items():
            (routerIpAddr, routerMacAddr, routerPort, routeDist) = port.get_all()
            if arp_dstIp == routerIpAddr:
                srcMac = routerMacAddr
                outPort = portNo

        if srcMac:
            self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
            LOG.debug("send ARP reply %s => %s (port%d)" % (srcMac, dstMac, outPort))
            return 0
        else:
            LOG.debug("unknown arp requst received !")
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
            self.portInfo[outPort] = PortTable(outPort, srcIp, srcMac, RouteDist)

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

    def add_flow_gateway(self, datapath, ethertype, mod_srcMac, mod_dstMac, outPort, defaultGateway):
        ipaddress = IPNetwork("0.0.0.0" + '/' + "0.0.0.0")
        prefix = str(ipaddress.cidr)
        LOG.debug("add RoutingInfo(gateway) for %s" % prefix)
        self.routingInfo[prefix] = RoutingTable(prefix, "0.0.0.0", "0.0.0.0", defaultGateway)
        match = datapath.ofproto_parser.OFPMatch(eth_type=ethertype)
        actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=mod_srcMac),
                   datapath.ofproto_parser.OFPActionSetField(eth_dst=mod_dstMac),
                   datapath.ofproto_parser.OFPActionOutput(outPort, 0),
                   datapath.ofproto_parser.OFPActionDecNwTtl()]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            cookie=0,
            cookie_mask=0,
            table_id=0,
            command=datapath.ofproto.OFPFC_ADD,
            datapath=datapath,
            idle_timeout=0,
            hard_timeout=0,
            priority=0x1,
            buffer_id=0xffffffff,
            out_port=datapath.ofproto.OFPP_ANY,
            out_group=datapath.ofproto.OFPG_ANY,
            match=match,
            instructions=inst)
        datapath.send_msg(mod)
        return 0

    def print_etherFrame(self, etherFrame):
        LOG.debug("---------------------------------------")
        LOG.debug("eth_dst_address :%s" % etherFrame.dst)
        LOG.debug("eth_src_address :%s" % etherFrame.src)
        LOG.debug("eth_ethertype :0x%04x" % etherFrame.ethertype)
        LOG.debug("---------------------------------------")

    def print_arpPacket(self, arpPacket):
        LOG.debug("arp_hwtype :%d" % arpPacket.hwtype)
        LOG.debug("arp_proto :0x%04x" % arpPacket.proto)
        LOG.debug("arp_hlen :%d" % arpPacket.hlen)
        LOG.debug("arp_plen :%d" % arpPacket.plen)
        LOG.debug("arp_opcode :%d" % arpPacket.opcode)
        LOG.debug("arp_src_mac :%s" % arpPacket.src_mac)
        LOG.debug("arp_src_ip :%s" % arpPacket.src_ip)
        LOG.debug("arp_dst_mac :%s" % arpPacket.dst_mac)
        LOG.debug("arp_dst_ip :%s" % arpPacket.dst_ip)
        LOG.debug("---------------------------------------")

    def print_ipPacket(self, ipPacket):
        LOG.debug("ip_version :%d" % ipPacket.version)
        LOG.debug("ip_header_length :%d" % ipPacket.header_length)
        LOG.debug("ip_tos :%d" % ipPacket.tos)
        LOG.debug("ip_total_length :%d" % ipPacket.total_length)
        LOG.debug("ip_identification:%d" % ipPacket.identification)
        LOG.debug("ip_flags :%d" % ipPacket.flags)
        LOG.debug("ip_offset :%d" % ipPacket.offset)
        LOG.debug("ip_ttl :%d" % ipPacket.ttl)
        LOG.debug("ip_proto :%d" % ipPacket.proto)
        LOG.debug("ip_csum :%d" % ipPacket.csum)
        LOG.debug("ip_src :%s" % ipPacket.src)
        LOG.debug("ip_dst :%s" % ipPacket.dst)
        LOG.debug("---------------------------------------")

    def print_icmp(self, icmpPacket):
        LOG.debug("icmp_type :%d", icmpPacket.type)
        LOG.debug("icmp_code :%d", icmpPacket.code)
        LOG.debug("icmp_csum :%d", icmpPacket.csum)
        LOG.debug("icmp_id :%d", icmpPacket.data.id)
        LOG.debug("icmp_seq :%d", icmpPacket.data.seq)
        LOG.debug("icmp_data :%s", icmpPacket.data.data)

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

        # TODO: Create only if not exisiting
        for switch in switch_list:
            # self.create_switch(switch)
            self.create_logical_router(switch)

        print ("l3 Switch ENTER Done")

    def create_logical_router(self, switch):
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)

        # TODO: lswitch from nb api
        router_ports = []
        for port in switch.ports:
            # network = "192.168.33.1/24",
            router_port = l3.LogicalRouterPort(lswitch="{}".format(switch.dp.id),
                                               topic="fake_tenant1",
                                               mac="{}".format(port.hw_addr),
                                               unique_key=4,
                                               id="{}:{}:{}".format(switch.dp.id, port.port_no, port.name))
            router_ports.append(router_port)

        router = l3.LogicalRouter(name="router_of_{}".format(switch.dp.id),
                                  topic="fake_tenant1",
                                  version=10,
                                  id="{}:router".format(switch.dp.id),
                                  unique_key=5,
                                  ports=router_ports)
        self.nb_api.create(router)

    def get_all_ports_of_dp(self, datapath):
        if self.nb_api is None:
             self.nb_api = api_nb.NbApi.get_instance(False)
        all_ports = self.nb_api.get_all(l2.LogicalPort)
        ports_match = []
        for port in all_ports:
            if port.lswitch.dp.id == datapath.id:
                ports_match.append(port)
        return ports_match

    def update_port_ip(self, dpid, port, ip):
        """
        Update Database with learned IPs from port
        :param dpid:
        :param port:
        :param ip:
        :return:
        """
        #TODO Connection between mac and ip of host?
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
