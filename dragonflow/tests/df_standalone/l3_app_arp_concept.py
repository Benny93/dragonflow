import logging

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
from dragonflow.db import db_store, api_nb
from dragonflow.db.models import l2
from dragonflow.common.exceptions import DBKeyNotFound

LOG = logging.getLogger('SimpleArp')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()

HOST_IPADDR1 = "192.168.0.1"
HOST_IPADDR2 = "192.168.1.1"
ROUTER_IPADDR1 = "192.168.33.1"
ROUTER_IPADDR2 = "192.168.34.1"
ROUTER_MACADDR1 = "00:00:00:00:00:01"
ROUTER_MACADDR2 = "00:00:00:00:00:02"
ROUTER_PORT1 = 1
ROUTER_PORT2 = 2


class SimpleArp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    HOST_MACADDR1 = None
    HOST_MACADDR2 = None

    nb_api = None

    def __init__(self, *args, **kwargs):
        super(SimpleArp, self).__init__(*args, **kwargs)

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
            datapath.ofproto.OFPCML_MAX
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)

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
            return 0
        else:
            LOG.debug("Drop packet")
            return 1

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            LOG.debug("receive ARP request %s => %s (port%d)"
                      % (etherFrame.src, etherFrame.dst, inPort))
            # DB lookup for arp reply. Saves new learned IP address
            # arpPacket.src_ip + inPort

            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            pass

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        if arp_dstIp == ROUTER_IPADDR1:
            srcMac = ROUTER_MACADDR1
            outPort = ROUTER_PORT1
        elif arp_dstIp == ROUTER_IPADDR2:
            srcMac = ROUTER_MACADDR2
            outPort = ROUTER_PORT2
        else:
            LOG.debug("unknown arp request received !")

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        LOG.debug("send ARP reply %s => %s (port%d)" % (srcMac, dstMac, outPort))

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
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

    # Database Access
    def update_port_ip(self, dpid, port, ip):
        """
        Update Database with learned IPs from port
        :param dpid:
        :param port:
        :param ip:
        :return:
        """
        if self.nb_api is None:
            self.nb_api = api_nb.NbApi.get_instance(False)
            if self.nb_api is None:
                print ("Cannot get nb api instance")
                return
        port_id = "{}:{}".format(dpid, port)
        try:
            lport = self.nb_api.get(l2.LogicalSwitch(id=port_id))
            if ip not in lport.ips:
                lport.append(ip)
                self.nb_api.update(lport)
        # TODO: Remove old ips
        except DBKeyNotFound:
            # TODO: Create Port?
            print "Key not Found!!"

    def get_port_by_ip(self, ip):
        """
        Searches Ports in Database for ip and returns matching port
        :param ip:
        :return:
        """
        if self.nb_api is None:
            self.nb_api = api_nb.get_instance(False)
            if self.nb_api is None:
                print ("Cannot get nb api instance")
                return
        lports = self.nb_api.get_all(l2.LogicalPort)
        for port in lports:
            if ip in port.ips and len(port.mac) == 1:
                return port
        return None