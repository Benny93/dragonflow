#!/usr/env/python
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, DEAD_DISPATCHER

from dragonflow.controller import df_local_controller
from dragonflow.db import db_store
from dragonflow.db import sync
from dragonflow import conf as cfg
from ryu import cfg as ryu_cfg
from dragonflow.neutron.common import config as common_config
import sys
from dragonflow.db import api_nb
from dragonflow.controller import ryu_base_app
from dragonflow.controller import service
from oslo_service import loopingcall, time
from dragonflow.common import utils as df_utils
from dragonflow.db import db_common
from ryu.base import app_manager
from ryu.app.ofctl import service as of_service

from ryu.topology.api import get_link, get_switch
from ryu.topology import event, switches
import ryu.topology.switches as topo_switches

import dragonflow.tests.df_standalone.l2_app_concept2 as concept_app

class DfStandaloneController2(df_local_controller.DfLocalController):
    def __init__(self, chassis_name, nb_api):
        chassis_name = cfg.CONF.host

        self.db_store = db_store.get_instance()
        self.chassis_name = chassis_name
        self.nb_api = nb_api
        self.ip = cfg.CONF.df.local_ip

        app_mgr = app_manager.AppManager.get_instance()
        self.open_flow_app = app_mgr.instantiate(
            ryu_base_app.RyuDFAdapter,
            nb_api=self.nb_api,
            vswitch_api=None,
            neutron_server_notifier=None,
        )
        # The OfctlService is needed to support the 'get_flows' method
        self.open_flow_service = app_mgr.instantiate(of_service.OfctlService)
        self.ryu_switches = app_mgr.instantiate(switches.Switches)
        self.simples_switch = app_mgr.instantiate(concept_app.SimpleSwitch13)
        self.enable_selective_topo_dist = \
            cfg.CONF.df.enable_selective_topology_distribution
        self._sync = sync.Sync(
            nb_api=self.nb_api,
            update_cb=self.update,
            delete_cb=self.delete,
            selective=self.enable_selective_topo_dist,
        )
        self._sync_pulse = loopingcall.FixedIntervalLoopingCall(
            self._submit_sync_event)

        self.sync_rate_limiter = df_utils.RateLimiter(
            max_rate=1, time_unit=db_common.DB_SYNC_MINIMUM_INTERVAL)

    def run(self):
        self.nb_api.register_notification_callback(self._handle_update)
        self._sync_pulse.start(
            interval=cfg.CONF.df.db_sync_time,
            initial_delay=cfg.CONF.df.db_sync_time,
        )
        self.open_flow_service.start()
        self.open_flow_app.start()
        self.ryu_switches.start()
        self.force_ryu_server()


        # def register_chassis(self):
        # Get all chassis from nb db to db store.
        # for c in self.nb_api.get_all(core.Chassis):
        #     self.db_store.update(c)

        # old_chassis = self.db_store.get_one(
        #     core.Chassis(id=self.chassis_name))

        # chassis = core.Chassis(
        #     id=self.chassis_name,
        #     ip=self.ip,
        #   tunnel_types=self.tunnel_types,
        # )
        # if cfg.CONF.df.external_host_ip:
        #    chassis.external_host_ip = cfg.CONF.df.external_host_ip

        # self.db_store.update(chassis)

        ## REVISIT (dimak) Remove skip_send_event once there is no bind conflict
        ## between publisher service and the controoler, see bug #1651643
        # if old_chassis is None:
        #    self.nb_api.create(chassis, skip_send_event=True)
        # elif old_chassis != chassis:
        #    self.nb_api.update(chassis, skip_send_event=True)

    def force_ryu_server(self):
        import gc
        from ryu.controller.ofp_handler import OpenFlowController
        objs = gc.get_objects()
        for obj in objs:
            if type(obj) is OpenFlowController:
                obj.__call__()


    def on_datapath_set(self):
        self._register_models()
        # self.register_chassis()
        # self.nb_api.process_changes()

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        print "success"

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)  # .topology_api_app
        switches = [switch.dp.id for switch in switch_list]

def init_ryu_config():
    ryu_cfg.CONF(project='ryu', args=[])
    ryu_cfg.CONF.ofp_listen_host = cfg.CONF.df_ryu.of_listen_address
    ryu_cfg.CONF.ofp_tcp_listen_port = cfg.CONF.df_ryu.of_listen_port


def main():
    chassis_name = cfg.CONF.host
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    init_ryu_config()
    nb_api = api_nb.NbApi.get_instance(False)
    controller = DfStandaloneController2(chassis_name, nb_api)
    DfStandaloneController2.instance = controller
    ryu_base_app.RyuDFAdapter.call_on_datapath_set = DfStandaloneController2.on_datapath_set
    ryu_base_app.RyuDFAdapter.ctrl = controller
    service.register_service('df-local-controller', nb_api, controller)
    controller.run()


if __name__ == "__main__":
    sys.argv.append('--config-file')
    sys.argv.append('/home/vagrant/dragonflow/etc/neutron.conf')
    sys.argv.append('--config-file')
    sys.argv.append('/home/vagrant/dragonflow/etc/dragonflow.ini')
    sys.exit(main())
