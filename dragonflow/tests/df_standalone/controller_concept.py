#!/usr/env/python
from dragonflow.controller import df_local_controller
from dragonflow.db import db_store
from dragonflow.db import sync
from dragonflow import conf as cfg
from dragonflow.controller.df_local_controller import init_ryu_config
from dragonflow.neutron.common import config as common_config
import sys


class DfStandaloneController(df_local_controller.DfLocalController):
    def __init__(self, chassis_name, nb_api):
        chassis_name = cfg.CONF.host

        self.db_store = db_store.get_instance()
        self.chassis_name = chassis_name
        self.nb_api = nb_api
        self.ip = cfg.CONF.df.local_ip
        self._sync = sync.Sync(
            nb_api=self.nb_api,
            update_cb=self.update,
            delete_cb=self.delete,
            selective=False,
        )





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

    def sync(self):
        #        self.topology.check_topology_info()
        self._sync.sync()

    def on_datapath_set(self):
        self._register_models()
        # self.register_chassis()
        #self.nb_api.process_changes()
