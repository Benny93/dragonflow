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

import re

from oslo_log import log
from redis import client as redis_client
from redis import exceptions

from dragonflow.common import exceptions as df_exceptions
from dragonflow.db import db_api
from dragonflow.db.drivers import redis_mgt

LOG = log.getLogger(__name__)


class RedisDbDriver(db_api.DbApi):

    RequestRetryTimes = 5

    def __init__(self):
        super(RedisDbDriver, self).__init__()
        self.clients = {}
        self.remote_server_lists = []
        self.redis_mgt = None
        self.is_neutron_server = False

    def initialize(self, db_ip, db_port, **args):
        # get remote ip port list
        self.redis_mgt = redis_mgt.RedisMgt.get_instance(db_ip, db_port)
        self._update_server_list()

    def _update_server_list(self):
        if self.redis_mgt is not None:
            self.remote_server_lists = self.redis_mgt.get_master_list()
            self.clients = {}
            for remote in self.remote_server_lists:
                remote_ip_port = remote['ip_port']
                ip_port = remote_ip_port.split(':')
                self.clients[remote_ip_port] = \
                    redis_client.StrictRedis(host=ip_port[0], port=ip_port[1])

    def create_table(self, table):
        # Not needed in redis
        pass

    def delete_table(self, table):
        local_key = self._uuid_to_key(table, '*', '*')
        for host, client in self.clients.items():
            local_keys = client.keys(local_key)
            if len(local_keys) > 0:
                for tmp_key in local_keys:
                    try:
                        self._execute_cmd("DEL", tmp_key)
                    except Exception:
                        LOG.exception("exception when delete_table: "
                                      "%(key)s ", {'key': local_key})

    def _handle_db_conn_error(self, ip_port, local_key=None):
        self.redis_mgt.remove_node_from_master_list(ip_port)
        self._update_server_list()

        if local_key is not None:
            LOG.exception("update server list, key: %(key)s",
                          {'key': local_key})

    def _sync_master_list(self):
        if self.is_neutron_server:
            result = self.redis_mgt.redis_get_master_list_from_syncstring(
                redis_mgt.RedisMgt.global_sharedlist.raw)
            if result:
                self._update_server_list()

    def _gen_args(self, local_key, value):
        args = []
        args.append(local_key)
        if value is not None:
            args.append(value)

        return args

    def _is_oper_valid(self, oper):
        if oper == 'SET' or oper == 'GET' or oper == 'DEL':
            return True

        return False

    def _update_client(self, local_key):
        self._sync_master_list()
        ip_port = self.redis_mgt.get_ip_by_key(local_key)
        client = self._get_client(local_key, ip_port)
        return client

    def _execute_cmd(self, oper, local_key, value=None):
        if not self._is_oper_valid(oper):
            LOG.warning("invalid oper: %(oper)s",
                        {'oper': oper})
            return None

        ip_port = self.redis_mgt.get_ip_by_key(local_key)
        client = self._get_client(local_key, ip_port)
        if client is None:
            return None

        arg = self._gen_args(local_key, value)

        ttl = self.RequestRetryTimes
        asking = False
        alreadysync = False
        while ttl > 0:
            ttl -= 1
            try:
                if asking:
                    client.execute_command('ASKING')
                    asking = False

                return client.execute_command(oper, *arg)
            except exceptions.ConnectionError as e:
                if not alreadysync:
                    client = self._update_client(local_key)
                    alreadysync = True
                    continue
                self._handle_db_conn_error(ip_port, local_key)
                LOG.exception("connection error while sending "
                              "request to db: %(e)s", {'e': e})
                raise e
            except exceptions.ResponseError as e:
                if not alreadysync:
                    client = self._update_client(local_key)
                    alreadysync = True
                    continue
                resp = str(e).split(' ')
                if 'ASK' in resp[0]:
                    # one-time flag to force a node to serve a query about an
                    # IMPORTING slot
                    asking = True

                if 'ASK' in resp[0] or 'MOVE' in resp[0]:
                    # MOVED/ASK XXX X.X.X.X:X
                    # do redirection
                    client = self._get_client(host=resp[2])
                    if client is None:
                        # maybe there is a fast failover
                        self._handle_db_conn_error(ip_port, local_key)
                        LOG.exception("no client available: "
                                      "%(ip_port)s, %(e)s",
                                      {'ip_port': resp[2], 'e': e})
                        raise e
                else:
                    LOG.exception("error not handled: %(e)s",
                                  {'e': e})
                    raise e
            except Exception as e:
                if not alreadysync:
                    client = self._update_client(local_key)
                    alreadysync = True
                    continue
                self._handle_db_conn_error(ip_port, local_key)
                LOG.exception("exception while sending request to "
                              "db: %(e)s", {'e': e})
                raise e

    def _find_key_without_topic(self, table, key):
        local_key = self._uuid_to_key(table, key, '*')
        self._sync_master_list()
        for client in self.clients.values():
            local_keys = client.keys(local_key)
            if len(local_keys) == 1:
                return local_keys[0]

    def get_key(self, table, key, topic=None):
        if topic:
            local_key = self._uuid_to_key(table, key, topic)
        else:
            local_key = self._find_key_without_topic(table, key)
            if local_key is None:
                raise df_exceptions.DBKeyNotFound(key=key)

        try:
            res = self._execute_cmd("GET", local_key)
            if res is not None:
                return res
        except Exception:
            LOG.exception("exception when get_key: %(key)s",
                          {'key': local_key})

        raise df_exceptions.DBKeyNotFound(key=key)

    def set_key(self, table, key, value, topic=None):
        local_key = self._uuid_to_key(table, key, topic)

        try:
            res = self._execute_cmd("SET", local_key, value)
            if res is None:
                res = 0

            return res
        except Exception:
            LOG.exception("exception when set_key: %(key)s",
                          {'key': local_key})

    def create_key(self, table, key, value, topic=None):
        return self.set_key(table, key, value, topic)

    def delete_key(self, table, key, topic=None):
        if topic:
            local_key = self._uuid_to_key(table, key, topic)
        else:
            local_key = self._find_key_without_topic(table, key)
            if local_key is None:
                raise df_exceptions.DBKeyNotFound(key=key)

        try:
            res = self._execute_cmd("DEL", local_key)
            if res is None:
                res = 0

            return res
        except Exception:
            LOG.exception("exception when delete_key: %(key)s",
                          {'key': local_key})

    def get_all_entries(self, table, topic=None):
        res = []
        ip_port = None
        self._sync_master_list()
        if not topic:
            local_key = self._uuid_to_key(table, '*', '*')
            try:
                for host, client in self.clients.items():
                    local_keys = client.keys(local_key)
                    if len(local_keys) > 0:
                        for tmp_key in local_keys:
                            res.append(self._execute_cmd("GET", tmp_key))
                return res
            except Exception:
                print "exception when get_all_entries: {}".format(
                              {'key': local_key})

        else:
            local_key = self._uuid_to_key(table, '*', topic)
            try:
                ip_port = self.redis_mgt.get_ip_by_key(local_key)
                client = self._get_client(local_key, ip_port)
                if client is None:
                    return res

                local_keys = client.keys(local_key)
                if len(local_keys) > 0:
                    res.extend(client.mget(local_keys))
                return res
            except Exception as e:
                self._handle_db_conn_error(ip_port, local_key)
                LOG.exception("exception when mget: %(key)s, %(e)s",
                              {'key': local_key, 'e': e})

    def get_all_keys(self, table, topic=None):
        res = []
        ip_port = None
        self._sync_master_list()
        if not topic:
            local_key = self._uuid_to_key(table, '*', '*')
            try:
                for host, client in self.clients.items():
                    ip_port = host
                    res.extend(client.keys(local_key))
                return [self._strip_table_name_from_key(key) for key in res]
            except Exception as e:
                self._handle_db_conn_error(ip_port, local_key)
                LOG.exception("exception when get_all_keys: %(key)s, %(e)s",
                              {'key': local_key, 'e': e})

        else:
            local_key = self._uuid_to_key(table, '*', topic)
            try:
                ip_port = self.redis_mgt.get_ip_by_key(local_key)
                client = self._get_client(local_key, ip_port)
                if client is None:
                    return res

                res = client.keys(local_key)
                return [self._strip_table_name_from_key(key) for key in res]

            except Exception as e:
                self._handle_db_conn_error(ip_port, local_key)
                LOG.exception("exception when get_all_keys: %(key)s, %(e)s",
                              {'key': local_key, 'e': e})

    def _strip_table_name_from_key(self, key):
        regex = '^{.*}\\.(.*)$'
        m = re.match(regex, key)
        return m.group(1)

    def _allocate_unique_key(self, table):
        local_key = self._uuid_to_key('unique_key', table, None)
        ip_port = None
        try:
            client = self._update_client(local_key)
            if client is None:
                return None
            return client.incr(local_key)
        except Exception as e:
            self._handle_db_conn_error(ip_port, local_key)
            LOG.exception("exception when incr: %(key)s, %(e)s",
                          {'key': local_key, 'e': e})

    def allocate_unique_key(self, table):
        try:
            return self._allocate_unique_key(table)
        except Exception as e:
            LOG.error("allocate_unique_key exception: %(e)s",
                      {'e': e})
            return

    def _uuid_to_key(self, table, key, topic):
        if not topic:
            #local_key = ('{' + table + '.' + '}' + '.' + key)
            local_key = ('{{{}.}}.{}'.format(table,key))
        else:
            #local_key = ('{' + table + '.' + topic + '}' + '.' + key)
            local_key = ('{{{}.{}}}.{}'.format(table, topic,key))
        return local_key

    def _get_client(self, key=None, host=None):
        if host is None:
            ip_port = self.redis_mgt.get_ip_by_key(key)
            if ip_port is None:
                return None
        else:
            ip_port = host

        client = self.clients.get(ip_port, None)
        if client is not None:
            return self.clients[ip_port]
        else:
            return None

    def process_ha(self):
        if self.is_neutron_server:
            self._sync_master_list()
        else:
            self._update_server_list()

    def set_neutron_server(self, is_neutron_server):
        self.is_neutron_server = is_neutron_server
