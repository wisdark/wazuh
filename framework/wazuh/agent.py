# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import hashlib
import operator
import os
import socket
from base64 import b64encode
from datetime import date, datetime, timedelta, timezone
from functools import reduce
from glob import glob
from json import loads
from os import chown, chmod, path, makedirs, urandom, listdir, stat, remove
from platform import platform
from shutil import copyfile, rmtree
from time import time, sleep
from typing import Dict

import requests

from wazuh import common, configuration
from wazuh.InputValidator import InputValidator
from wazuh.cluster.utils import get_manager_status
from wazuh.database import Connection
from wazuh.exception import WazuhException
from wazuh.ossec_queue import OssecQueue
from wazuh.ossec_socket import OssecSocket, OssecSocketJSON
from wazuh.utils import cut_array, sort_array, search_array, chmod_r, chown_r, WazuhVersion, \
    plain_dict_to_nested_dict, get_fields_to_nest, get_hash, WazuhDBQuery, WazuhDBQueryDistinct, WazuhDBQueryGroupBy, \
    mkdir_with_mode, md5, SQLiteBackend, WazuhDBBackend, filter_array_by_query, safe_move


def create_exception_dic(id, e):
    """
    Creates a dictionary with a list of agent ids and it's error codes.
    """
    exception_dic = {}
    exception_dic['id'] = id
    exception_dic['error'] = {'message': e.message}

    if isinstance(e, WazuhException):
        exception_dic['error']['code'] = e.code
    else:
        exception_dic['error']['code'] = 1000


    return exception_dic


class WazuhDBQueryAgents(WazuhDBQuery):

    def __init__(self, offset, limit, sort, search, select, count, get_data, query, filters={}, default_sort_field='id',
                 min_select_fields={'lastKeepAlive', 'version', 'id'}, remove_extra_fields=True, distinct=False):
        backend = SQLiteBackend(common.database_path_global)
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='agent', sort=sort, search=search, select=select, filters=filters,
                              fields=Agent.fields, default_sort_field=default_sort_field, default_sort_order='ASC', query=query,
                              min_select_fields=min_select_fields, count=count, get_data=get_data, backend=backend,
                              date_fields={'lastKeepAlive','dateAdd'}, extra_fields={'internal_key'}, distinct=distinct)
        self.remove_extra_fields = remove_extra_fields

    def _filter_status(self, status_filter):
        # set the status value to lowercase in case it's a string. If not, the value will be return unmodified.
        status_filter['value'] = getattr(status_filter['value'], 'lower', lambda: status_filter['value'])()
        result = datetime.utcnow() - timedelta(seconds=common.limit_seconds)
        self.request['time_active'] = result.replace(tzinfo=timezone.utc).timestamp()
        if status_filter['operator'] == '!=':
            self.query += 'NOT '

        if status_filter['value'] == 'active':
            self.query += '(last_keepalive >= :time_active AND version IS NOT NULL) or id = 0'
        elif status_filter['value'] == 'disconnected':
            self.query += 'last_keepalive < :time_active'
        elif status_filter['value'] == "never connected" or status_filter['value'] == "neverconnected":
            self.query += 'last_keepalive IS NULL AND id != 0'
        elif status_filter['value'] == 'pending':
            self.query += 'last_keepalive IS NOT NULL AND version IS NULL'
        else:
            raise WazuhException(1729, status_filter['value'])


    def _filter_date(self, date_filter, filter_db_name):
        WazuhDBQuery._filter_date(self, date_filter, filter_db_name)
        self.query = self.query[:-1] + ' AND id != 0'


    def _sort_query(self, field):
        if field == 'status':
            # Order by status ASC is the same that order by last_keepalive DESC.
            return '{} {}'.format('last_keepAlive', self.sort['order'])
        elif field == 'os.version':
            return "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(self.sort['order'])
        else:
            return WazuhDBQuery._sort_query(self, field)


    def _add_search_to_query(self):
        # since id are stored in database as integers, id searches must be turned into integers to work as expected.
        if self.search:
            del self.fields['id']
            WazuhDBQuery._add_search_to_query(self)
            self.fields['id'] = 'id'
            self.query = self.query[:-1] + ' OR id LIKE :search_id)'
            self.request['search_id'] = int(self.search['value']) if self.search['value'].isdigit() else self.search['value']

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value, today, lastKeepAlive=None, version=None):
            if field_name == 'id':
                return str(value).zfill(3)
            elif field_name == 'status':
                return Agent.calculate_status(lastKeepAlive, version is None, today)
            elif field_name == 'group':
                return value.split(',')
            elif field_name in ['dateAdd', 'lastKeepAlive']:
                return datetime.utcfromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
            else:
                return value

        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

        today = datetime.utcnow()

        # compute 'status' field, format id with zero padding and remove non-user-requested fields.
        # Also remove, extra fields (internal key and registration IP)
        selected_fields = self.select['fields'] - self.extra_fields if self.remove_extra_fields else self.select['fields']
        selected_fields |= {'id'}
        self._data = [{key: format_fields(key, value, today, item.get('lastKeepAlive'), item.get('version'))
                        for key, value in item.items() if key in selected_fields} for item in self._data]

        self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in self._data]

        return super()._format_data_into_dictionary()

    def _parse_legacy_filters(self):
        if 'older_than' in self.legacy_filters:
            if self.legacy_filters['older_than'] is not None:
                self.q += (';' if self.q else '') + "(lastKeepAlive>{0};status!=neverconnected,dateAdd>{0};status=neverconnected)".format(self.legacy_filters['older_than'])
            del self.legacy_filters['older_than']
        WazuhDBQuery._parse_legacy_filters(self)

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name == 'group' and q_filter['value'] is not None:
            field_filter_1, field_filter_2, field_filter_3 = field_filter+'_1', field_filter+'_2', field_filter+'_3'
            self.query += '{0} LIKE :{1} OR {0} LIKE :{2} OR {0} LIKE :{3} OR {0} = :{4}'.format(self.fields[field_name], field_filter_1, field_filter_2, field_filter_3, field_filter)
            self.request[field_filter_1] = '%,'+q_filter['value']
            self.request[field_filter_2] = q_filter['value']+',%'
            self.request[field_filter_3] = '%,{},%'.format(q_filter['value'])
            self.request[field_filter] = q_filter['value']
        else:
            WazuhDBQuery._process_filter(self, field_name, field_filter, q_filter)


class WazuhDBQueryDistinctAgents(WazuhDBQueryDistinct, WazuhDBQueryAgents): pass


class WazuhDBQueryGroupByAgents(WazuhDBQueryGroupBy, WazuhDBQueryAgents):
    def __init__(self, filter_fields, *args, **kwargs):
        WazuhDBQueryAgents.__init__(self, *args, **kwargs)
        WazuhDBQueryGroupBy.__init__(self, table=self.table, fields=self.fields, filter_fields=filter_fields,
                                     default_sort_field=self.default_sort_field, backend=self.backend, *args, **kwargs)
        self.remove_extra_fields = True


class WazuhDBQueryMultigroups(WazuhDBQueryAgents):
    def __init__(self, group_id, query, *args, **kwargs):
        self.group_id = group_id
        query = 'group={}'.format(group_id) + (';'+query if query else '')
        WazuhDBQueryAgents.__init__(self, query=query, *args, **kwargs)

    def _default_query(self):
        return "SELECT {0} FROM agent a LEFT JOIN belongs b ON a.id = b.id_agent" if self.group_id != "null" else "SELECT {0} FROM agent a"

    def _default_count_query(self):
        return 'COUNT(DISTINCT a.id)'

    def _get_total_items(self):
        self.total_items = self.backend.execute(self.query.format(self._default_count_query()), self.request, True)
        self.query += ' GROUP BY a.id '


class Agent:
    """
    OSSEC Agent object.
    """

    fields = {'id': 'id', 'name': 'name', 'ip': 'coalesce(ip,register_ip)', 'status': 'status',
              'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform',
              'version': 'version', 'manager': 'manager_host', 'dateAdd': 'date_add',
              'group': '`group`', 'mergedSum': 'merged_sum', 'configSum': 'config_sum',
              'os.codename': 'os_codename', 'os.major': 'os_major', 'os.minor': 'os_minor',
              'os.uname': 'os_uname', 'os.arch': 'os_arch', 'os.build':'os_build',
              'node_name': 'node_name', 'lastKeepAlive': 'last_keepalive', 'internal_key':'internal_key',
              'registerIP': 'register_ip'}


    def __init__(self, id=None, name=None, ip=None, key=None, force=-1):
        """
        Initialize an agent.
        'id': When the agent exists
        'name' and 'ip': Add an agent (generate id and key automatically)
        'name', 'ip' and 'force': Add an agent (generate id and key automatically), removing old agent with same IP if disconnected since <force> seconds.
        'name', 'ip', 'id', 'key': Insert an agent with an existent id and key
        'name', 'ip', 'id', 'key', 'force': Insert an agent with an existent id and key, removing old agent with same IP if disconnected since <force> seconds.
        """
        self.id            = id
        self.name          = name
        self.ip            = ip
        self.internal_key  = key
        self.os            = {}
        self.version       = None
        self.dateAdd       = None
        self.lastKeepAlive = None
        self.status        = None
        self.key           = None
        self.configSum     = None
        self.mergedSum     = None
        self.group         = None
        self.manager       = None
        self.node_name     = None
        self.registerIP    = ip

        # if the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name != None and ip != None:
            self._add(name=name, ip=ip, id=id, key=key, force=force)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os,
                      'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive,
                      'status': self.status, 'key': self.key, 'configSum': self.configSum, 'mergedSum': self.mergedSum,
                      'group': self.group, 'manager': self.manager, 'node_name': self.node_name }

        return dictionary


    @staticmethod
    def calculate_status(last_keep_alive, pending, today=datetime.utcnow()):
        """
        Calculates state based on last keep alive
        """
        if not last_keep_alive:
            return "Never connected"
        else:
            last_date = datetime.utcfromtimestamp(last_keep_alive)
            difference = (today - last_date).total_seconds()
            return "Disconnected" if difference > common.limit_seconds else ("Pending" if pending else "Active")


    def _load_info_from_DB(self, select=None):
        """
        Gets attributes of existing agent.
        """
        db_query = WazuhDBQueryAgents(offset=0,limit=None,sort=None,search=None,select=select,
                                      query="id={}".format(self.id),count=False,get_data=True, remove_extra_fields=False)
        try:
            data = db_query.run()['items'][0]
        except IndexError:
            raise WazuhException(1701, self.id)

        list(map(lambda x: setattr(self, x[0], x[1]), data.items()))


    def get_basic_information(self, select=None):
        """
        Gets public attributes of existing agent.
        """
        self._load_info_from_DB(select)
        fields = set(self.fields.keys()) & set(select['fields']) if select is not None \
                                                                 else set(self.fields.keys()) - {'internal_key'}
        return {field:getattr(self,field) for field in map(lambda x: x.split('.')[0], fields) if getattr(self,field)}


    def compute_key(self):
        str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.registerIP, self.internal_key)
        return b64encode(str_key.encode()).decode()

    def get_key(self):
        """
        Gets agent key.

        :return: Agent key.
        """
        self._load_info_from_DB()
        if self.id != "000":
            self.key = self.compute_key()
        else:
            raise WazuhException(1703)

        return self.key


    def restart(self):
        """
        Restarts the agent.

        :return: Message generated by OSSEC.
        """

        if self.id == "000":
            raise WazuhException(1703)
        else:
            # Check if agent exists and it is active
            agent_info = self.get_basic_information()

            if self.status.lower() != 'active':
                raise WazuhException(1707, '{0} - {1}'.format(self.id, self.status))

            # Check if agent has active-response disabled
            agent_conf = self.get_config(self.id, 'com', 'active-response')
            if agent_conf['active-response']['disabled'] == 'yes':
                raise WazuhException(1750)
            else:
                oq = OssecQueue(common.ARQUEUE)
                ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS, self.id)
                oq.close()

        return ret_msg


    def use_only_authd(self):
        """
        Function to know the value of the option "use_only_authd" in API configuration
        """
        try:
            with open(common.api_config_path) as f:
                data = f.readlines()

            use_only_authd = list(filter(lambda x: x.strip().startswith('config.use_only_authd'), data))

            return loads(use_only_authd[0][:-2].strip().split(' = ')[1]) if use_only_authd != [] else False
        except IOError:
            return False


    def remove(self, backup=False, purge=False):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        manager_status = get_manager_status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if self.use_only_authd():
            if not is_authd_running:
                raise WazuhException(1726)

        if not is_authd_running:
            data = self._remove_manual(backup, purge)
        else:
            data = self._remove_authd(purge)

        return data


    def _remove_authd(self, purge=False):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        msg = { "function": "remove", "arguments": { "id": str(self.id).zfill(3), "purge": purge } }

        authd_socket = OssecSocketJSON(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _remove_manual(self, backup=False, purge=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """
        # Check if agent exists
        self._load_info_from_DB()

        f_keys_temp = '{0}.tmp'.format(common.client_keys)

        try:
            agent_found = False
            with open(common.client_keys) as client_keys, open(f_keys_temp, 'w') as client_keys_tmp:
                try:
                    for line in client_keys.readlines():
                        id, name, ip, key = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key
                        if self.id == id and name[0] not in ('#!'):
                            if not purge:
                                client_keys_tmp.write('{0} !{1} {2} {3}\n'.format(id, name, ip, key))

                            agent_found = True
                        else:
                            client_keys_tmp.write(line)
                except Exception as e:
                    remove(f_keys_temp)
                    raise e

            if not agent_found:
                remove(f_keys_temp)
                raise WazuhException(1701, self.id)
            else:
                f_keys_st = stat(common.client_keys)
                chown(f_keys_temp, common.ossec_uid(), common.ossec_gid())
                chmod(f_keys_temp, f_keys_st.st_mode)
        except Exception as e:
            raise WazuhException(1746, str(e))

        # Tell wazuhbd to delete agent database
        wdb_conn = WazuhDBBackend(self.id).connect_to_db()
        wdb_conn.delete_agents_db([self.id])

        try:
            # remove agent from groups
            db_global = glob(common.database_path_global)
            if not db_global:
                raise WazuhException(1600)

            conn = Connection(db_global[0])
            conn.execute('delete from belongs where id_agent = :id_agent', {'id_agent': int(self.id)})
            conn.commit()
        except Exception as e:
            raise WazuhException(1747, str(e))

        try:
            # Remove rid file
            rids_file = path.join(common.ossec_path, 'queue/rids', self.id)
            if path.exists(rids_file):
                remove(rids_file)

            if backup:
                # Create backup directory
                # /var/ossec/backup/agents/yyyy/Mon/dd/id-name-ip[tag]
                date_part = date.today().strftime('%Y/%b/%d')
                main_agent_backup_dir = path.join(common.backup_path,
                                                  f'agents/{date_part}/{self.id}-{self.name}-{self.registerIP}')
                agent_backup_dir = main_agent_backup_dir

                not_agent_dir = True
                i = 0
                while not_agent_dir:
                    if path.exists(agent_backup_dir):
                        i += 1
                        agent_backup_dir = '{0}-{1}'.format(main_agent_backup_dir, str(i).zfill(3))
                    else:
                        makedirs(agent_backup_dir)
                        chmod_r(agent_backup_dir, 0o750)
                        not_agent_dir = False
            else:
                agent_backup_dir = ''

            # Move agent file
            agent_files = [
                ('{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.registerIP), '{0}/agent-info'.format(agent_backup_dir)),
                ('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.registerIP), '{0}/rootcheck'.format(agent_backup_dir)),
                ('{0}/queue/agent-groups/{1}'.format(common.ossec_path, self.id), '{0}/agent-group'.format(agent_backup_dir)),
                ('{}/var/db/agents/{}-{}.db'.format(common.ossec_path, self.name, self.id), '{}/var_db'.format(agent_backup_dir)),
                ('{}/queue/diff/{}'.format(common.ossec_path, self.name), '{}/diff'.format(agent_backup_dir))
            ]

            for agent_file, backup_file in agent_files:
                if path.exists(agent_file):
                    if not backup:
                        if path.isdir(agent_file):
                            rmtree(agent_file)
                        else:
                            remove(agent_file)
                    elif not path.exists(backup_file):
                        safe_move(agent_file, backup_file, permissions=0o660)

            # Overwrite client.keys
            safe_move(f_keys_temp, common.client_keys, permissions=0o640)
        except Exception as e:
            raise WazuhException(1748, str(e))

        return 'Agent deleted successfully.'


    def _add(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """
        manager_status = get_manager_status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if self.use_only_authd():
            if not is_authd_running:
                raise WazuhException(1726)

        if not is_authd_running:
            data = self._add_manual(name, ip, id, key, force)
        else:
            data = self._add_authd(name, ip, id, key, force)

        return data


    def _add_authd(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC using authd.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise WazuhException(1709)

        force = force if type(force) == int else int(force)

        msg = ""
        if name and ip:
            if id and key:
                msg = {"function": "add", "arguments": {"name": name, "ip": ip, "id": id, "key": key, "force": force}}
            else:
                msg = {"function": "add", "arguments": {"name": name, "ip": ip, "force": force}}

        authd_socket = OssecSocketJSON(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        self.id  = data['id']
        self.internal_key = data['key']
        self.key = self.compute_key()


    def _add_manual(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC manually.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise WazuhException(1709)

        force = force if type(force) == int else int(force)

        # Check manager name
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        conn.execute("SELECT name FROM agent WHERE (id = 0)")
        manager_name = str(conn.fetch())

        if name == manager_name:
            raise WazuhException(1705, name)

        # Check if ip, name or id exist in client.keys
        last_id = 0
        lock_file = open("{}/var/run/.api_lock".format(common.ossec_path), 'a+')
        fcntl.lockf(lock_file, fcntl.LOCK_EX)
        with open(common.client_keys) as f_k:
            try:
                for line in f_k.readlines():
                    if not line.strip():  # ignore empty lines
                        continue

                    if line[0] in ('# '):  # starts with # or ' '
                        continue

                    line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                    line_id = int(line_data[0])
                    if last_id < line_id:
                        last_id = line_id

                    if line_data[1][0] in ('#!'):  # name starts with # or !
                        continue

                    check_remove = 0
                    if id and id == line_data[0]:
                        raise WazuhException(1708, id)
                    if name == line_data[1]:
                        if force < 0:
                            raise WazuhException(1705, name)
                        else:
                            check_remove = 1
                    if ip != 'any' and ip == line_data[2]:
                        if force < 0:
                            raise WazuhException(1706, ip)
                        else:
                            check_remove = 2

                    if check_remove:
                        if force == 0 or Agent.check_if_delete_agent(line_data[0], force):
                            Agent.remove_agent(line_data[0], backup=True)
                        else:
                            if check_remove == 1:
                                raise WazuhException(1705, name)
                            else:
                                raise WazuhException(1706, ip)


                if not id:
                    agent_id = str(last_id + 1).zfill(3)
                else:
                    agent_id = id

                if not key:
                    # Generate key
                    epoch_time = int(time())
                    str1 = "{0}{1}{2}".format(epoch_time, name, platform())
                    str2 = "{0}{1}".format(ip, agent_id)
                    hash1 = hashlib.md5(str1.encode())
                    hash1.update(urandom(64))
                    hash2 = hashlib.md5(str2.encode())
                    hash1.update(urandom(64))
                    agent_key = hash1.hexdigest() + hash2.hexdigest()
                else:
                    agent_key = key

                # Tmp file
                f_keys_temp = '{0}.tmp'.format(common.client_keys)
                open(f_keys_temp, 'a').close()

                f_keys_st = stat(common.client_keys)
                chown(f_keys_temp, common.ossec_uid(), common.ossec_gid())
                chmod(f_keys_temp, f_keys_st.st_mode)

                copyfile(common.client_keys, f_keys_temp)


                # Write key
                with open(f_keys_temp, 'a') as f_kt:
                    f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

                # Overwrite client.keys
                safe_move(f_keys_temp, common.client_keys, permissions=f_keys_st.st_mode)
            except WazuhException as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise ex
            except Exception as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise WazuhException(1725, str(ex))


            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

        self.id = agent_id
        self.internal_key = agent_key
        self.key = self.compute_key()


    @staticmethod
    def _remove_single_group(group_id):
        """
        Remove the group in every agent.

        :param group_id: Group ID.
        :return: Confirmation message.
        """

        if group_id.lower() == "default":
            raise WazuhException(1712)

        if not Agent.group_exists(group_id):
            raise WazuhException(1710, group_id)

        ids = list(map(operator.itemgetter('id'), Agent.get_agent_group(group_id=group_id, limit=None)['items']))

        # Remove group directory
        group_path = "{0}/{1}".format(common.shared_path, group_id)
        group_backup = "{0}/groups/{1}_{2}".format(common.backup_path, group_id, int(time()))
        if path.exists(group_path):
            safe_move(group_path, group_backup, permissions=0o660)

        msg = "Group '{0}' removed.".format(group_id)

        return {'msg': msg, 'affected_agents': ids}


    def get_agent_attr(self, attr):
        """
        Returns a string with an agent's os name
        """
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        query = "SELECT :attr FROM agent WHERE id = :id"
        request = {'attr':attr, 'id': self.id}
        conn.execute(query, request)
        query_value = str(conn.fetch())

        return query_value


    @staticmethod
    def get_agents_overview(offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}, q=""):
        """
        Gets a list of available agents with basic attributes.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        :param q: Defines query to filter in DB.

        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select, filters=filters, query=q, count=True, get_data=True)

        data = db_query.run()

        return data


    @staticmethod
    def get_distinct_agents(offset=0, limit=common.database_limit, sort=None, search=None, select=None, fields=None, q=""):
        """
        Gets a list of available agents with basic attributes.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param q: Defines query to filter in DB.
        :param fields: Fields to group by
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        db_query = WazuhDBQueryGroupByAgents(filter_fields=fields, offset=offset, limit=limit, sort=sort, search=search, select=select, query=q,
                                             count=True, get_data=True, min_select_fields=set())
        return db_query.run()


    @staticmethod
    def get_agents_summary():
        """
        Counts the number of agents by status.

        :return: Dictionary with keys: total, Active, Disconnected, Never connected
        """
        db_query = WazuhDBQueryAgents(offset=0,limit=None,sort=None,search=None,select=None,count=True,get_data=False,query="")

        db_query.run()
        data = {'Total':db_query.total_items}

        for status in ['Active','Disconnected','Never connected','Pending']:
            db_query.reset()

            db_query.q = "status="+status
            db_query.run()
            data[status] = db_query.total_items

        return data


    @staticmethod
    def get_os_summary(offset=0, limit=common.database_limit, sort=None, search=None, q=""):
        """
        Gets a list of available OS.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param q: Query to filter results.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search,
                                      select={'fields':['os.platform']}, count=True, get_data=True,
                                      default_sort_field='os_platform', query=q, min_select_fields=set(), distinct=True)
        return db_query.run()


    @staticmethod
    def restart_agents(agent_id=None, restart_all=False):
        """
        Restarts an agent or all agents.

        :param agent_id: Agent ID of the agent to restart. Can be a list of ID's.
        :param restart_all: Restarts all agents.

        :return: Message.
        """

        if restart_all:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS)
            oq.close()
            return ret_msg
        else:
            if not agent_id:
                raise WazuhException(1732)
            failed_ids = list()
            affected_agents = list()
            if isinstance(agent_id, list):
                for id in agent_id:
                    try:
                        Agent(id).restart()
                        affected_agents.append(id)
                    except Exception as e:
                        failed_ids.append(create_exception_dic(id, e))
            else:
                try:
                    Agent(agent_id).restart()
                    affected_agents.append(agent_id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(agent_id, e))
            if not failed_ids:
                message = 'All selected agents were restarted'
            else:
                message = 'Some agents were not restarted'

            final_dict = {}
            if failed_ids:
                final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
            else:
                final_dict = {'msg': message, 'affected_agents': affected_agents}

            return final_dict

    @staticmethod
    def get_agent_by_name(agent_name, select=None):
        """
        Gets an existing agent called agent_name.

        :param agent_name: Agent name.
        :return: The agent.
        """
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        conn.execute("SELECT id FROM agent WHERE name = :name", {'name': agent_name})
        try:
            agent_id = str(conn.fetch()).zfill(3)
        except TypeError as e:
            raise WazuhException(1701, agent_name)

        return Agent(agent_id).get_basic_information(select)


    @staticmethod
    def get_agent(agent_id, select=None):
        """
        Gets an existing agent.

        :param agent_id: Agent ID.
        :return: The agent.
        """

        return Agent(agent_id).get_basic_information(select)


    @staticmethod
    def get_agent_key(agent_id):
        """
        Get the key of an existing agent.

        :param agent_id: Agent ID.
        :return: Agent key.
        """

        return Agent(agent_id).get_key()

    @staticmethod
    def get_group_by_name(group_name, select=None):
        """
        Gets an existing group called group_name.

        :param group_name: Group name.
        :return: The group id.
        """
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        conn.execute("SELECT id FROM `group` WHERE name = :name", {'name': group_name})
        try:
            group_id = conn.fetch()
        except TypeError as e:
            raise WazuhException(1701, group_name)

        return group_id



    @staticmethod
    def remove_agent(agent_id, backup=False, purge=False):
        """
        Removes an existing agent.

        :param agent_id: Agent ID.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Dictionary with affected_agents (agents removed), failed_ids if it necessary (agents that cannot been removed), and a message.
        """

        failed_ids = []
        affected_agents = []
        try:
            Agent(agent_id).remove(backup, purge)
            affected_agents.append(agent_id)
        except Exception as e:
            failed_ids.append(create_exception_dic(agent_id, e))

        if not failed_ids:
            message = 'All selected agents were removed'
        else:
            message = 'Some agents were not removed'

        final_dict = {}
        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents}

        return final_dict


    @staticmethod
    def remove_agents(list_agent_ids="all", backup=False, purge=False, status="all", older_than="7d"):
        """
        Removes an existing agent.

        :param list_agent_ids: List of agents ID's.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :param older_than:  Filters out disconnected agents for longer than specified. Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s". For never connected agents, uses the register date.
        :param status: Filters by agent status: Active, Disconnected or Never connected. Multiples statuses separated by commas.
        :return: Dictionary with affected_agents (agents removed), timeframe applied, failed_ids if it necessary (agents that cannot been removed), and a message.
        """

        id_purgeable_agents = list(map(operator.itemgetter('id'),
                                       Agent.get_agents_overview(filters={'older_than':older_than,'status':status},
                                                                 limit = None)['items']))

        failed_ids = []
        affected_agents = []

        if list_agent_ids != "all":
            for id in list_agent_ids:
                try:
                    my_agent = Agent(id)
                    my_agent._load_info_from_DB()
                    if id not in id_purgeable_agents:
                        raise WazuhException(1731, "The agent has a status different to '{}' or the specified time frame 'older_than {}' does not apply.".format(status, older_than))
                    my_agent.remove(backup, purge)
                    affected_agents.append(id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))
        else:
            for id in id_purgeable_agents:
                try:
                    my_agent = Agent(id)
                    my_agent._load_info_from_DB()
                    my_agent.remove(backup, purge)
                    affected_agents.append(id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))

        if not failed_ids:
            message = 'All selected agents were removed' if affected_agents else "No agents were removed"
        else:
            message = 'Some agents were not removed'

        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids,
                          'older_than': older_than, 'total_affected_agents':len(affected_agents),
                          'total_failed_ids':len(failed_ids)}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'older_than': older_than,
                          'total_affected_agents':len(affected_agents)}

        return final_dict


    @staticmethod
    def add_agent(name, ip='any', force=-1):
        """
        Adds a new agent to OSSEC.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """
        # check length of agent name
        if len(name) > 128:
            raise WazuhException(1738)

        new_agent = Agent(name=name, ip=ip, force=force)
        return {'id': new_agent.id, 'key': new_agent.key}

    @staticmethod
    def add_group_to_agent(agent_id,group_id,force=False):
        """
        Adds an existing group to an agent

        :param group_id: name of the group.
        :param agent_id: ID of the agent.
        :param force: No check if agent exists
        :return: Agent ID.
        """
        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        # get agent's group
        group_path = "{}/{}".format(common.groups_path, agent_id)
        if path.exists(group_path):
            with open(group_path) as f:
                group_name = f.read().replace('\n', '')

            # Check if the group already belongs to the agent
            if group_id in group_name.split(','):
                return "Agent '{0}' already belongs to group '{1}'.".format(agent_id, group_id)
        else:
            group_name = ""

        agent_group = (group_name + ',' if group_name else '') + group_id
        old_agent_group = group_name

        # Check multigroup limit
        if Agent().check_multigroup_limit(agent_id):
            raise WazuhException(1737)

        # Check if the group exists
        if not Agent.group_exists(group_id):
            raise WazuhException(1710, group_id)

        Agent().set_multi_group(str(agent_id), agent_group)

        # Check if the multigroup still exists in other agents
        multi_group_list = []
        for filename in listdir("{0}".format(common.groups_path)):
            file = open("{0}/{1}".format(common.groups_path,filename),"r")
            group_read = file.read()
            group_read = group_read.strip()
            multi_group_list.append(group_read)
            file.close()

        return "Group '{0}' added to agent '{1}'.".format(group_id, agent_id)



    @staticmethod
    def insert_agent(name, id, key, ip='any', force=-1):
        """
        Create a new agent providing the id, name, ip and key to the Manager.

        :param id: id of the new agent.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param key: name of the new agent.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        new_agent = Agent(name=name, ip=ip, id=id, key=key, force=force)
        return {'id': new_agent.id, 'key': new_agent.compute_key()}


    @staticmethod
    def check_if_delete_agent(id, seconds):
        """
        Check if we should remove an agent: if time from last connection is greater thant <seconds>.

        :param id: id of the new agent.
        :param seconds: Number of seconds.
        :return: True if time from last connection is greater thant <seconds>.
        """
        remove_agent = False

        agent_info = Agent(id=id).get_basic_information()

        if 'lastKeepAlive' in agent_info:
            if agent_info['lastKeepAlive'] == 0:
                remove_agent = True
            else:
                last_date = datetime.strptime(agent_info['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                difference = (datetime.utcnow() - last_date).total_seconds()
                if difference >= seconds:
                    remove_agent = True

        return remove_agent


    @staticmethod
    def get_all_groups_sql(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets the existing groups.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        db_query = WazuhDBQueryDistinct(offset=offset, limit=limit, sort=sort, search=search, select={'fields':['name']},
                                        fields={'name':'`group`'}, count=True, get_data=True,
                                        db_path=common.database_path_global, default_sort_field='`group`', table='agent')
        db_query.run()

        return {'totalItems': db_query.total_items, 'items': [tuple[0] for tuple in db_query.conn]}


    @staticmethod
    def get_all_groups(offset=0, limit=common.database_limit, sort=None, search=None, filters={}, q=''):
        """
        Gets the existing groups.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}.
            This filter is used to set hash algorithm for getting mergedsum and configsum in this method.
        :param q: Defines query to filter.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # set hash algorithm used to get mergedsum and configsum, 'md5' by default
        hash_algorithm = filters['hash'] if 'hash' in filters else 'md5'
        try:
            # Connect DB
            db_global = glob(common.database_path_global)
            if not db_global:
                raise WazuhException(1600)

            conn = Connection(db_global[0])

            # Group names
            data = []
            for entry in listdir(common.shared_path):
                full_entry = path.join(common.shared_path, entry)
                if not path.isdir(full_entry):
                    continue

                # Get the id of the group
                query = "SELECT id FROM `group` WHERE name = :group_id"
                request = {'group_id': entry}
                conn.execute(query, request)
                id_group = conn.fetch()

                if id_group is None:
                    continue

                # Group count
                query = "SELECT {0} FROM belongs WHERE id_group = :id"
                request = {'id': id_group}
                conn.execute(query.format('COUNT(*)'), request)

                # merged.mg and agent.conf sum
                merged_sum = get_hash(full_entry + "/merged.mg", hash_algorithm)
                conf_sum   = get_hash(full_entry + "/agent.conf", hash_algorithm)

                item = {'count': conn.fetch(), 'name': entry}

                if merged_sum:
                    item['mergedSum'] = merged_sum

                if conf_sum:
                    item['configSum'] = conf_sum

                data.append(item)


            if search:
                data = search_array(data, search['value'], search['negation'], fields=['name'])

            if q:
                data = filter_array_by_query(q, data)

            if sort:
                data = sort_array(data, sort['fields'], sort['order'])
            else:
                data = sort_array(data, ['name'])
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhException(1736, str(e))

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}


    @staticmethod
    def group_exists_sql(group_id):
        """
        Checks if the group exists

        :param group_id: Group ID.
        :return: True if group exists, False otherwise
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        db_query = WazuhDBQueryAgents(offset=0, limit=None, sort=None, search=None, select={'fields':['group']},
                                      query="group="+group_id, count=True, get_data=False)
        db_query.run()

        return bool(db_query.total_items)


    @staticmethod
    def group_exists(group_id):
        """
        Checks if the group exists

        :param group_id: Group ID.
        :return: True if group exists, False otherwise
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        if path.exists("{0}/{1}".format(common.shared_path, group_id)):
            return True
        else:
            return False


    @staticmethod
    def multi_group_exists(group_id):
        """
        Checks if the group exists

        :param group_id: Group ID.
        :return: String of groups if group exists, an empty list otherwise
        """

        all_multigroups = []
        for file in listdir(common.groups_path):
            filepath = path.join(common.groups_path, file)
            f = open(filepath, 'r')
            all_multigroups.append(f.read())
            f.close()
        if group_id in all_multigroups:
            return all_multigroups
        else:
            return []


    @staticmethod
    def get_agent_group(group_id, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}, q=""):
        """
        Gets the agents in a group

        :param group_id: Group ID.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # check whether the group exists or not
        if group_id != 'null' and not glob("{}/{}".format(common.shared_path, group_id)) and not glob("{}/{}".format(common.multi_groups_path, group_id)):
            raise WazuhException(1710, group_id)

        db_query = WazuhDBQueryMultigroups(group_id=group_id, offset=offset, limit=limit, sort=sort, search=search, select=select, filters=filters,
                                           count=True, get_data=True, query=q)
        return db_query.run()


    @staticmethod
    def get_agents_without_group(offset=0, limit=common.database_limit, sort=None, search=None, select=None, q="", filters={}):
        """
        Gets the agents without a group

        :param group_id: Group ID.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param filters: Values to filter by on database (legacy format).
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Agent.get_agent_group(group_id="null", offset=offset, limit=limit, sort=sort, search=search, select=select,
                                     q='id!=0'+(';'+q if q else ''), filters=filters)


    @staticmethod
    def get_group_files(group_id=None, offset=0, limit=common.database_limit, sort=None, search=None, hash_algorithm='md5'):
        """
        Gets the group files.

        :param group_id: Group ID.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        group_path = common.shared_path
        if group_id:
            if not Agent.group_exists(group_id):
                raise WazuhException(1710, group_id)
            group_path = "{0}/{1}".format(common.shared_path, group_id)

        if not path.exists(group_path):
            raise WazuhException(1006, group_path)

        try:
            data = []
            for entry in listdir(group_path):
                item = {}
                try:
                    item['filename'] = entry
                    item['hash'] = get_hash('{}/{}'.format(group_path, entry), hash_algorithm)
                    data.append(item)
                except (OSError, IOError) as e:
                    pass

            try:
                # ar.conf
                ar_path = "{0}/ar.conf".format(common.shared_path)
                data.append({'filename': "ar.conf", 'hash': get_hash(ar_path, hash_algorithm)})
            except (OSError, IOError) as e:
                pass

            if search:
                data = search_array(data, search['value'], search['negation'])

            if sort:
                data = sort_array(data, sort['fields'], sort['order'])
            else:
                data = sort_array(data, ["filename"])

            return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhException(1727, str(e))


    @staticmethod
    def create_group(group_id):
        """
        Creates a group.

        :param group_id: Group ID.
        :return: Confirmation message.
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        group_path = "{0}/{1}".format(common.shared_path, group_id)

        if group_id.lower() == "default" or path.exists(group_path):
            raise WazuhException(1711, group_id)

        # Create group in /etc/shared
        group_def_path = "{0}/agent-template.conf".format(common.shared_path)
        try:
            mkdir_with_mode(group_path)
            copyfile(group_def_path, group_path + "/agent.conf")
            chown_r(group_path, common.ossec_uid(), common.ossec_gid())
            chmod_r(group_path, 0o660)
            chmod(group_path, 0o770)
            msg = "Group '{0}' created.".format(group_id)
        except Exception as e:
            raise WazuhException(1005, str(e))

        return msg

    @staticmethod
    def remove_multi_group(groups_id):
        """
        Removes groups by IDs.

        :param groups_id: list with Groups ID.
        """
        groups_to_remove = []
        for agent_id in listdir("{0}".format(common.groups_path)):
            agent_group = Agent.get_agents_group_file(agent_id)

            new_group = ''
            group_list = agent_group.split(',')
            for group_to_remove in groups_id & set(group_list):
                # remove the group
                groups_to_remove.append(','.join(group_list))
                group_list.remove(group_to_remove)
                if len(group_list) > 1:
                    new_group = ','.join(group_list)
                else:
                    new_group = 'default' if not group_list else group_list[0]

            if new_group:
                # Add multigroup
                Agent.set_agent_group_file(agent_id, new_group)


    @staticmethod
    def remove_group(group_id):
        """
        Remove the group in every agent.

        :param group_id: Group ID.
        :return: Confirmation message.
        """

        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        failed_ids = []
        ids = []
        affected_agents = []
        if isinstance(group_id, list):
            for id in group_id:

                if id.lower() == "default":
                    raise WazuhException(1712)

                try:
                    removed = Agent._remove_single_group(id)
                    ids.append(id)
                    affected_agents += removed['affected_agents']
                    Agent.remove_multi_group(set(map(lambda x: x.lower(), group_id)))
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))
        else:
            if group_id.lower() == "default":
                raise WazuhException(1712)

            try:
                removed = Agent._remove_single_group(group_id)
                ids.append(group_id)
                affected_agents += removed['affected_agents']
                Agent.remove_multi_group({group_id.lower()})
            except Exception as e:
                failed_ids.append(create_exception_dic(group_id, e))

        if not failed_ids:
            message = 'All selected groups were removed'
            final_dict = {'msg': message, 'ids': ids, 'affected_agents': affected_agents}
        else:
            message = 'Some groups were not removed'
            final_dict = {'msg': message, 'failed_ids': failed_ids, 'ids': ids, 'affected_agents': affected_agents}

        return final_dict


    @staticmethod
    def set_group(agent_id, group_id, force=False, replace=False):
        """
        Set a group to an agent.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :param replace: Replace agent group instead of appending.
        :return: Confirmation message.
        """
        if replace:
            return Agent.replace_group(agent_id=agent_id, group_id=group_id, force=force)
        else:
            return Agent.add_group_to_agent(agent_id=agent_id, group_id=group_id, force=force)

    @staticmethod
    def set_group_list(group_id, agent_id_list):
        """
        Set a group to a list of agents.

        :param agent_id: List of Agent IDs.
        :param group_id: Group ID.
        :return: Confirmation message.
        """
        failed_ids = list()
        affected_agents = list()

        # raise an exception if agent_list_id is empty
        if len(agent_id_list) < 1:
            raise WazuhException(1732)

        for agent_id in agent_id_list:
            try:
                Agent.add_group_to_agent(agent_id=agent_id, group_id=group_id)
                affected_agents.append(agent_id)
            except Exception as e:
                failed_ids.append(agent_id)

            if not failed_ids:
                message = 'All selected agents assigned to group ' + group_id
            else:
                message = 'Some agents were not assigned to group ' + group_id

            final_dict = {}
            if failed_ids:
                final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
            else:
                final_dict = {'msg': message, 'affected_agents': affected_agents}

        return final_dict

    @staticmethod
    def unset_group_list(group_id, agent_id_list):
        """
        Unset a group to a list of agents.

        :param agent_id_list: List of Agent IDs.
        :param group_id: Group ID.
        :return: Confirmation message.
        """
        failed_ids = list()
        affected_agents = list()

        # raise an exception if agent_list_id is empty
        if len(agent_id_list) < 1:
            raise WazuhException(1732)

        # raise an exception if group does not exist
        if not Agent.group_exists(group_id):
            raise WazuhException(1710)

        message = f'All selected agents were removed from group {group_id}'
        for agent_id in agent_id_list:
            try:
                Agent.unset_group(agent_id=agent_id, group_id=group_id)
                affected_agents.append(agent_id)
            except Exception as e:
                failed_ids.append(create_exception_dic(agent_id, e))

            if failed_ids:
                message = f'Some agents were not removed from group {group_id}'

        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents}

        return final_dict


    @staticmethod
    def get_agents_group_file(agent_id):
        group_path, group_name = "{}/{}".format(common.groups_path, agent_id), ""
        if path.exists(group_path):
            with open(group_path) as f:
                group_name = f.read().strip()

        return group_name


    @staticmethod
    def set_agent_group_file(agent_id, group_id):
        try:
            agent_group_path = "{0}/{1}".format(common.groups_path, agent_id)
            new_file = not path.exists(agent_group_path)

            with open(agent_group_path, 'w') as f_group:
                f_group.write(group_id)

            if new_file:
                chown(agent_group_path, common.ossec_uid(), common.ossec_gid())
                chmod(agent_group_path, 0o660)
        except Exception as e:
            raise WazuhException(1005, str(e))

    @staticmethod
    def replace_group(agent_id, group_id, force=False):
        """
        Replaces a group to an agent.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        agent_id = agent_id.zfill(3)
        if agent_id == "000":
            raise WazuhException(1703)

        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        group_name = Agent.get_agents_group_file(agent_id)

        # Assign group in /queue/agent-groups
        Agent.set_agent_group_file(agent_id, group_id)

        # Create group in /etc/shared
        if not Agent.group_exists(group_id):
            Agent.create_group(group_id)

        return "Group '{0}' set to agent '{1}'.".format(group_id, agent_id)


    @staticmethod
    def set_multi_group(agent_id, group_id, force=False):
        """
        Set a multi group to an agent.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """
        # Input Validation of all groups_id
        if not reduce(operator.iand, map(InputValidator().group, group_id.split(','))):
            raise WazuhException(1722, group_id)

        agent_id = agent_id.zfill(3)
        if agent_id == "000":
            raise WazuhException(1703)

        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        # Assign group in /queue/agent-groups
        Agent.set_agent_group_file(agent_id, group_id)

        return "Group '{0}' set to agent '{1}'.".format(group_id, agent_id)


    @staticmethod
    def check_multigroup_limit(agent_id):
        """
        An agent can belong to <common.max_groups_per_multigroup> groups as maximum. This function checks that limit is
        not yet reached.

        :param agent_id: Agent ID to check
        :return: True if the limit is reached, False otherwise
        """
        group_read = Agent.get_agents_group_file(agent_id)
        if group_read:
            return len(group_read.split(',')) >= common.max_groups_per_multigroup
        else:
            # In case that the agent is not connected and has no assigned group, the file is not created.
            # So, the limit is not reached.
            return False

    @staticmethod
    def unset_group(agent_id, group_id=None, force=False):
        """
        Unset the agent group.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """
        if group_id is None:
            return Agent.unset_all_groups_agent(agent_id=agent_id, force=force)
        else:
            return Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=force)


    @staticmethod
    def unset_single_group_agent(agent_id, group_id=None, force=False):
        """
        Unset the agent group. If agent has multigroups, it will preserve all previous groups except the last one.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """
        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        # get agent's group
        group_name = Agent.get_agents_group_file(agent_id)
        group_list = group_name.split(',')
        # check agent belongs to group group_id
        if group_id not in group_list:
            raise WazuhException(1734)
        elif group_id == 'default' and len(group_list) == 1:
            raise WazuhException(1745)
        # remove group from group_list
        group_list.remove(group_id)
        if len(group_list) > 1:
            multigroup_name = ','.join(group_list)
        else:
            multigroup_name = 'default' if not group_list else group_list[0]

        Agent.unset_all_groups_agent(agent_id=agent_id, force=True, group_id=multigroup_name)

        return f"Group '{group_id}' unset for agent '{agent_id}'." if multigroup_name != 'default' else \
               f"Agent {agent_id} set to group default."


    @staticmethod
    def get_number_of_agents_in_multigroup(multigroup_name):
        """
        Returns the number of agents belonging to a multigroup
        :param multigroup_name: name of the multigroup
        :return:
        """
        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        conn.execute('select count(*) from agent where `group` = :group_name', {'group_name': multigroup_name})
        return int(conn.fetch())


    @staticmethod
    def unset_all_groups_agent(agent_id, force=False, group_id='default'):
        """
        Unset the agent group. The group will be group_id ('default' by default).

        :param agent_id: Agent ID.
        :param force: No check if agent exists
        :param group_id: New group to set.
        :return: Confirmation message.
        """
        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        # Check if multi group still exists in other agents
        group_name = Agent.get_agents_group_file(agent_id)
        if group_name:
            Agent.set_agent_group_file(agent_id, group_id)

            return "Group unset for agent '{0}'.".format(agent_id)
        else:
            raise WazuhException(1746)


    @staticmethod
    def get_outdated_agents(offset=0, limit=common.database_limit, sort=None, search=None, select=None, q=""):
        """
        Gets the outdated agents.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # Get manager version
        manager = Agent(id=0)
        manager._load_info_from_DB()

        select = {'fields': ['version', 'id', 'name']} if select is None else select
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      query=q, get_data=True, count=True)

        list_agents_outdated = []
        query_result = db_query.run()

        for item in query_result['items']:
            try:
                if WazuhVersion(item['version']) < WazuhVersion(manager.version):
                    list_agents_outdated.append(item)
            except ValueError:
                list_agents_outdated.append(item)  # if an error happens getting agent version, agent is considered as outdated
            except KeyError:
                continue  # a never connected agent causes a key error

        return {'items': list_agents_outdated, 'totalItems': len(list_agents_outdated)}


    def _get_protocol(self, wpk_repo, use_http=False):
        protocol = ""
        if "http://" not in wpk_repo and "https://" not in wpk_repo:
            protocol = "https://" if not use_http else "http://"

        return protocol

    def _get_versions(self, wpk_repo=common.wpk_repo_url, version=None, use_http=False):
        """
        Generates a list of available versions for its distribution and version.
        """
        invalid_platforms = ["darwin", "solaris", "aix", "hpux", "bsd"]
        not_valid_versions = [("sles", 11), ("rhel", 5), ("centos", 5)]

        if self.os['platform'] in invalid_platforms or (self.os['platform'], int(self.os['major'])) in not_valid_versions:
            error = "The WPK for this platform is not available."
            raise WazuhException(1713, error)

        protocol = self._get_protocol(wpk_repo, use_http)
        if (version is None or WazuhVersion(version) >= WazuhVersion("v3.4.0")) and self.os['platform'] != "windows":
            versions_url = protocol + wpk_repo + "linux/" + self.os['arch'] + "/versions"
        else:
            if self.os['platform'] == "windows":
                versions_url = protocol + wpk_repo + "windows/versions"
            elif self.os['platform'] == "ubuntu":
                versions_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + \
                               self.os['minor'] + "/" + self.os['arch'] + "/versions"
            else:
                versions_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + \
                               self.os['arch'] + "/versions"

        try:
            result = requests.get(versions_url)
        except requests.exceptions.RequestException:
            error = "Selected version repository ({}) isn't reachable".format(versions_url)
            raise WazuhException(1713, error)

        if result.ok:
            versions = [version.split() for version in result.text.split('\n')]
            versions = list(filter(lambda x: len(x) > 0, versions))
        else:
            error = "Can't access to the versions file in {}".format(versions_url)
            raise WazuhException(1713, error)

        return versions

    def _get_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, use_http=False):
        """
        Searchs latest Wazuh WPK file for its distribution and version.
        Downloads the WPK if it is not in the upgrade folder.
        """
        # Get manager version
        manager = Agent(id=0)
        manager._load_info_from_DB()
        manager_ver = WazuhVersion(manager.version)
        if debug:
            print("Manager version: {0}".format(manager_ver))

        agent_new_ver = None
        versions = self._get_versions(wpk_repo=wpk_repo, version=version, use_http=use_http)
        if not version:
            for ver in versions:
                if WazuhVersion(ver[0]) == manager_ver:
                    agent_new_ver = ver[0]
                    agent_new_shasum = ver[1]
                    break
        else:
            for ver in versions:
                if WazuhVersion(ver[0]) == WazuhVersion(version):
                    agent_new_ver = ver[0]
                    agent_new_shasum = ver[1]
                    break
        if not agent_new_ver:
            raise WazuhException(1718, version)

        # Comparing versions
        agent_ver = self.version

        if manager_ver < WazuhVersion(agent_new_ver) and not force:
            raise WazuhException(1717, WazuhException.ERRORS[1717] + ". Manager; {0} / Agent; {1} -> {2}".format(
                manager_ver, agent_ver, agent_new_ver), cmd_error=True)

        if WazuhVersion(agent_ver) >= WazuhVersion(agent_new_ver) and not force:
            raise WazuhException(1749,
                                 WazuhException.ERRORS[1749] + ". Agent; {0} -> {1}".format(agent_ver, agent_new_ver),
                                 cmd_error=True)

        if debug:
            print("Agent version: {0}".format(agent_ver))
            print("Agent new version: {0}".format(agent_new_ver))

        protocol = self._get_protocol(wpk_repo, use_http)
        # Generating file name
        if self.os['platform'] == "windows":
            wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_new_ver, self.os['platform'])
            wpk_url = protocol + wpk_repo + "windows/" + wpk_file

        else:
            if version is None or WazuhVersion(version) >= WazuhVersion("v3.4.0"):
                wpk_file = "wazuh_agent_{0}_linux_{1}.wpk".format(agent_new_ver, self.os['arch'])
                wpk_url = protocol + wpk_repo + "linux/" + self.os['arch'] + "/" + wpk_file

            else:
                if self.os['platform'] == "ubuntu":
                    wpk_file = "wazuh_agent_{0}_{1}_{2}.{3}_{4}.wpk".format(agent_new_ver, self.os['platform'],
                                                                            self.os['major'], self.os['minor'],
                                                                            self.os['arch'])
                    wpk_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + \
                              self.os['minor'] + "/" + self.os['arch'] + "/" + wpk_file
                else:
                    wpk_file = "wazuh_agent_{0}_{1}_{2}_{3}.wpk".format(agent_new_ver, self.os['platform'],
                                                                        self.os['major'], self.os['arch'])
                    wpk_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + \
                              self.os['arch'] + "/" + wpk_file

        wpk_file_path = "{0}/var/upgrade/{1}".format(common.ossec_path, wpk_file)

        # If WPK is already downloaded
        if path.isfile(wpk_file_path):
            # Get SHA1 file sum
            sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
            # Comparing SHA1 hash
            if not sha1hash == agent_new_shasum:
                if debug:
                    print("Downloaded file SHA1 does not match (downloaded: {0} / repository: {1})".format(
                        sha1hash, agent_new_shasum))
            else:
                if debug:
                    print("WPK file already downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))
                return [wpk_file, sha1hash]

        # Download WPK file
        if debug:
            print("Downloading WPK file from: {0}".format(wpk_url))

        try:
            result = requests.get(wpk_url)
        except requests.exceptions.RequestException as e:
            raise WazuhException(1714,
                                 WazuhException.ERRORS[1714] + ". Can't access to the WPK file in {}".format(wpk_url),
                                 cmd_error=True)

        if result.ok:
            with open(wpk_file_path, 'wb') as fd:
                for chunk in result.iter_content(chunk_size=128):
                    fd.write(chunk)
                os.chown(wpk_file_path, common.ossec_gid(), common.ossec_gid())
                os.chmod(wpk_file_path, 0o660)
        else:
            raise WazuhException(1714,
                                 WazuhException.ERRORS[1714] + ". Can't access to the WPK file in {}".format(wpk_url),
                                 cmd_error=True)

        # Get SHA1 file sum
        sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
        # Comparing SHA1 hash
        if not sha1hash == agent_new_shasum:
            raise WazuhException(1714,
                                 "The file has lost integrity in the transfer. "
                                 "Original SHA1; {} , Received SHA1; {}".format(agent_new_shasum, sha1hash),
                                 cmd_error=True)

        if debug:
            print("WPK file downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))

        return [wpk_file, sha1hash]

    def _send_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, show_progress=None,
                       chunk_size=None, rl_timeout=-1, timeout=common.open_retries, use_http=False):
        """
        Sends WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size
        # Check WPK file
        _get_wpk = self._get_wpk_file(wpk_repo=wpk_repo, debug=debug, version=version, force=force, use_http=use_http)
        wpk_file = _get_wpk[0]
        file_sha1 = _get_wpk[1]
        wpk_file_size = stat("{0}/var/upgrade/{1}".format(common.ossec_path, wpk_file)).st_size
        if debug:
            print("Upgrade PKG: {0} ({1} KB)".format(wpk_file, wpk_file_size/1024))

        # Sending reset lock timeout
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(1715, data.replace("err ",""))

        # Open file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
            s = OssecSocket(common.REQUEST_SOCKET)
            msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.receive().decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(
                1715,
                WazuhException.ERRORS[1715] +
                ". The file was not received correctly or there has been a timeout in the call [Agent side]",
                cmd_error=True)

        # Sending reset lock timeout
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(1715,
                                 WazuhException.ERRORS[1715] + ". A timeout has occurred in the call. "
                                 "Check that the agent is active and there are no problems with the network.",
                                 cmd_error=True)

        # Sending file to agent
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        file = open(common.ossec_path + "/var/upgrade/" + wpk_file, "rb")
        if not file:
            raise WazuhException(1715, data.replace("err ",""))
        if debug:
            print("Sending: {0}".format(common.ossec_path + "/var/upgrade/" + wpk_file))
        try:
            start_time = time()
            bytes_read = file.read(chunk_size)
            bytes_read_acum = 0
            while bytes_read:
                s = OssecSocket(common.REQUEST_SOCKET)
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.receive().decode()
                s.close()
                if not data.startswith('ok'):
                    raise WazuhException(1715, data.replace("err ",""))
                bytes_read = file.read(chunk_size)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) +
                                  (bytes_read_acum * 100 % wpk_file_size > 0))
            elapsed_time = time() - start_time
        finally:
            file.close()

        # Close file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(1715,
                                 "The agent has been disconnected during the process "
                                 "or the file has been modified [Agent side]",
                                 cmd_error=True)

        # Get file SHA1 from agent and compare
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(
                1715,
                extra_message="Error sending WPK file. Error when receiving SHA1 from the upgrade file "
                              "or the installer is invalid",
                cmd_error=True)
        rcv_sha1 = data.split(' ')[1]
        if rcv_sha1 == file_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise WazuhException(1715,
                                 "The file has lost integrity in the transfer. "
                                 "Original SHA1; {} , Received SHA1; {}".format(file_sha1, rcv_sha1), cmd_error=True)

    def upgrade(self, wpk_repo=None, debug=False, version=None, force=False, show_progress=None, chunk_size=None,
                rl_timeout=-1, use_http=False):
        """
        Upgrade agent using a WPK file.
        """
        if int(self.id) == 0:
            raise WazuhException(1703)

        self._load_info_from_DB()

        # Check if agent is active.
        if self.status != 'Active':
            raise WazuhException(1720)

        # Check if remote upgrade is available for the selected agent version
        if WazuhVersion(self.version) < WazuhVersion("3.0.0-alpha4"):
            raise WazuhException(1719, WazuhException.ERRORS[1719] + ". Version; {}".format(version), cmd_error=True)

        if self.os['platform'] == "windows" and int(self.os['major']) < 6:
            raise WazuhException(1721,
                                 WazuhException.ERRORS[1721] + ". OS name; {} OS platform; {} OS major; {}".format(
                                     self.os['name'], self.os['platform'], self.os['major']), cmd_error=True)

        if wpk_repo is None:
            wpk_repo = common.wpk_repo_url

        if not wpk_repo.endswith('/'):
            wpk_repo = wpk_repo + '/'

        # Send file to agent
        sending_result = self._send_wpk_file(wpk_repo=wpk_repo, debug=debug, version=version, force=force,
                                             show_progress=show_progress, chunk_size=chunk_size, rl_timeout=rl_timeout,
                                             use_http=use_http)
        if debug:
            print(sending_result[0])

        # Send upgrading command
        s = OssecSocket(common.REQUEST_SOCKET)
        if self.os['platform'] == "windows":
            msg = "{0} com upgrade {1} upgrade.bat".format(str(self.id).zfill(3), sending_result[1])
        else:
            msg = "{0} com upgrade {1} upgrade.sh".format(str(self.id).zfill(3), sending_result[1])
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()

        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(
                ("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): started. Current version: {2}".format(
                    str(self.id).zfill(3), self.name, self.version)).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            return "Upgrade procedure started"
        else:
            s.sendto(
                ("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): aborted: {2}".format(
                    str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(),
                common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716,
                                 "Error when receiving the upgrade command. "
                                 "It is possible that the agent has been disconnected "
                                 "or a timeout has occurred in the call",
                                 cmd_error=True)

    @staticmethod
    def upgrade_agent(agent_id, wpk_repo=None, version=None, force=False, chunk_size=None, use_http=False):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :return: Upgrade message.
        """

        return Agent(agent_id).upgrade(wpk_repo=wpk_repo, version=version, force=True if int(force) == 1 else False,
                                       chunk_size=chunk_size, use_http=use_http)

    def upgrade_result(self, debug=False, timeout=common.upgrade_result_retries):
        """
        Read upgrade result output from agent.
        """
        sleep(1)
        self._load_info_from_DB()
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com upgrade_result".format(str(self.id).zfill(3))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.upgrade_result_sleep)
            counter = counter + 1
            s = OssecSocket(common.REQUEST_SOCKET)
            msg = str(self.id).zfill(3) + " com upgrade_result"
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.receive().decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok 0'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): succeeded. New version: {2}".format(
                str(self.id).zfill(3), self.name, self.version)).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            return "Agent upgraded successfully"
        elif data.startswith('ok 2'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): failed: restored to previous version".format(str(self.id).zfill(3), self.name)).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716, "Error upgrading agent. Agent {} restored to previous version".format(self.id),
                                 cmd_error=True)
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): lost: {2}".format(
                str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(),
                     common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716,
                                 data.replace("err ", "") +
                                 ". The update status information could not be retrieved. Check the internet connection"
                                 " and that the agent is active.", cmd_error=True)

    @staticmethod
    def get_upgrade_result(agent_id, timeout=3):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :param timeout: Timeout of the call.
        :return: Upgrade result.
        """

        return Agent(agent_id).upgrade_result(timeout=int(timeout))

    def _send_custom_wpk_file(self, file_path, debug=False, show_progress=None, chunk_size=None, rl_timeout=-1,
                              timeout=common.open_retries):
        """
        Sends custom WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size

        # Check WPK file
        if not path.isfile(file_path):
            raise WazuhException(
                1006, extra_message='File {} does not exist or API does not have permissions on it'.format(file_path),
                cmd_error=True)

        wpk_file = path.basename(file_path)
        wpk_file_size = stat(file_path).st_size
        if debug:
            print("Custom WPK file: {0} ({1} KB)".format(wpk_file, wpk_file_size/1024))

        # Sending reset lock timeout
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(
                1715,
                data.replace("err ", "") +
                ". Please check the internet connection and that the agent is active (timeout). Agent {}".format(
                    self.id), cmd_error=True)

        # Open file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
            s = OssecSocket(common.REQUEST_SOCKET)
            msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.receive().decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(
                1715, extra_message="The file was not received correctly or there has been a timeout in the call",
                cmd_error=True)

        # Sending file to agent
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        try:
            file = open(file_path, "rb")
        except:
            raise WazuhException(1715, "API does not have permissions on this file", cmd_error=True)
        try:
            start_time = time()
            bytes_read = file.read(chunk_size)
            file_sha1=hashlib.sha1(bytes_read)
            bytes_read_acum = 0
            while bytes_read:
                s = OssecSocket(common.REQUEST_SOCKET)
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.receive().decode()
                s.close()
                if not data.startswith('ok'):
                    raise WazuhException(1715,
                                         data.replace("err ", "") +
                                         ". The agent {} has been disconnected while receiving the upgrade file".format(
                                             self.id), cmd_error=True)
                bytes_read = file.read(chunk_size)
                file_sha1.update(bytes_read)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) +
                                  (bytes_read_acum * 100 % wpk_file_size > 0))
            elapsed_time = time() - start_time
            calc_sha1 = file_sha1.hexdigest()
            if debug:
                print("FILE SHA1: {0}".format(calc_sha1))
        finally:
            file.close()

        # Close file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(1715, extra_message=data.replace("err ", "") +
                                 ". The agent has been disconnected during the process or the file has been modified",
                                 cmd_error=True)

        # Get file SHA1 from agent and compare
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok '):
            raise WazuhException(
                1715,
                "Error sending WPK file. Error when receiving SHA1 from the upgrade file or the installer is invalid",
                cmd_error=True)
        rcv_sha1 = data.split(' ')[1]
        if calc_sha1 == rcv_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise WazuhException(1715,
                                 "The file has lost integrity in the transfer. "
                                 "Original SHA1; {} , Received SHA1; {}".format(calc_sha1, rcv_sha1), cmd_error=True)

    def upgrade_custom(self, file_path, installer, debug=False, show_progress=None, chunk_size=None, rl_timeout=-1):
        """
        Upgrade agent using a custom WPK file.
        """
        self._load_info_from_DB()

        # Check if agent is active.
        if self.status != 'Active':
            raise WazuhException(1720)

        # Send file to agent
        sending_result = self._send_custom_wpk_file(file_path, debug, show_progress, chunk_size, rl_timeout)
        if debug:
            print(sending_result[0])

        # Send installing command
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com upgrade {1} {2}".format(str(self.id).zfill(3), sending_result[1], installer)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(("1:wazuh-upgrade:wazuh: Custom installation on agent {0} ({1}): started.".format(str(self.id).zfill(3), self.name)).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            return "Installation started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Custom installation on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716,
                                 "File {} . It is possible that the agent has been disconnected "
                                 "or a timeout has occurred in the call".format(file_path), cmd_error=True)

    @staticmethod
    def upgrade_agent_custom(agent_id, file_path=None, installer=None):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :param file_path: Path of the file to update
        :param installer: Installer script
        :return: Upgrade message.
        """
        if not file_path or not installer:
            raise WazuhException(1307)

        return Agent(agent_id).upgrade_custom(file_path=file_path, installer=installer)

    def getconfig(self, component, config):
        """
        Read agent loaded configuration.
        """
        # checks if agent version is compatible with this feature
        self._load_info_from_DB()
        if self.version is None:
            raise WazuhException(1015)

        agent_version = WazuhVersion(self.version.split(" ")[1])
        required_version = WazuhVersion("v3.7.0")
        if agent_version < required_version:
            raise WazuhException(1735, "Minimum required version is " + str(required_version))

        return configuration.get_active_configuration(self.id, component, config)

    @staticmethod
    def get_config(agent_id, component, configuration):
        """
        Read selected configuration from agent.

        :param agent_id: Agent ID.
        :return: Loaded configuration in JSON.
        """
        my_agent = Agent(agent_id)
        my_agent._load_info_from_DB()

        if my_agent.status != "Active":
            raise WazuhException(1740)

        return my_agent.getconfig(component=component, config=configuration)

    @staticmethod
    def get_sync_group(agent_id):
        if agent_id == "000":
            raise WazuhException(1703)
        else:
            try:
                # Check if agent exists and it is active
                agent_info = Agent(agent_id).get_basic_information()

                # Check if it has a multigroup
                if len(agent_info['group']) > 1:
                    multi_group = ','.join(agent_info['group'])
                    multi_group = hashlib.sha256(multi_group.encode()).hexdigest()[:8]
                    agent_group_merged_path = "{0}/{1}/merged.mg".format(common.multi_groups_path, multi_group)
                else:
                    agent_group_merged_path = "{0}/{1}/merged.mg".format(common.shared_path, agent_info['group'][0])

                return {'synced': md5(agent_group_merged_path) == agent_info['mergedSum']}
            except (IOError, KeyError):
                # the file can't be opened and therefore the group has not been synced
                return {'synced': False}
            except Exception as e:
                raise WazuhException(1739, str(e))

    @staticmethod
    def get_agent_conf(group_id=None, offset=0, limit=common.database_limit, filename='agent.conf', return_format=None):
        """
        Returns agent.conf as dictionary.

        :return: agent.conf as dictionary.
        """
        if group_id:
            if not Agent.group_exists(group_id):
                raise WazuhException(1710, group_id)

        return configuration.get_agent_conf(group_id, offset, limit, filename, return_format)

    @staticmethod
    def get_file_conf(filename, group_id=None, type_conf=None, return_format=None):
        """
        Returns the configuration file as dictionary.

        :return: configuration file as dictionary.
        """

        if group_id:
            if not Agent.group_exists(group_id):
                raise WazuhException(1710, group_id)

        return configuration.get_file_conf(filename, group_id, type_conf, return_format)

    @staticmethod
    def upload_group_file(group_id, tmp_file, file_name='agent.conf'):
        """
        Updates a group file
        :param group_id: Group to update
        :param tmp_file: Relative path of temporary file to upload
        :param file_name: File name to update
        :return: Confirmation message in string
        """
        # check if the group exists
        if not Agent.group_exists(group_id):
            raise WazuhException(1710)

        return configuration.upload_group_file(group_id, tmp_file, file_name)

    @staticmethod
    def get_full_summary() -> Dict:
        """Get information about agents.
        :return: Dictionary with information about agents
        """
        # get information from different methods of Agent class
        stats_distinct_node = Agent.get_distinct_agents(fields={'fields': ['node_name']})
        groups = Agent.get_all_groups()
        stats_distinct_os = Agent.get_distinct_agents(fields={'fields': ['os.name',
                                                      'os.platform', 'os.version']})
        stats_version = Agent.get_distinct_agents(fields={'fields': ['version']})
        summary = Agent.get_agents_summary()
        try:
            last_registered_agent = Agent.get_agents_overview(limit=1,
                                                              sort={'fields': ['dateAdd'], 'order': 'desc'},
                                                              q='id!=000').get('items')[0]
        except IndexError:  # an IndexError could happen if there are not registered agents
            last_registered_agent = {}
        # combine results in an unique dictionary
        result = {'nodes': stats_distinct_node, 'groups': groups,
                  'agent_os': stats_distinct_os, 'agent_status': summary,
                  'agent_version': stats_version,
                  'last_registered_agent': last_registered_agent}

        return result
