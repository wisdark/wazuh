

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from grp import getgrnam
from pwd import getpwnam

try:
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, 'wazuh.json'), 'r') as f:
        metadata = json.load(f)
except Exception:
    metadata = {
        'install_type': '',
        'installation_date': '',
        'wazuh_version': ''
    }


def find_wazuh_path():
    """
    Gets the path where Wazuh is installed dinamically

    :return: str path where Wazuh is installed or empty string if there is no framework in the environment
    """
    abs_path = os.path.abspath(os.path.dirname(__file__))
    allparts = []
    while 1:
        parts = os.path.split(abs_path)
        if parts[0] == abs_path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == abs_path:  # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            abs_path = parts[0]
            allparts.insert(0, parts[1])

    wazuh_path = ''
    try:
        for i in range(0, allparts.index('framework')):
            wazuh_path = os.path.join(wazuh_path, allparts[i])
    except ValueError:
        pass

    return wazuh_path


ossec_path = find_wazuh_path()

install_type = metadata['install_type']
wazuh_version = metadata['wazuh_version']
installation_date = metadata['installation_date']
ossec_conf = os.path.join(ossec_path, 'etc', 'ossec.conf')
internal_options = os.path.join(ossec_path, 'etc', 'internal_options.conf')
local_internal_options = os.path.join(ossec_path, 'etc', 'local_internal_options.conf')
ossec_log = os.path.join(ossec_path, 'logs', 'ossec.log')
client_keys = os.path.join(ossec_path, 'etc', 'client.keys')
stats_path = os.path.join(ossec_path, 'stats')
ruleset_path = os.path.join(ossec_path, 'ruleset')
groups_path = os.path.join(ossec_path, 'queue', 'agent-groups')
multi_groups_path = os.path.join(ossec_path, 'var', 'multigroups')
shared_path = os.path.join(ossec_path, 'etc', 'shared')
backup_path = os.path.join(ossec_path, 'backup')
ruleset_rules_path = os.path.join(ruleset_path, 'rules')
database_path = os.path.join(ossec_path, 'var', 'db')
database_path_global = os.path.join(database_path, 'global.db')
wdb_socket_path = os.path.join(ossec_path, 'queue', 'db', 'wdb')
wdb_path = os.path.join(ossec_path, 'queue', 'db')
api_config_path = os.path.join(ossec_path, 'api', 'configuration', 'config.js')
database_path_agents = os.path.join(database_path, 'agents')
os_pidfile = os.path.join('var', 'run')
analysisd_stats = os.path.join(ossec_path, 'var', 'run', 'ossec-analysisd.state')
remoted_stats = os.path.join(ossec_path, 'var', 'run', 'ossec-remoted.state')
lists_path = os.path.join(ossec_path, 'etc', 'lists')

# Queues
ARQUEUE = os.path.join(ossec_path, 'queue', 'alerts', 'ar')
EXECQ = os.path.join(ossec_path, 'queue', 'alerts', 'execq')

# Socket
AUTHD_SOCKET = os.path.join(ossec_path, 'queue', 'ossec', 'auth')
REQUEST_SOCKET = os.path.join(ossec_path, 'queue', 'ossec', 'request')

# Agent upgrading variables
wpk_repo_url = "packages.wazuh.com/wpk/"

wpk_chunk_size = 512

open_retries = 10  # Retries until get open ok message
open_sleep = 5  # Seconds between retries

upgrade_result_retries = 60  # Retries until get upgrade_result ok message
upgrade_result_sleep = 5  # Seconds between retries

agent_info_retries = 100  # Retries to detect when agent_info file is updated
agent_info_sleep = 2  # Seconds between retries

# Common variables
database_limit = 500
maximum_database_limit = 1000
limit_seconds = 1800  # 600*3


_ossec_uid = None
_ossec_gid = None


def ossec_uid():
    return getpwnam("ossec").pw_uid if globals()['_ossec_uid'] is None else globals()['_ossec_uid']


def ossec_gid():
    return getgrnam("ossec").gr_gid if globals()['_ossec_gid'] is None else globals()['_ossec_gid']


# Multigroup variables
max_groups_per_multigroup = 256
