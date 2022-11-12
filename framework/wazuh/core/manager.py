# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import json
import re
import socket
from collections import OrderedDict
from os.path import exists
from typing import Dict

from api import configuration
from wazuh import WazuhInternalError, WazuhError, WazuhException
from wazuh.core import common
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.utils import tail, get_utc_strptime
from wazuh.core.wazuh_socket import WazuhSocket

_re_logtest = re.compile(r"^.*(?:ERROR: |CRITICAL: )(?:\[.*\] )?(.*)$")


def status() -> dict:
    """Return the Manager processes that are running."""

    return get_manager_status()


def get_ossec_log_fields(log: str) -> tuple:
    """Get ossec.log log fields.

    Parameters
    ----------
    log : str
        Log example.

    Returns
    -------
    tuple
        Log fields: timestamp, tag, level, and description.
    """
    regex_category = re.compile(
        r"^(\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d)\s(\S+)(?:\[.*)?:\s(DEBUG|INFO|CRITICAL|ERROR|WARNING):(.*)$")

    match = re.search(regex_category, log)

    if match:
        date = match.group(1)
        tag = match.group(2)
        level = match.group(3)
        description = match.group(4)

        if "rootcheck" in tag:  # Unify rootcheck category
            tag = "wazuh-rootcheck"

    else:
        return None

    return get_utc_strptime(date, '%Y/%m/%d %H:%M:%S'), tag, level.lower(), description


def get_ossec_logs(limit: int = 2000) -> list:
    """Return last <limit> lines of ossec.log file.

    Parameters
    ----------
    limit : int
        Number of lines to return. Default: 2000

    Returns
    -------
    list
        List of dictionaries with requested logs.
    """
    logs = []

    for line in tail(common.OSSEC_LOG, limit):
        log_fields = get_ossec_log_fields(line)
        if log_fields:
            date, tag, level, description = log_fields

            # We transform local time (ossec.log) to UTC with ISO8601 maintaining time integrity
            log_line = {'timestamp': date.strftime(common.DATE_FORMAT), 'tag': tag,
                        'level': level, 'description': description}
            logs.append(log_line)

    return logs


def get_logs_summary(limit: int = 2000) -> dict:
    """Get the number of alerts of each tag.

    Parameters
    ----------
    limit : int
        Number of lines to return. Default: 2000

    Returns
    -------
    dict
        Number of logs for every tag.
    """
    tags = dict()
    logs = get_ossec_logs(limit)

    for log in logs:
        if log['tag'] in tags:
            tags[log['tag']]['all'] += 1
        else:
            tags[log['tag']] = {'all': 1, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0}
        tags[log['tag']][log['level']] += 1

    return tags


def validate_ossec_conf() -> str:
    """Check if Wazuh configuration is OK.

    Raises
    ------
    WazuhInternalError(1014)
        If there is a socket communication error.
    WazuhInternalError(1013)
        If it is unable to connect to socket.
    WazuhInternalError(1901)
        If 'execq' socket cannot be created.
    WazuhInternalError(1904)
        If there is bad data received from 'execq'.

    Returns
    -------
    str
        Status of the configuration.
    """

    # Socket path
    wcom_socket_path = common.WCOM_SOCKET
    # Message for checking Wazuh configuration
    wcom_msg = common.CHECK_CONFIG_COMMAND

    # Connect to wcom socket
    if exists(wcom_socket_path):
        try:
            wcom_socket = WazuhSocket(wcom_socket_path)
        except WazuhException as e:
            extra_msg = f'Socket: WAZUH_PATH/queue/sockets/com. Error {e.message}'
            raise WazuhInternalError(1013, extra_message=extra_msg)
    else:
        raise WazuhInternalError(1901)

    # Send msg to wcom socket
    try:
        wcom_socket.send(wcom_msg.encode())

        buffer = bytearray()
        datagram = wcom_socket.receive()
        buffer.extend(datagram)

    except (socket.error, socket.timeout) as e:
        raise WazuhInternalError(1014, extra_message=str(e))
    finally:
        wcom_socket.close()

    try:
        response = parse_execd_output(buffer.decode('utf-8').rstrip('\0'))
    except (KeyError, json.decoder.JSONDecodeError) as e:
        raise WazuhInternalError(1904, extra_message=str(e))

    return response


def parse_execd_output(output: str) -> Dict:
    """Parse output from execd socket to fetch log message and remove log date, log daemon, log level, etc.

    Parameters
    ----------
    output : str
        Raw output from execd.

    Returns
    -------
    dict
        Cleaned log message in a dictionary structure.
    """
    json_output = json.loads(output)
    error_flag = json_output['error']
    if error_flag != 0:
        errors = []
        log_lines = json_output['message'].splitlines(keepends=False)
        for line in log_lines:
            match = _re_logtest.match(line)
            if match:
                errors.append(match.group(1))
        errors = list(OrderedDict.fromkeys(errors))
        raise WazuhError(1908, extra_message=', '.join(errors))
    else:
        response = {'status': 'OK'}

    return response


def get_api_conf() -> dict:
    """Return current API configuration.

    Returns
    -------
    dict
        API configuration.
    """
    return copy.deepcopy(configuration.api_conf)
