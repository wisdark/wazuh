# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from api.util import remove_nones_to_dict
from wazuh.cluster.dapi.dapi import DistributedAPI
import wazuh.syscheck as syscheck


loop = asyncio.get_event_loop()
logger = logging.getLogger('syscheck')

def put_syscheck(pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    """
    pass


def get_syscheck_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, limit=None, 
                       select=None, sort=None, search=None, file=None, type=None, summary=False,
                       md5=None, sha1=None, sha256=None, hash=None):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order. 
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param file: Filters by filename.
    :type file: str
    :param type: Filters by file type.
    :type type: str
    :param summary: Returns a summary grouping by filename.
    :type summary: bool
    :param md5: Filters files with the specified MD5 checksum.
    :type md5: str
    :param sha1: Filters files with the specified SHA1 checksum.
    :type sha1: str
    :param sha256: Filters files with the specified SHA256 checksum.
    :type sha256: str
    :param hash: Filters files with the specified checksum (MD5, SHA256 or SHA1)
    :type md5: str
    """
    filters = {'type': type, 'md5': md5, 'sha1': sha1, 'sha256': sha256,
               'hash': hash, 'file': file}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': sort, 'search': search,
                'summary': summary, 'filters': filters}

    dapi = DistributedAPI(f=syscheck.files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200


def put_syscheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=syscheck.run,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200


def delete_syscheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=syscheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200

def get_last_scan_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=syscheck.last_scan,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200