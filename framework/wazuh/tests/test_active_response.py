#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest
with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.exception import WazuhException
        from wazuh import active_response
import os

# all necessary params
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def test_get_commands():
    with patch("wazuh.common.ossec_path", new=test_data_path):
        assert (active_response.get_commands() != [])


@patch('wazuh.active_response.OssecQueue')
@patch('wazuh.active_response.Agent')
@patch('wazuh.active_response.get_commands', return_value=['valid_cmd', 'another_valid_cmd', 'one_more'])
@pytest.mark.parametrize('expected_exception, agent_id, command, arguments, custom', [
    (1650, '000', None, [], False),
    (1653, None, 'random', [], False),
    (1655, '000', 'invalid_cmd', [], False),
    (1651, '001', 'valid_cmd', [], False),
    (None, '001', 'valid_cmd', [], False),
    (None, '001', 'valid_cmd', [], True),
    (None, '001', 'valid_cmd', ["arg1", "arg2"], False),
    (None, '000', 'valid_cmd', [], False),
    (None, 'all', 'valid_cmd', [], False)
])
def test_run_command(cmd_patch, agent_patch, queue_patch, expected_exception, agent_id, command, arguments, custom):
    """
    Tests run_command function
    """
    agent_patch.return_value.get_basic_information.return_value = {'status': 'disconnected' if expected_exception else 'active'}
    queue_patch.return_value.send_msg_to_agent.return_value = "success"
    queue_patch.AR_TYPE = "AR"

    if expected_exception is not None:
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            active_response.run_command(agent_id, command, arguments, custom)
    else:
        ret = active_response.run_command(agent_id, command, arguments, custom)
        assert ret == "success"
        handle = queue_patch()
        msg = f'{"!" if custom else ""}{command} {"- -" if not arguments else " ".join(arguments)}'
        if agent_id != 'all':
            handle.send_msg_to_agent.assert_called_with(agent_id=agent_id, msg=msg, msg_type='AR')
        else:
            handle.send_msg_to_agent.assert_called_with(agent_id=None, msg=msg, msg_type='AR')