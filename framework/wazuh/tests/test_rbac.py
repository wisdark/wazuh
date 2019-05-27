# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open
import pytest
import connexion

import wazuh.rbac
from wazuh.exception import WazuhException
from flask import Flask
from api.authentication import generate_token

mock_jwt = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ3YXp1aCIsImlhdCI6MTU1ODY5ODM2NiwiZXhwI" \
           "joxNTU4Njk4OTY2LCJzdWIiOiJmb28iLCJyYmFjX3BvbGljaWVzIjpbeyJhY3Rpb25zIjpbImRlY29kZXI6Z2V0Il0sInJ" \
           "lc291cmNlcyI6WyJkZWNvZGVyOm5hbWU6d2luZG93c19maWVsZHMiLCJkZWNvZGVyOm5hbWU6KiJdLCJlZmZlY3QiOiJhb" \
           "GxvdyJ9XSwibW9kZSI6ZmFsc2V9.Pve6eh1AgqWVvST-ewBfST2IMb8c7_vVm6XD_RQ52v4"

mock_rbac_policies = [
    {
        "actions": ["decoder:get"],
        "resources": ["decoder:name:windows_fields", "decoder:name:*"],
        "effect": "allow"
    }
]

mock_payload = {
    "rbac_policies": mock_rbac_policies,
    "mode": False  # True if black_list, False if white_list
}


def mock_decode_token():
    return mock_payload


# @patch('wazuh.syscheck.Agent.get_basic_information', side_effect=get_random_status)
# def test_syscheck_run_status(mocked_status):
#     with pytest.raises(WazuhException, match='.* 1604 .*'):
# run(agent_id='001')
#
def mock_request(mocsk_jwt):
    print(mocsk_jwt)
    return "PEPE"


# @patch("api.authentication.decode_token", side_effect=mock_decode_token)
# @patch("connexion.request.headers.get(Authorization)", side_effect=mock_request)
# def test_get_user_permissions():
#     app = connexion.App("test")
#     with app.app.test_request_context(headers={"Authorization": mock_jwt}):
#         with patch("api.authentication.decode_token", side_effect=mock_decode_token):
#             mode, permissions = wazuh.rbac.get_user_permissions()
#     # mode = True
#     # permissions = list()
#     assert isinstance(mode, bool)
#     assert isinstance(permissions, list)

@pytest.mark.parametrize('mock_actions', [
    ['mock_action:get',
     'mock_action:delete']
])
@pytest.mark.parametrize('mock_resources', [
    'mock_resources:name:{name}',
    'mock_resources:name:mock_name'
])
@pytest.mark.parametrize('mock_names', [
    'mock_decoders.xml',                         # params is a str
    ['mock1_decoders.xml', 'mock_decoders.xml']  # params is a list
])
def test_get_required_permissions(mock_actions, mock_resources, mock_names):
    permissions = wazuh.rbac.get_required_permissions(actions=mock_actions,
                                                      resources=mock_resources,
                                                      name=mock_names)
    assert isinstance(permissions, dict)
    for action in mock_actions:
        assert action in permissions.keys()



# def test_match_pairs():
#     wazuh.rbac.match_pairs()
#     pass
#
#
# def test_matches_privileges():
#     wazuh.rbac.matches_privileges()
#     pass
