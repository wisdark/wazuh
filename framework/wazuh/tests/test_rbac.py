# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import connexion
import pytest

import wazuh.rbac
from wazuh.exception import WazuhError

# MOCK DATA
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
    "mode": False
}

mocked_user1 = [{
        "actions": ["mock_action:get"],                  # 1st policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "allow"
}]


mocked_user2 = [{
        "actions": ["mock_action:get"],                  # 1st policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "deny"
}]


@patch("wazuh.rbac.decode_token", return_value=mock_payload)
def test_get_user_permissions(mocked_payload):
    app = connexion.App("test")
    with app.app.test_request_context(headers={"Authorization": mock_jwt}):
        mode, permissions = wazuh.rbac.get_user_permissions()

    assert isinstance(mode, bool)
    assert isinstance(permissions, list)


@pytest.mark.parametrize('mock_actions', [
    ['mock_action:get',
     'mock_action:delete']
])
@pytest.mark.parametrize('mock_resources', [
    'mock_resources:name:{name}',                           # dynamic resources
    'mock_resources:name:mock_name'                         # static resources
])
@pytest.mark.parametrize('mock_names', [
    'mock_file1.xml',                                       # params is a str
    ['mock_file1.xml', 'mock_file2.xml']                    # params is a list
])
def test_get_required_permissions(mock_names, mock_resources, mock_actions):
    permissions = wazuh.rbac.get_required_permissions(actions=mock_actions,
                                                      resources=mock_resources,
                                                      name=mock_names)
    assert isinstance(permissions, dict)
    for action in mock_actions:
        assert action in permissions.keys()


def test_get_required_permissions_exception():

    with pytest.raises(WazuhError, match='.* 4000 .*'):
        wazuh.rbac.get_required_permissions(actions=['mock_action:get'],
                                            resources='mock_resources:name:{name}',
                                            wrong='mock_file1.xml')


@pytest.mark.parametrize('mock_req', [
    {
        'mock_action:get': {'mock_resources:name:mock_name'}
    }
])
@pytest.mark.parametrize('mock_user', [
    [{                                                      # 1st user permissions
        "actions": ["mock_action:get"],                         # 1st policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "deny"
    }],
    [{                                                      # 2nd user permissions
        "actions": ["mock_action:update"],                      # 1st policy
        "resources": ["mock_resources:name:wrong"],
        "effect": "deny"
    }],
    [{                                                      # 3rd user permissions
        "actions": ["mock_action:get"],                         # 1st policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "allow"
    },
        {
        "actions": ["mock_action:update"],                      # 2nd policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "deny"
    },
    ]
])
@pytest.mark.parametrize('mock_modes', [
    False,                                                  # white_list mode
    True                                                    # black_list mode
])
def test_match_pairs(mock_modes, mock_user, mock_req):
    allowed = wazuh.rbac.match_pairs(mode=mock_modes, user_permissions=mock_user, req_permissions=mock_req)
    assert isinstance(allowed, bool)


@patch("wazuh.rbac.get_user_permissions", side_effect=[[False, mocked_user1], [False, mocked_user2]])
def test_matches_privileges(mocked_perms):

    @wazuh.rbac.matches_privileges(actions=["mock_action:get"], resources="mock_resources:name:mock_name")
    def endpoint_test():
        return True

    # First call to matches_privileges uses mocked_user1 and should return true
    assert endpoint_test() is True

    # Second call to matches_privileges uses mocked_user2 and should raise a WazuhError
    with pytest.raises(WazuhError, match='.* 4000 .*'):
        endpoint_test()
