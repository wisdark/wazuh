# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock
import pytest

from wazuh.ossec_socket import OssecSocket, OssecSocketJSON
from wazuh.exception import WazuhException

@patch('wazuh.ossec_socket.OssecSocket._connect')
def test_OssecSocket__init__(mock_conn):
    """Tests OssecSocket.__init__ function works"""

    OssecSocket('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.ossec_socket.socket.socket.connect')
def test_OssecSocket_protected_connect(mock_conn):
    """Tests OssecSocket._connect function works"""

    OssecSocket('test_path')

    mock_conn.assert_called_with('test_path')


@patch('wazuh.ossec_socket.socket.socket.connect', side_effect=Exception)
def test_OssecSocket_protected_connect_ko(mock_conn):
    """Tests OssecSocket._connect function exceptions works"""

    with pytest.raises(WazuhException, match=".* 1013 .*"):
        OssecSocket('test_path')


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.socket.socket.close')
def test_OssecSocket_close(mock_close, mock_conn):
    """Tests OssecSocket.close function works"""

    queue = OssecSocket('test_path')

    queue.close()

    mock_conn.assert_called_once_with('test_path')
    mock_close.assert_called_once_with()


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.socket.socket.send')
def test_OssecSocket_send(mock_send, mock_conn):
    """Tests OssecSocket.send function works"""

    queue = OssecSocket('test_path')

    response = queue.send(b"\x00\x01")

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@pytest.mark.parametrize('msg, effect, send_effect, expected_exception', [
    ('text_msg', 'side_effect', None, 1104),
    (b"\x00\x01", 'return_value', 0, 1014),
    (b"\x00\x01", 'side_effect', Exception, 1014)
])
@patch('wazuh.ossec_socket.socket.socket.connect')
def test_OssecSocket_send_ko(mock_conn, msg, effect, send_effect, expected_exception):
    """Tests OssecSocket.send function exceptions works"""

    queue = OssecSocket('test_path')

    if effect == 'return_value':
        with patch('wazuh.ossec_socket.socket.socket.send', return_value=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                queue.send(msg)
    else:
        with patch('wazuh.ossec_socket.socket.socket.send', side_effect=send_effect):
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                queue.send(msg)

    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.unpack', return_value='1024')
@patch('wazuh.ossec_socket.socket.socket.recv')
def test_OssecSocket_receive(mock_recv, mock_unpack, mock_conn):
    """Tests OssecSocket.receive function works"""

    queue = OssecSocket('test_path')

    response = queue.receive()

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.socket.socket.recv', side_effect=Exception)
def test_OssecSocket_receive_ko(mock_recv, mock_conn):
    """Tests OssecSocket.receive function exception works"""

    queue = OssecSocket('test_path')

    with pytest.raises(WazuhException, match=".* 1014 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.ossec_socket.OssecSocket._connect')
def test_OssecSocketJSON__init__(mock_conn):
    """Tests OssecSocketJSON.__init__ function works"""

    OssecSocketJSON('test_path')

    mock_conn.assert_called_once_with()


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.OssecSocket.send')
def test_OssecSocketJSON_send(mock_send, mock_conn):
    """Tests OssecSocketJSON.send function works"""

    queue = OssecSocketJSON('test_path')

    response = queue.send('test_msg')

    assert isinstance(response, MagicMock)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.OssecSocket.receive')
@patch('wazuh.ossec_socket.loads', return_value={'error':0, 'message':None, 'data':'Ok'})
def test_OssecSocketJSON_receive(mock_loads, mock_receive, mock_conn):
    """Tests OssecSocketJSON.receive function works"""

    queue = OssecSocketJSON('test_path')

    response = queue.receive()

    assert isinstance(response, str)
    mock_conn.assert_called_once_with('test_path')


@patch('wazuh.ossec_socket.socket.socket.connect')
@patch('wazuh.ossec_socket.OssecSocket.receive')
@patch('wazuh.ossec_socket.loads', return_value={'error':10000, 'message':'Error', 'data':'KO'})
def test_OssecSocketJSON_receive_ko(mock_loads, mock_receive, mock_conn):
    """Tests OssecSocketJSON.receive function works"""

    queue = OssecSocketJSON('test_path')

    with pytest.raises(WazuhException, match=".* 10000 .*"):
        queue.receive()

    mock_conn.assert_called_once_with('test_path')