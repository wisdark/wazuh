# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock
import pytest

from wazuh.pyDaemonModule import *
from wazuh.exception import WazuhException
from tempfile import NamedTemporaryFile, TemporaryDirectory


@pytest.mark.parametrize('effect', [
   None,
   OSError(10000, 'Error')
])
@patch('wazuh.pyDaemonModule.sys.exit')
@patch('wazuh.pyDaemonModule.os.setsid')
@patch('wazuh.pyDaemonModule.sys.stderr.write')
@patch('wazuh.pyDaemonModule.sys.stdin.fileno')
@patch('wazuh.pyDaemonModule.os.dup2')
@patch('wazuh.pyDaemonModule.os.chdir')
def test_pyDaemon(mock_chdir, mock_dup, mock_fileno, mock_write, mock_setsid, mock_exit, effect):
    """Tests pyDaemon function works"""

    with patch('wazuh.pyDaemonModule.os.fork', return_value=255, side_effect=effect):
        pyDaemon()

    if effect == None:
        mock_exit.assert_called_with(0)
    else:
        mock_exit.assert_called_with(1)
    mock_setsid.assert_called_once_with()
    mock_chdir.assert_called_once_with('/')


@patch('wazuh.pyDaemonModule.common.ossec_path', new='/tmp')
def test_create_pid():
    """Tests create_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.pyDaemonModule.common.os_pidfile', new=tmpdirname.split('/')[2]):
            create_pid(tmpfile.name.split('/')[3].split('-')[0],'255')


@patch('wazuh.pyDaemonModule.common.ossec_path', new='/tmp')
@patch('wazuh.pyDaemonModule.os.chmod', side_effect=OSError)
def test_create_pid_ko(mock_chmod):
    """Tests create_pid function exception works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.pyDaemonModule.common.os_pidfile', new=tmpdirname.split('/')[2]):
            with pytest.raises(WazuhException, match=".* 3002 .*"):
                create_pid(tmpfile.name.split('/')[3].split('-')[0],'255')


@patch('wazuh.pyDaemonModule.common.ossec_path', new='/tmp')
def test_delete_pid():
    """Tests delete_pid function works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.pyDaemonModule.common.os_pidfile', new=tmpdirname.split('/')[2]):
            delete_pid(tmpfile.name.split('/')[3].split('-')[0],'255')


@patch('wazuh.pyDaemonModule.common.ossec_path', new='/tmp')
@patch('wazuh.pyDaemonModule.os.path.exists', side_effect=OSError)
def test_delete_pid_ko(mock_exists):
    """Tests delete_pid function exception works"""

    with TemporaryDirectory() as tmpdirname:
        tmpfile = NamedTemporaryFile(dir=tmpdirname, delete=False, suffix='-255.pid')
        with patch('wazuh.pyDaemonModule.common.os_pidfile', new=tmpdirname.split('/')[2]):
            with pytest.raises(WazuhException, match=".* 3003 .*"):
                delete_pid(tmpfile.name.split('/')[3].split('-')[0],'255')