# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from asyncio import Transport
from contextvars import ContextVar
from logging import Logger
from unittest.mock import call, patch

import pytest
from freezegun import freeze_time
from uvloop import EventLoopPolicy, new_event_loop

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from wazuh.core.cluster.server import *
        from wazuh.core.cluster import common as c_common
        from wazuh.core.exception import WazuhClusterError, WazuhError, WazuhResourceNotFound

fernet_key = "00000000000000000000000000000000"
asyncio.set_event_loop_policy(EventLoopPolicy())
loop = new_event_loop()


def test_AbstractServerHandler_init():
    """Check the correct initialization of the AbstractServerHandler object."""
    with patch("wazuh.core.cluster.server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
        abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                        cluster_items={"test": "server"})
        assert abstract_server_handler.server == "Test"
        assert abstract_server_handler.loop == loop
        assert isinstance(abstract_server_handler.last_keepalive, float)
        assert abstract_server_handler.tag == "Client"
        assert mock_contextvar.get() == "Client"
        assert abstract_server_handler.name is None
        assert abstract_server_handler.ip is None
        assert abstract_server_handler.transport is None

        abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                        cluster_items={"test": "server"},
                                                        logger=Logger(name="test_logger"),
                                                        tag="NoClient")
        assert abstract_server_handler.server == "Test"
        assert abstract_server_handler.loop == loop
        assert isinstance(abstract_server_handler.last_keepalive, float)
        assert abstract_server_handler.tag == "NoClient"
        assert mock_contextvar.get() == "NoClient"


def test_AbstractServerHandler_to_dict():
    """Check the correct transformation of an AbstractServerHandler to a dict."""
    abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                    cluster_items={"test": "server"})
    abstract_server_handler.ip = "111.111.111.111"
    abstract_server_handler.name = "to_dict_testing"
    assert abstract_server_handler.to_dict() == {"info": {"ip": "111.111.111.111", "name": "to_dict_testing"}}


def test_AbstractServerHandler_connection_made():
    """Check that the connection_made function correctly assigns the IP and the transport."""

    def get_extra_info(self, name):
        return ["peername", "mock"]

    transport = Transport()
    logger = Logger("test_connection_made")
    with patch("logging.getLogger", return_value=logger):
        with patch.object(logger, "info") as mock_logger:
            abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                            cluster_items={"test": "server"})
            with patch.object(asyncio.Transport, "get_extra_info", get_extra_info):
                abstract_server_handler.connection_made(transport=transport)
                assert abstract_server_handler.ip == "peername"
                assert abstract_server_handler.transport == transport
                mock_logger.assert_called_once_with("Connection from ['peername', 'mock']")


@patch("wazuh.core.cluster.server.AbstractServerHandler.hello")
@patch("wazuh.core.cluster.server.AbstractServerHandler.echo_master")
@patch("wazuh.core.cluster.common.Handler.process_request")
def test_AbstractServerHandler_process_request(mock_process_request, mock_echo_master, mock_hello):
    """Check the behavior of the process_request function for the different commands that can be sent to it."""
    abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                    cluster_items={"test": "server"})

    abstract_server_handler.process_request(command=b"echo-c", data=b"wazuh")
    mock_echo_master.assert_called_once_with(b"wazuh")

    abstract_server_handler.process_request(command=b"hello", data=b"hi")
    mock_hello.assert_called_once_with(b"hi")

    abstract_server_handler.process_request(command=b"process", data=b"request")
    mock_process_request.assert_called_once_with(b"process", b"request")


@freeze_time("1970-01-01")
def test_AbstractServerHandler_echo_master():
    """Check that the echo_master function updates the last_keepalive variable and returns a confirmation message."""

    abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                    cluster_items={"test": "server"})

    assert abstract_server_handler.echo_master(data=b"wazuh") == (b"ok-m ", b"wazuh")
    abstract_server_handler.echo_master(data=b"wazuh")
    assert abstract_server_handler.last_keepalive == 0.0


def test_AbstractServerHandler_hello():
    """Check that the information of the new client invoking this function is stored correctly."""

    class ServerMock:
        def __init__(self):
            self.clients = {}
            self.configuration = {"node_name": "elif_test"}

    abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                    cluster_items={"test": "server"})
    abstract_server_handler.server = ServerMock()
    abstract_server_handler.tag = "FixBehaviour"

    with patch("wazuh.core.cluster.server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
        assert abstract_server_handler.hello(b"else_test") == (b"ok",
                                                               f"Client {abstract_server_handler.name} added".encode())
        assert abstract_server_handler.name == "else_test"
        assert abstract_server_handler.server.clients["else_test"] == abstract_server_handler
        assert abstract_server_handler.tag == f"FixBehaviour {abstract_server_handler.name}"
        assert mock_contextvar.get() == abstract_server_handler.tag

    with pytest.raises(WazuhClusterError, match=".* 3029 .*"):
        abstract_server_handler.hello(b"elif_test")

    abstract_server_handler.server.clients["if_test"] = "testing"
    with pytest.raises(WazuhClusterError, match=f".* 3028 .* b'if_test'"):
        abstract_server_handler.hello(b"if_test")
    assert abstract_server_handler.name == ""


@patch("wazuh.core.cluster.common.Handler.process_response")
def test_AbstractServerHandler_process_response(process_response_mock):
    """Check that the process_response function processes the response according to the command sent."""
    abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                    cluster_items={"test": "server"})
    assert abstract_server_handler.process_response(command=b"ok-c", payload=b"test") == \
           b"Successful response from client: test"

    abstract_server_handler.process_response(command=b"else", payload=b"test")
    process_response_mock.assert_called_once_with(b"else", b"test")


def test_AbstractServerHandler_connection_lost():
    """Check that the process of client disconnection is done correctly. Removing all the information of this one."""

    class ServerMock:
        def __init__(self):
            self.clients = {"unit": "test"}
            self.configuration = {"node_name": "elif_test"}

    logger = Logger("test_connection_made")
    with patch("logging.getLogger", return_value=logger):
        abstract_server_handler = AbstractServerHandler(server="Test", loop=loop, fernet_key=fernet_key,
                                                        cluster_items={"test": "server"})
        with patch.object(logger, "error") as mock_error_logger:
            abstract_server_handler.connection_lost(exc=None)
            mock_error_logger.assert_called_once_with("Error during handshake with incoming connection.")

        with patch.object(logger, "error") as mock_error_logger:
            abstract_server_handler.connection_lost(exc=Exception("Test_connection_lost"))
            mock_error_logger.assert_called_once_with(
                "Error during handshake with incoming connection: Test_connection_lost", exc_info=True)

        abstract_server_handler.name = "unit"
        abstract_server_handler.server = ServerMock()
        with patch.object(logger, "error") as mock_error_logger:
            abstract_server_handler.connection_lost(exc=Exception("Test_connection_lost_if"))
            mock_error_logger.assert_called_once_with("Error during connection with 'unit': Test_connection_lost_if.\n")
            assert "unit" not in abstract_server_handler.server.clients.keys()

        with patch.object(logger, "debug") as mock_debug_logger:
            abstract_server_handler.connection_lost(exc=None)
            mock_debug_logger.assert_called_once_with("Disconnected unit.")


@patch("asyncio.get_running_loop", return_value=loop)
def test_AbstractServer_init(loop_mock):
    """Check the correct initialization of the AbstractServer object."""
    with patch("wazuh.core.cluster.server.context_tag", ContextVar("tag", default="")) as mock_contextvar:
        abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                         cluster_items={"test4": 4}, enable_ssl=True)

        assert abstract_server.clients == {}
        assert abstract_server.performance == 1
        assert abstract_server.concurrency == 2
        assert abstract_server.configuration == {"test3": 3}
        assert abstract_server.cluster_items == {"test4": 4}
        assert abstract_server.enable_ssl is True
        assert abstract_server.tag == "Abstract Server"
        assert mock_contextvar.get() == "Abstract Server"
        assert isinstance(abstract_server.logger, Logger)

        logger = Logger("abs")
        abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                         cluster_items={"test4": 4}, enable_ssl=True, logger=logger, tag="test")
        assert abstract_server.tag == "test"
        assert mock_contextvar.get() == "test"
        assert abstract_server.logger == logger


@patch("asyncio.get_running_loop", return_value=loop)
def test_AbstractServer_to_dict(loop_mock):
    """Check the correct transformation of an AbstractServer to a dict."""
    configuration = {"test_to_dict": 0,
                     "nodes": [0, 1],
                     "node_name": "worker2"}
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration=configuration,
                                     cluster_items={"test4": 4}, enable_ssl=True)
    assert abstract_server.to_dict() == {"info": {"ip": configuration["nodes"][0], "name": configuration['node_name']}}


@patch("asyncio.get_running_loop", return_value=loop)
def test_AbstractServer_setup_task_logger(loop_mock):
    """Check that a logger is created with a specific tag."""
    logger = Logger("setup_task_logger")
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                     cluster_items={"test4": 4}, enable_ssl=True, logger=logger)
    assert abstract_server.setup_task_logger(task_tag="zxf").name == "setup_task_logger.zxf"

    with patch.object(abstract_server.logger, "getChild") as mock_child:
        abstract_server.setup_task_logger(task_tag="fxz")
        mock_child.assert_called_with("fxz")


@patch("wazuh.core.cluster.server.utils.process_array")
@patch("asyncio.get_running_loop", return_value=loop)
def test_AbstractServer_get_connected_nodes(loop_mock, mock_process_array):
    """Check that all the necessary data is sent to the utils.process_array
    function to return all the information of the connected nodes."""
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                     cluster_items={"test4": 4}, enable_ssl=True)
    basic_dict = {"info": {"first": "test"}}

    with patch.object(abstract_server, "to_dict", return_value=basic_dict):
        abstract_server.get_connected_nodes(search={"value": "wazuh", "negation": True},
                                            sort={"fields": ["nothing"], "order": "desc"}, limit=501, offset=1)
        mock_process_array.assert_called_once_with([basic_dict["info"]], search_text="wazuh", complementary_search=True,
                                                   sort_by=["nothing"], sort_ascending=False,
                                                   allowed_sort_fields=basic_dict["info"].keys(), offset=1, limit=501)
        mock_process_array.reset_mock()


@patch("wazuh.core.cluster.server.utils.process_array")
@patch("asyncio.get_running_loop", return_value=loop)
def test_AbstractServer_get_connected_nodes_ko(loop_mock, mock_process_array):
    """Check all exceptions that can be returned by the get_connected_nodes function."""
    abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                     cluster_items={"test4": 4}, enable_ssl=True)
    basic_dict = {"info": {"first": "test"}}

    with patch.object(abstract_server, "to_dict", return_value=basic_dict):
        abstract_server.get_connected_nodes()
        mock_process_array.assert_called_once_with([basic_dict["info"]], search_text=None, complementary_search=False,
                                                   sort_by=None, sort_ascending=True,
                                                   allowed_sort_fields=basic_dict["info"].keys(), offset=0, limit=500)
        mock_process_array.reset_mock()

        with pytest.raises(WazuhError, match=".* 1724 .* Not a valid select field: no"):
            abstract_server.get_connected_nodes(select={"no": "exists"})

        with pytest.raises(WazuhError, match=".* 1728 .*"):
            abstract_server.get_connected_nodes(filter_type="None")

        abstract_server.configuration = {"node_name": "master"}
        with pytest.raises(WazuhResourceNotFound, match=".* 1730 .*"):
            abstract_server.get_connected_nodes(filter_node="worker")


@pytest.mark.asyncio
@patch("asyncio.sleep", side_effect=IndexError)
@patch("asyncio.get_running_loop", return_value=loop)
async def test_AbstractServer_check_clients_keepalive(loop_mock, sleep_mock):
    """Check that the function check_clients_keepalive checks the date of the
    last last_keepalive of the clients to verify if they are connected or not."""

    class TransportMock:
        def close(self):
            pass

    class ClientMock:
        def __init__(self):
            self.last_keepalive = 0
            self.transport = TransportMock()

    logger = Logger("test_check_clients_keepalive")
    with patch.object(logger, "debug") as mock_debug:
        with patch.object(logger, "error") as mock_error:
            with patch("wazuh.core.cluster.server.AbstractServer.setup_task_logger",
                       return_value=logger):
                abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                                 cluster_items={"test4": 4}, enable_ssl=True, logger=logger)
                tester = "check_clients_keepalive"
                abstract_server.cluster_items = {"intervals": {"master": {"check_worker_lastkeepalive": tester}}}
                try:
                    await abstract_server.check_clients_keepalive()
                except IndexError:
                    pass
                mock_debug.assert_has_calls([call("Calculated."), call("Calculating.")], any_order=True)
                sleep_mock.assert_called_once_with(tester)

                abstract_server.cluster_items = {"intervals": {"master": {"max_allowed_time_without_keepalive": 0,
                                                                          "check_worker_lastkeepalive": tester}}}
                abstract_server.clients = {"worker_test": ClientMock()}
                try:
                    await abstract_server.check_clients_keepalive()
                except IndexError:
                    pass
                mock_error.assert_called_once_with("No keep alives have been received from "
                                                   "worker_test in the last minute. Disconnecting")


@pytest.mark.asyncio
@patch("asyncio.sleep", side_effect=IndexError)
@patch("asyncio.get_running_loop", return_value=loop)
async def test_AbstractServer_echo(loop_mock, sleep_mock):
    """Check that the echo function sends a message to all clients and that the information is written to the log."""

    class ClientMock:
        async def send_request(self, command, data):
            return data + b" mock"

    logger = Logger("test_echo")
    with patch.object(logger, "debug") as mock_debug:
        with patch.object(logger, "info") as mock_info:
            abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                             cluster_items={"test4": 4}, enable_ssl=True, logger=logger)
            abstract_server.clients = {b"worker_test": ClientMock()}
            try:
                await abstract_server.echo()
            except IndexError:
                pass
            mock_debug.assert_called_once_with("Sending echo to worker b'worker_test'")
            mock_info.assert_called_once_with("keepalive worker_test mock")


@freeze_time("2022-01-01")
@patch("asyncio.sleep", side_effect=IndexError)
@patch("asyncio.get_running_loop", return_value=loop)
async def test_AbstractServer_performance_test(loop_mock, sleep_mock):
    """Check that the function performance_test sends a big message to all clients
     and then get the time it took to send them."""

    class ClientMock:
        async def send_request(self, command, data):
            return data * 10

    logger = Logger("test_echo")
    with patch.object(logger, "info") as mock_info:
        abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                         cluster_items={"test4": 4}, enable_ssl=True, logger=logger)
        abstract_server.clients = {b"worker_test": ClientMock()}
        abstract_server.performance = 2
        try:
            await abstract_server.performance_test()
        except IndexError:
            pass
        mock_info.assert_called_once_with("Received size: 20 // Time: 0.0")


@freeze_time("2022-01-01")
@patch("asyncio.sleep", side_effect=IndexError)
@patch("asyncio.get_running_loop", return_value=loop)
async def test_AbstractServer_concurrency_test(loop_mock, sleep_mock):
    """Check that the function concurrency_test sends messages to all clients
     and then get the time it took to send them."""

    class ClientMock:
        async def send_request(self, command, data):
            pass

    logger = Logger("test_echo")
    with patch.object(logger, "info") as mock_info:
        abstract_server = AbstractServer(performance_test=1, concurrency_test=2, configuration={"test3": 3},
                                         cluster_items={"test4": 4}, enable_ssl=True, logger=logger)
        abstract_server.clients = {b"worker_test": ClientMock()}
        abstract_server.concurrency = 777
        try:
            await abstract_server.concurrency_test()
        except IndexError:
            pass
        mock_info.assert_called_once_with("Time sending 777 messages: 0.0")


@pytest.mark.asyncio
@patch("os.path.join", return_value="testing_path")
@patch("uvloop.EventLoopPolicy")
@patch("asyncio.set_event_loop_policy")
@patch("asyncio.sleep", side_effect=IndexError)
async def test_AbstractServer_start(sleep_mock, set_event_loop_policy_mock, eventlooppolicy_mock, mock_path_join):
    """Check that the start function starts infinite asynchronous tasks according
    to the parameters with which the AbstractServer object has been created."""

    class LoopMock:
        def set_exception_handler(self, handler):
            pass

        async def create_server(self, protocol_factory, host, port, ssl):
            pass

    async def async_mock(dummy, dummy1=None):
        pass

    class SSLMock:
        def load_cert_chain(self):
            pass

    logger = Logger("test_echo")
    loop_mock = LoopMock()

    with patch("asyncio.gather", side_effect=async_mock):
        with patch.object(loop_mock, "set_exception_handler") as set_exception_handler_mock:
            with patch.object(loop_mock, "create_server") as create_server_mock:
                with patch("asyncio.get_running_loop", return_value=loop_mock):
                    with patch("wazuh.core.cluster.server.context_tag",
                               ContextVar("tag", default="")) as mock_contextvar:
                        cluster_items = {"intervals": {"master": {"check_worker_lastkeepalive": 987}}}
                        abstract_server = AbstractServer(performance_test=1, concurrency_test=2,
                                                         configuration={"bind_addr": 3, "port": 10000},
                                                         cluster_items=cluster_items, enable_ssl=False, logger=logger)

                        with patch.object(abstract_server, "handler_class"):
                            with patch.object(abstract_server, "tasks", []):
                                abstract_server.configuration["key"] = fernet_key
                                abstract_server.tag = "start_test"
                                await abstract_server.start()
                                assert mock_contextvar.get() == "start_test"
                                set_exception_handler_mock.assert_called_once_with(c_common.asyncio_exception_handler)
                                eventlooppolicy_mock.assert_called_once()
                                set_event_loop_policy_mock.assert_called_once()
                                create_server_mock.assert_awaited_once()

                    ssl_mock = SSLMock()
                    with patch("ssl.create_default_context", return_value=ssl_mock) as create_default_context_mock:
                        with patch.object(ssl_mock, "load_cert_chain") as load_cert_chain_mock:
                            await AbstractServer(performance_test=1, concurrency_test=2,
                                                 configuration={"bind_addr": 3, "port": 10000},
                                                 cluster_items=cluster_items, enable_ssl=True,
                                                 logger=logger).start()

                            create_default_context_mock.assert_called_once_with(purpose=ssl.Purpose.CLIENT_AUTH)
                            load_cert_chain_mock.assert_called_once_with(certfile="testing_path",
                                                                         keyfile="testing_path")


@pytest.mark.asyncio
@patch("wazuh.core.cluster.server.AbstractServerHandler")
@patch("uvloop.EventLoopPolicy")
@patch("asyncio.set_event_loop_policy")
@patch("asyncio.sleep", side_effect=IndexError)
async def test_AbstractServer_start_ko(sleep_mock, set_event_loop_policy_mock, eventlooppolicy_mock,
                                       mock_AbstractServerHandler):
    """Check for exceptions that may arise inside the start function."""

    class LoopMock:
        def set_exception_handler(self, handler):
            pass

        async def create_server(self, protocol_factory, host, port, ssl):
            raise OSError("test_start")

    logger = Logger("start")
    with patch("asyncio.get_running_loop", return_value=LoopMock()):
        with patch("logging.getLogger", return_value=logger):
            with patch.object(logger, "error") as mock_logger:
                with pytest.raises(KeyboardInterrupt):
                    abstract_server = AbstractServer(performance_test=1, concurrency_test=2,
                                                     configuration={"bind_addr": 3, "port": 10000},
                                                     cluster_items={"intervals":
                                                                        {"master":
                                                                             {"check_worker_lastkeepalive": 987}
                                                                         }
                                                                    },
                                                     enable_ssl=False, logger=logger)
                    abstract_server.configuration["key"] = fernet_key
                    await abstract_server.start()
                    mock_logger.assert_called_once_with("Could not start master: ")
