#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import asyncio
import argparse
import os
import sys
import time
from wazuh.cluster import cluster, __version__, __author__, __ossec_name__, __licence__, master, local_server, worker
from wazuh import common, configuration, pyDaemonModule, Wazuh


#
# Aux functions
#
def set_logging(debug_mode=0):
    logger = logging.getLogger('wazuh')
    logger.propagate = False
    # configure logger
    fh = cluster.CustomFileRotatingHandler(filename="{}/logs/cluster.log".format(common.ossec_path), when='midnight')
    formatter = logging.Formatter(
        fmt='%(asctime)s wazuh-clusterd: %(levelname)s: [%(tag)s] [%(subtag)s] %(message)s',
        datefmt="%Y/%m/%d %H:%M:%S"
    )
    formatter.converter = time.gmtime
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.addFilter(cluster.ClusterFilter(tag='Cluster', subtag='Main'))

    # add a new debug level
    logging.DEBUG2 = 5

    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.DEBUG2, "DEBUG2")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error

    debug_level = logging.DEBUG2 if debug_mode == 2 else logging.DEBUG if \
                  debug_mode == 1 else logging.INFO

    logger.setLevel(debug_level)
    return logger


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


#
# Master main
#
async def master_main(args, cluster_config, cluster_items, logger):
    cluster.context_tag.set('Master')
    cluster.context_subtag.set("Main")
    my_server = master.Master(performance_test=args.performance_test, concurrency_test=args.concurrency_test,
                              configuration=cluster_config, enable_ssl=args.ssl, logger=logger,
                              cluster_items=cluster_items)
    my_local_server = local_server.LocalServerMaster(performance_test=args.performance_test, logger=logger,
                                                     concurrency_test=args.concurrency_test, node=my_server,
                                                     configuration=cluster_config, enable_ssl=args.ssl,
                                                     cluster_items=cluster_items)
    await asyncio.gather(my_server.start(), my_local_server.start())


#
# Worker main
#
async def worker_main(args, cluster_config, cluster_items, logger):
    cluster.context_tag.set('Worker')
    cluster.context_subtag.set("Main")
    while True:
        my_client = worker.Worker(configuration=cluster_config, enable_ssl=args.ssl,
                                  performance_test=args.performance_test, concurrency_test=args.concurrency_test,
                                  file=args.send_file, string=args.send_string, logger=logger,
                                  cluster_items=cluster_items)
        my_local_server = local_server.LocalServerWorker(performance_test=args.performance_test, logger=logger,
                                                         concurrency_test=args.concurrency_test, node=my_client,
                                                         configuration=cluster_config, enable_ssl=args.ssl,
                                                         cluster_items=cluster_items)
        try:
            await asyncio.gather(my_client.start(), my_local_server.start())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            await asyncio.sleep(cluster_items['intervals']['worker']['connection_retry'])


#
# Main
#
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    # Dev options - Silenced in the help message.
    ####################################################################################################################
    # Performance test - value stored in args.performance_test will be used to send a request of that size in bytes to
    # all clients/to the server.
    parser.add_argument('--performance_test', type=int, dest='performance_test', help=argparse.SUPPRESS)
    # Concurrency test - value stored in args.concurrency_test will be used to send that number of requests in a row,
    # without sleeping.
    parser.add_argument('--concurrency_test', type=int, dest='concurrency_test', help=argparse.SUPPRESS)
    # Send string test - value stored in args.send_string variable will be used to send a string with that size in bytes
    # to the server. Only implemented in worker nodes.
    parser.add_argument('--string', help=argparse.SUPPRESS, type=int, dest='send_string')
    # Send file test - value stored in args.send_file variable is the path of a file to send to the server. Only
    # implemented in worker nodes.
    parser.add_argument('--file', help=argparse.SUPPRESS, type=str, dest='send_file')
    ####################################################################################################################
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl', default=False)
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", action='count',
                        dest='debug_level')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.ossec_conf)
    args = parser.parse_args()

    if args.version:
        print_version()
        sys.exit(0)

    # Set logger
    try:
        debug_mode = configuration.get_internal_options_value('wazuh_clusterd', 'debug', 2, 0) or args.debug_level
    except Exception:
        debug_mode = 0

    # set correct permissions on cluster.log file
    if os.path.exists('{0}/logs/cluster.log'.format(common.ossec_path)):
        os.chown('{0}/logs/cluster.log'.format(common.ossec_path), common.ossec_uid(), common.ossec_gid())
        os.chmod('{0}/logs/cluster.log'.format(common.ossec_path), 0o660)

    main_logger = set_logging(debug_mode)

    cluster_configuration = cluster.read_config(config_file=args.config_file)
    if cluster_configuration['disabled']:
        sys.exit(0)
    cluster_items = cluster.get_cluster_items()
    try:
        cluster.check_cluster_config(cluster_configuration)
    except Exception as e:
        main_logger.error(e)
        sys.exit(1)

    if args.test_config:
        sys.exit(0)

    # clean
    cluster.clean_up()

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    # Drop privileges to ossec
    if not args.root:
        os.setgid(common.ossec_gid())
        os.setuid(common.ossec_uid())

    pyDaemonModule.create_pid('wazuh-clusterd', os.getpid())

    main_function = master_main if cluster_configuration['node_type'] == 'master' else worker_main
    try:
        asyncio.run(main_function(args, cluster_configuration, cluster_items, main_logger))
    except KeyboardInterrupt:
        main_logger.info("SIGINT received. Bye!")
    except MemoryError:
        main_logger.error("Directory '/tmp' needs read, write & execution "
                          "permission for 'ossec' user")
    except Exception as e:
        main_logger.error(f"Unhandled exception: {e}")
