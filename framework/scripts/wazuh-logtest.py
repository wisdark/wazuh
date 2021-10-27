#!/usr/bin/env python

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import atexit
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import textwrap

from wazuh.core import common
from wazuh.core.common import LOGTEST_SOCKET


def init_argparse():
    """Setup argpase for handle command line parameters

    Returns:
        object: argparse parser object
    """
    parser = argparse.ArgumentParser(
        description="Tool for developing, tuning, and debugging rules."
    )
    parser.add_argument(
        "-V", help='Version and license message',
        action="store_true",
        dest='version'
    )
    parser.add_argument(
        "-d", help='Execute in debug mode',
        action="store_true",
        dest='debug'
    )
    parser.add_argument(
        "-U", help='Unit test. Refer to ruleset/testing/runtests.py',
        metavar='rule:alert:decoder',
        dest='ut'
    )
    parser.add_argument(
        "-l", help='Use custom location. Default "stdin"',
        default='stdin',
        metavar='location',
        dest='location'
    )
    parser.add_argument(
        "-q", help='Quiet execution',
        dest='quiet',
        action="store_true"
    )
    parser.add_argument(
        '-v', help='Verbose (full) output/rule debugging',
        dest='verbose',
        action='store_true'
    )
    return parser


def main():
    """wazuh-logtest tool main function
    """
    # Parse cmdline args
    parser = init_argparse()
    args = parser.parse_args()
    init_logger(args)

    # Handle version request
    if args.version:
        logging.info('%s', Wazuh.get_description())
        logging.info('%s', Wazuh.get_license())
        sys.exit(0)

    # Handle unit test request
    if args.ut:
        ut = args.ut.split(":")
        if len(ut) != 3:
            logging.error('Unit test configuration wrong syntax: %s', args.ut)
            sys.exit(1)

    options = dict()
    if args.verbose:
        options['rules_debug'] = True

    # Initialize wazuh-logtest component
    w_logtest = WazuhLogtest(location=args.location)
    logging.info('Starting wazuh-logtest %s', Wazuh.get_version_str())
    logging.info('Type one log per line')

    # Cleanup: remove session before exit
    atexit.register(w_logtest.remove_last_session)

    # Main processing loop
    session_token = str()
    while True:
        # Get user input
        try:
            event = input('\n')
        # Handle user interrupt execution or EOF
        except (EOFError, KeyboardInterrupt):
            # Exit normally if ut is not selected
            if not args.ut:
                sys.exit(0)
            # Check if ut match
            elif ut == w_logtest.get_last_ut():
                # Workarround to support runtest.py
                sys.exit(ut.count(''))
            # Exit with error
            else:
                sys.exit(1)
        # Avoid empty events
        if not event:
            continue
        # Empty line to separate input from processing
        logging.info('')

        # Process log event
        try:
            output = w_logtest.process_log(event, session_token, options)
        except ValueError as error:
            logging.error('** Wazuh-logtest error ' + str(error))
            continue
        except ConnectionError:
            logging.error('** Wazuh-logtest error when connecting with wazuh-analysisd')
            continue

        # Check and alert to user if new session was created
        if session_token and session_token != output['token']:
            logging.warning('New session was created with token "%s"', output['token'])

        # Continue using last available session
        session_token = output['token']

        # Show wazuh-logtest output
        WazuhLogtest.show_output(output)

        # Show UT info
        if args.ut:
            w_logtest.show_last_ut_result(ut)


class WazuhDeamonProtocol:
    def __init__(self, version="1", origin_module="wazuh-logtest", module_name="wazuh-logtest"):
        """Class that encapsulate logic communication aspects between wazuh daemons

        Args:
            version (str, optional): protocol version. Defaults to "1".
            origin_module (str, optional): origin source module. Defaults to "wazuh-logtest".
            module_name (str, optional): origin source module. Defaults to "wazuh-logtest".
        """
        self.protocol = dict()
        self.protocol['version'] = 1
        self.protocol['origin'] = dict()
        self.protocol['origin']['name'] = origin_module
        self.protocol['origin']['module'] = module_name

    def wrap(self, command, parameters):
        """Wrap data with wazuh daemon protocol information

        Args:
            command (str): endpoint command
            parameters (dict): data to wrap

        Returns:
            dict: wrapped data
        """
        # Use default protocol template
        msg = self.protocol
        msg['command'] = command
        msg['parameters'] = parameters
        # Dump dict to str
        str_msg = json.dumps(msg)
        return str_msg

    def unwrap(self, msg):
        """Unwrap data from wazuh daemon protocol information

        Args:
            msg (dict): data to unwrap

        Returns:
            dict: unwrapped data
        """
        # Convert string to json
        json_msg = json.loads(msg)
        # Get only the payload
        if json_msg['error']:
            error_msg = json_msg['message']
            error_n = json_msg['error']
            raise ValueError(f'{error_n}: {error_msg}')
        data = json_msg['data']
        return data


class WazuhSocket:
    def __init__(self, file):
        """Encapsulate wazuh-socket communication(header with message size)

        Args:
            file ([type]): [description]
        """
        self.file = file

    def send(self, msg):
        """Send and receive data to wazuh-socket (header with message size)

        Args:
            msg (str): data to send

        Returns:
            str: received data
        """
        try:
            wlogtest_conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wlogtest_conn.connect(self.file)
            encoded_msg = msg.encode('utf-8')
            wlogtest_conn.send(struct.pack("<I", len(encoded_msg)) + encoded_msg)
            size = struct.unpack("<I", wlogtest_conn.recv(4, socket.MSG_WAITALL))[0]
            recv_msg = wlogtest_conn.recv(size, socket.MSG_WAITALL)
            wlogtest_conn.close()
            return recv_msg
        except Exception:
            raise ConnectionError


class WazuhLogtest:
    def __init__(self, location="stdin", log_format="syslog"):
        """Top level class to interact with wazuh-logtest feature, part of wazuh-analysisd

        Args:
            location (str, optional): log origin. Defaults to "master->/var/log/syslog".
            log_format (str, optional): type of log. Defaults to "syslog".
        """
        self.protocol = WazuhDeamonProtocol()
        self.socket = WazuhSocket(LOGTEST_SOCKET)
        self.fixed_fields = dict()
        self.fixed_fields['location'] = location
        self.fixed_fields['log_format'] = log_format
        self.last_token = ""
        self.ut = [''] * 3

    def process_log(self, log, token=None, options=None):
        """Send log event to wazuh-logtest and receive the outcome

        Args:
            log (str): event log to process
            token (str optional): session token. Defaults to None.

        Returns:
            dict: logtest outcome
        """

        # Use basic logtest template
        data = self.fixed_fields

        # Use token if specified
        if token:
            data['token'] = token
        data['event'] = log

        if options:
            data['options'] = options

        # Create a wrapper to log_processing
        request = self.protocol.wrap('log_processing', data)
        logging.debug('Request: %s\n', request)
        recv_packet = self.socket.send(request)

        # Get logtest reply
        logging.debug(f'Reply: %s\n', str(recv_packet,'utf-8'))
        reply = self.protocol.unwrap(recv_packet)

        if reply['codemsg'] < 0:
            error_msg = ['\n\t{0}'.format(i) for i in reply['messages']]
            error_n = reply['codemsg']
            raise ValueError(f'{error_n}: {"".join(error_msg)}')

        # Save the token
        self.last_token = reply['token']

        # Store unit test data
        self.ut = [''] * 3
        if 'rule' in reply['output']:
            self.ut[0] = reply['output']['rule']['id']
            self.ut[1] = str(reply['output']['rule']['level'])
        if 'decoder' in reply['output'] and reply['output']['decoder']:
            self.ut[2] = reply['output']['decoder']['name']
        # Return logtest payload
        return reply

    def remove_session(self, token):
        """Remove session by token

        Args:
            token (str): session token to remove

        Returns:
            dict: logtest outcome
        """

        # Use basic logtest template
        data = self.fixed_fields
        data['token'] = token
        logging.debug('Removing session with token %s.', data['token'])
        # Create a wrapper to remove_session
        request = self.protocol.wrap('remove_session', data)
        try:
            recv_packet = self.socket.send(request)
        except ConnectionError:
            return False

        # Get logtest payload
        reply = self.protocol.unwrap(recv_packet)

        if reply['codemsg'] < 0:
            return False
        else:
            return True

    def remove_last_session(self):
        """Remove last known session
        """
        if self.last_token:
            self.remove_session(self.last_token)

    def get_last_ut(self):
        """Get last known UT info (rule,alert,decoder)

        Returns:
            list of str: last rule,alert,decoder
        """
        return self.ut

    def show_output(output):
        """Display logtest event processing outcome

        Args:
            output (dict): logtest outcome
        """
        logging.debug(json.dumps(output, indent=2))
        WazuhLogtest.show_ossec_logtest_like(output)

    def show_ossec_logtest_like(output):
        """Show wazuh-logtest output like ossec-logtest

        Args:
            output (dict): wazuh-logtest outcome
        """
        output_data = output['output']
        # Pre-decoding phase
        logging.info('**Phase 1: Completed pre-decoding.')
        # Check in case rule has no_full_log attribute
        if 'full_log' in output_data:
            logging.info("\tfull event: '%s'", output_data.pop('full_log'))
        if 'predecoder' in output_data:
            WazuhLogtest.show_phase_info(output_data['predecoder'], ['timestamp', 'hostname', 'program_name'])
        # Decoding phase
        logging.info('')
        logging.info('**Phase 2: Completed decoding.')
        if 'decoder' in output_data and output_data['decoder']:
            WazuhLogtest.show_phase_info(output_data['decoder'], ['name', 'parent'])
            if 'data' in output_data:
                WazuhLogtest.show_phase_info(output_data['data'])
        else:
            logging.info('\tNo decoder matched.')

        # Rule phase

        ## Rules Debugging
        if 'rules_debug' in output:
            logging.info('')
            logging.info('**Rule debugging:')
            for debug_msg in output['rules_debug']:
                logging.info(('\t\t' if debug_msg[0] == '*' else '\t') + debug_msg)

        if 'rule' in output_data:
            logging.info('')
            logging.info('**Phase 3: Completed filtering (rules).')
            WazuhLogtest.show_phase_info(output_data['rule'], ['id', 'level', 'description', 'groups', 'firedtimes'])
        if output['alert']:
            logging.info('**Alert to be generated.')

    def show_phase_info(phase_data, show_first=[], prefix=""):
        """Show wazuh-logtest processing phase information

        Args:
            phase_data (dict): phase info to display
            show_first (list, optional): fields to be shown first. Defaults to []
            prefix (str, optional): add prefix to the name of the field to print. Default empty string
        """
        # Ordered fields first
        for field in show_first:
            if field in phase_data:
                logging.info("\t%s: '%s'", field, phase_data.pop(field))
        # Remaining fields then
        for field in sorted(phase_data.keys()):
            if isinstance(phase_data.get(field), dict):
                WazuhLogtest.show_phase_info(phase_data.pop(field), [], prefix + field + '.')
            else:
                logging.info("\t%s: '%s'", prefix + field, phase_data.pop(field))

    def show_last_ut_result(self, ut):
        """Display unit test result

        Args:
            ut (list of str): expected rule,alert,decoder
        """
        result = self.get_last_ut() == ut
        logging.info('')
        if result:
            logging.info('Unit test OK')
        else:
            logging.info('Unit test FAIL. Expected %s , Result %s', ut, self.get_last_ut())


class Wazuh:
    def get_install_path():
        """Get Wazuh installation path, obtained relative to the path of this file

        Returns:
            str: install_path
        """
        return common.find_wazuh_path()

    def get_info(field):
        """Get Wazuh information from wazuh-control

        Args:
            field (str): field to get

        Returns:
            str: field value
        """
        wazuh_control = os.path.join(Wazuh.get_install_path(), "bin", "wazuh-control")
        wazuh_env_vars = dict()
        try:
            proc = subprocess.Popen([wazuh_control, "info"], stdout=subprocess.PIPE)
            (stdout, stderr) = proc.communicate()
        except:
            return "ERROR"

        env_variables = stdout.decode().rsplit("\n")
        env_variables.remove("")
        for env_variable in env_variables:
            key, value = env_variable.split("=")
            wazuh_env_vars[key] = value.replace("\"", "")

        return wazuh_env_vars[field]

    def get_version_str():
        """Get Wazuh version string

        Returns:
            str: version
        """
        return Wazuh.get_info('WAZUH_VERSION')

    def get_description():
        """Get Wazuh description, contact info and version

        Returns:
            str: description
        """
        return 'Wazuh {} - Wazuh Inc.'.format(Wazuh.get_version_str())

    def get_license():
        """Get Wazuh License statement

        Returns:
            str: license
        """
        return textwrap.dedent('''
        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License (version 2) as
        published by the Free Software Foundation. For more details, go to
        https://www.gnu.org/licenses/gpl.html
        ''')


def init_logger(args):
    """[summary]

    Args:
        args ([type]): [description]
    """
    # Default logger configs
    logger_level = 'INFO'
    logger_fmt = '%(message)s'

    # Debug level if requested
    if args.debug:
        logger_level = 'DEBUG'
        logger_fmt = '%(asctime)-15s %(module)s[%(levelname)s] %(message)s'

    # Handle quiet request
    if args.quiet:
        logger_level = 'ERROR'
        logger_fmt = ''

    # Set logging configs
    logging.basicConfig(format=logger_fmt, level=logger_level)


if __name__ == "__main__":
    main()
