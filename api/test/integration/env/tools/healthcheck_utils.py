import json
import os
import re
import socket
import time

# Configuration
protocol = 'https'
host = 'localhost'
port = '55000'
user = 'testing'
password = 'wazuh'

# Variables
base_url = "{}://{}:{}".format(protocol, host, port)
login_url = "{}/security/user/authenticate".format(base_url)

HEALTHCHECK_TOKEN_FILE = '/tmp/healthcheck/healthcheck.token'
OSSEC_LOG_PATH = '/var/ossec/logs/ossec.log'


def get_login_header(user, password):
    from base64 import b64encode
    basic_auth = f"{user}:{password}".encode()
    return {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_response(url, headers):
    """Get API result for GET request.

    Parameters
    ----------
    url : str
        URL of the API (+ endpoint and parameters if needed).
    headers : dict
        Headers required by the API.

    Returns
    -------
    Dict
        API response for the request.
    """
    import urllib3
    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    from requests import get
    request_result = get(url, headers=headers, verify=False)

    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())


def get_agent_health_base():
    # Get agent health. The agent will be healthy if it has been connected to the manager after been
    # restarted due to shared configuration changes.
    # Using agentd when using grep as the module name can vary between ossec-agentd and wazuh-agentd,
    # depending on the agent version.

    shared_conf_restart = os.system(
        f"grep -q 'agentd: INFO: Agent is restarting due to shared configuration changes.' {OSSEC_LOG_PATH}")
    agent_connection = os.system(f"grep -q 'agentd: INFO: (4102): Connected to the server' {OSSEC_LOG_PATH}")

    if shared_conf_restart == 0 and agent_connection == 0:
        # No -q option as we need the output
        output = os.popen(
            f"grep -a 'agentd: INFO: Agent is restarting due to shared configuration changes."
            f"\|agentd: INFO: (4102): Connected to the server' {OSSEC_LOG_PATH}").read().split("\n")[:-1]

        agent_restarted = False
        for log in output:
            if not agent_restarted and re.match(r'.*Agent is restarting due to shared configuration changes.*', log):
                agent_restarted = True
            if agent_restarted and re.match(r'.*Connected to the server.*', log):
                # Wait to avoid the worst case:
                # +10 seconds for the agent to report the worker
                # +10 seconds for the worker to report master
                # After this time, the agent appears as active in the master node
                time.sleep(20)
                return 0
    return 1


def check(result):
    if result == 0:
        return 0
    else:
        return 1


def get_master_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    check0 = check(os.system("diff -q /tmp/output.txt /tmp/healthcheck/agent_control_check.txt"))
    check1 = check(os.system("diff -q /tmp/daemons.txt /tmp/healthcheck/daemons_check.txt"))
    check2 = get_api_health()
    return check0 or check1 or check2


def get_worker_health():
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    return check(os.system("diff -q /tmp/daemons.txt /tmp/healthcheck/daemons_check.txt"))


def get_manager_health_base():
    return get_master_health() if socket.gethostname() == 'wazuh-master' else get_worker_health()


def get_api_health():
    if not os.path.exists(HEALTHCHECK_TOKEN_FILE):
        if get_response(login_url, get_login_header(user, password)):
            open(HEALTHCHECK_TOKEN_FILE, mode='w').close()
            return 0
        else:
            return 1
    else:
        return 0
