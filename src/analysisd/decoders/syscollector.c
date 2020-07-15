/*
* Copyright (C) 2015-2020, Wazuh Inc.
* August 30, 2017.
*
* This program is free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* Syscollector decoder */

#include "config.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "external/cJSON/cJSON.h"
#include "plugin_decoders.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"
#include "string_op.h"
#include <time.h>
#include "wazuhdb_op.h"

static int error_package = 0;
static int prev_package_id = 0;
static int error_port = 0;
static int prev_port_id = 0;
static int error_process = 0;
static int prev_process_id = 0;

static int decode_netinfo( Eventinfo *lf, cJSON * logJSON,int *socket);
static int decode_osinfo( Eventinfo *lf, cJSON * logJSON,int *socket);
static int decode_hardware( Eventinfo *lf, cJSON * logJSON,int *socket);
static int decode_package( Eventinfo *lf, cJSON * logJSON,int *socket);
static int decode_hotfix(Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_port( Eventinfo *lf, cJSON * logJSON,int *socket);
static int decode_process( Eventinfo *lf, cJSON * logJSON,int *socket);

static OSDecoderInfo *sysc_decoder = NULL;

void SyscollectorInit(){

    os_calloc(1, sizeof(OSDecoderInfo), sysc_decoder);
    sysc_decoder->id = getDecoderfromlist(SYSCOLLECTOR_MOD);
    sysc_decoder->name = SYSCOLLECTOR_MOD;
    sysc_decoder->type = OSSEC_RL;
    sysc_decoder->fts = 0;

    mdebug1("SyscollectorInit completed.");
}

/* Special decoder for syscollector */
int DecodeSyscollector(Eventinfo *lf,int *socket)
{
    cJSON *logJSON;
    cJSON *json_type;
    char *msg_type = NULL;

    lf->decoder_info = sysc_decoder;

    // Check location
    if (lf->location[0] == '(') {
        char* search;
        search = strchr(lf->location, '>');
        if (!search) {
            mdebug1("Invalid received event.");
            return (0);
        }
        else if (strcmp(search + 1, "syscollector") != 0) {
            mdebug1("Invalid received event. Not syscollector.");
            return (0);
        }
    } else if (strcmp(lf->location, "syscollector") != 0) {
        mdebug1("Invalid received event. (Location)");
        return (0);
    }

    // Parsing event.

    const char *jsonErrPtr;
    logJSON = cJSON_ParseWithOpts(lf->log, &jsonErrPtr, 0);
    if (!logJSON) {
        mdebug1("Error parsing JSON event.");
        mdebug2("Input JSON: '%s", lf->log);
        return (0);
    }

    // Detect message type
    json_type = cJSON_GetObjectItem(logJSON, "type");
    if (!(json_type && (msg_type = json_type->valuestring))) {
        mdebug1("Invalid message. Type not found.");
        cJSON_Delete (logJSON);
        return (0);
    }

    fillData(lf,"type",msg_type);
    if (strcmp(msg_type, "port") == 0 || strcmp(msg_type, "port_end") == 0) {
        if (decode_port(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send ports information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "program") == 0 || strcmp(msg_type, "program_end") == 0) {
        if (decode_package(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send packages information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "hotfix") == 0 || strcmp(msg_type, "hotfix_end") == 0) {
        if (decode_hotfix(lf, logJSON, socket) < 0) {
            mdebug1("Unable to send hotfixes information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "hardware") == 0) {
        if (decode_hardware(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send hardware information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "OS") == 0) {
        if (decode_osinfo(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send osinfo message to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "network") == 0 || strcmp(msg_type, "network_end") == 0) {
        if (decode_netinfo(lf, logJSON, socket) < 0) {
            merror("Unable to send netinfo message to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "process") == 0 || strcmp(msg_type, "process_end") == 0) {
        if (decode_process(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send processes information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else {
        mdebug1("Invalid message type: %s.", msg_type);
        cJSON_Delete (logJSON);
        return (0);
    }

    cJSON_Delete (logJSON);
    return (1);
}

int decode_netinfo(Eventinfo *lf, cJSON * logJSON, int *socket) {

    char *msg;
    char *response;
    cJSON * iface;
    char id[OS_SIZE_1024];
    int i;
    int retval = -1;

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    if (iface = cJSON_GetObjectItem(logJSON, "iface"), iface) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * name = cJSON_GetObjectItem(iface, "name");
        cJSON * adapter = cJSON_GetObjectItem(iface, "adapter");
        cJSON * type = cJSON_GetObjectItem(iface, "type");
        cJSON * state = cJSON_GetObjectItem(iface, "state");
        cJSON * mac = cJSON_GetObjectItem(iface, "MAC");
        cJSON * tx_packets = cJSON_GetObjectItem(iface, "tx_packets");
        cJSON * rx_packets = cJSON_GetObjectItem(iface, "rx_packets");
        cJSON * tx_bytes = cJSON_GetObjectItem(iface, "tx_bytes");
        cJSON * rx_bytes = cJSON_GetObjectItem(iface, "rx_bytes");
        cJSON * tx_errors = cJSON_GetObjectItem(iface, "tx_errors");
        cJSON * rx_errors = cJSON_GetObjectItem(iface, "rx_errors");
        cJSON * tx_dropped = cJSON_GetObjectItem(iface, "tx_dropped");
        cJSON * rx_dropped = cJSON_GetObjectItem(iface, "rx_dropped");
        cJSON * mtu = cJSON_GetObjectItem(iface, "MTU");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s netinfo save", lf->agent_id);

        if (scan_id) {
            snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
            fillData(lf,"netinfo.iface.name",name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (adapter) {
            wm_strcat(&msg, adapter->valuestring, '|');
            fillData(lf,"netinfo.iface.adapter",adapter->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (type) {
            wm_strcat(&msg, type->valuestring, '|');
            fillData(lf,"netinfo.iface.type",type->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
            fillData(lf,"netinfo.iface.state",state->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (mtu) {
            char _mtu[OS_SIZE_128];
            snprintf(_mtu, OS_SIZE_128 - 1, "%d", mtu->valueint);
            fillData(lf,"netinfo.iface.mtu",_mtu);
            wm_strcat(&msg, _mtu, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (mac) {
            wm_strcat(&msg, mac->valuestring, '|');
            fillData(lf,"netinfo.iface.mac",mac->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_packets) {
            char txpack[OS_SIZE_512];
            snprintf(txpack, OS_SIZE_512 - 1, "%d", tx_packets->valueint);
            fillData(lf,"netinfo.iface.tx_packets",txpack);
            wm_strcat(&msg, txpack, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_packets) {
            char rxpack[OS_SIZE_512];
            snprintf(rxpack, OS_SIZE_512 - 1, "%d", rx_packets->valueint);
            fillData(lf,"netinfo.iface.rx_packets",rxpack);
            wm_strcat(&msg, rxpack, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_bytes) {
            char txbytes[OS_SIZE_512];
            snprintf(txbytes, OS_SIZE_512 - 1, "%d", tx_bytes->valueint);
            fillData(lf,"netinfo.iface.tx_bytes",txbytes);
            wm_strcat(&msg, txbytes, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_bytes) {
            char rxbytes[OS_SIZE_512];
            snprintf(rxbytes, OS_SIZE_512 - 1, "%d", rx_bytes->valueint);
            fillData(lf,"netinfo.iface.rx_bytes",rxbytes);
            wm_strcat(&msg, rxbytes, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_errors) {
            char txerrors[OS_SIZE_512];
            snprintf(txerrors, OS_SIZE_512 - 1, "%d", tx_errors->valueint);
            fillData(lf,"netinfo.iface.tx_errors",txerrors);
            wm_strcat(&msg, txerrors, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_errors) {
            char rxerrors[OS_SIZE_512];
            snprintf(rxerrors, OS_SIZE_512 - 1, "%d", rx_errors->valueint);
            fillData(lf,"netinfo.iface.rx_errors",rxerrors);
            wm_strcat(&msg, rxerrors, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_dropped) {
            char txdropped[OS_SIZE_512];
            snprintf(txdropped, OS_SIZE_512 - 1, "%d", tx_dropped->valueint);
            fillData(lf,"netinfo.iface.tx_dropped",txdropped);
            wm_strcat(&msg, txdropped, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_dropped) {
            char rxdropped[OS_SIZE_512];
            snprintf(rxdropped, OS_SIZE_512 - 1, "%d", rx_dropped->valueint);
            fillData(lf,"netinfo.iface.rx_dropped",rxdropped);
            wm_strcat(&msg, rxdropped, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) == WDBC_OK) {
                cJSON * ip;

                if (ip = cJSON_GetObjectItem(iface, "IPv4"), ip) {

                    cJSON * address = cJSON_GetObjectItem(ip, "address");
                    cJSON * netmask = cJSON_GetObjectItem(ip, "netmask");
                    cJSON * broadcast = cJSON_GetObjectItem(ip, "broadcast");
                    cJSON * gateway = cJSON_GetObjectItem(ip, "gateway");
                    cJSON * dhcp = cJSON_GetObjectItem(ip, "dhcp");
                    cJSON * metric = cJSON_GetObjectItem(ip, "metric");

                    snprintf(msg, OS_SIZE_6144 - 1, "agent %s netproto save", lf->agent_id);

                    if (scan_id) {
                        wm_strcat(&msg, id, ' ');
                    } else {
                        wm_strcat(&msg, "NULL", ' ');
                    }

                    if (name) {
                        wm_strcat(&msg, name->valuestring, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    // Information about an IPv4 interface
                    wm_strcat(&msg, "0", '|');

                    if (gateway) {
                        wm_strcat(&msg, gateway->valuestring, '|');
                        fillData(lf,"netinfo.iface.ipv4.gateway",gateway->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (dhcp) {
                        wm_strcat(&msg, dhcp->valuestring, '|');
                        fillData(lf,"netinfo.iface.ipv4.dhcp",dhcp->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (metric) {
                        char _metric[OS_SIZE_128];
                        snprintf(_metric, OS_SIZE_128 - 1, "%d", metric->valueint);
                        fillData(lf,"netinfo.iface.ipv4.metric", _metric);
                        wm_strcat(&msg, _metric, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    char *message;
                    if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                        if (wdbc_parse_result(response, &message) != WDBC_OK) {
                            goto end;
                        }
                    } else {
                        goto end;
                    }

                    // Save addresses information into 'sys_netaddr' table

                    if (address) {
                        char *ip4_address = NULL;
                        char *ip4_netmask = NULL;
                        char *ip4_broadcast = NULL;
                        for (i = 0; i < cJSON_GetArraySize(address); i++) {

                            snprintf(msg, OS_SIZE_6144 - 1, "agent %s netaddr save", lf->agent_id);

                            if (scan_id) {
                                wm_strcat(&msg, id, ' ');
                            } else {
                                wm_strcat(&msg, "NULL", ' ');
                            }

                            if (name) {
                                wm_strcat(&msg, name->valuestring, '|');
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            // Information about an IPv4 address
                            wm_strcat(&msg, "0", '|');

                            wm_strcat(&msg, cJSON_GetArrayItem(address,i)->valuestring, '|');
                            if(i == 0){
                                os_strdup(cJSON_GetArrayItem(address,i)->valuestring, ip4_address);
                            } else {
                                wm_strcat(&ip4_address, cJSON_GetArrayItem(address,i)->valuestring, ',');
                            }

                            if (cJSON_GetArrayItem(netmask,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(netmask,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(netmask,i)->valuestring, ip4_netmask);
                                } else {
                                    wm_strcat(&ip4_netmask, cJSON_GetArrayItem(netmask,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            if (cJSON_GetArrayItem(broadcast,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(broadcast,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(broadcast,i)->valuestring, ip4_broadcast);
                                } else {
                                    wm_strcat(&ip4_broadcast, cJSON_GetArrayItem(broadcast,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            char *message;
                            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                                    if (ip4_address) {
                                        free(ip4_address);
                                    }
                                    if(ip4_netmask) {
                                        free(ip4_netmask);
                                    }
                                    if(ip4_broadcast) {
                                        free(ip4_broadcast);
                                    }
                                    goto end;
                                }
                            } else {
                                if (ip4_address) {
                                    free(ip4_address);
                                }
                                if(ip4_netmask) {
                                    free(ip4_netmask);
                                }
                                if(ip4_broadcast) {
                                    free(ip4_broadcast);
                                }
                                goto end;
                            }
                        }

                        char *array_buffer = NULL;
                        if (ip4_address) {
                            csv_list_to_json_str_array(ip4_address, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv4.address", array_buffer);
                            os_free(array_buffer);
                            free(ip4_address);
                        }
                        if(ip4_netmask) {
                            csv_list_to_json_str_array(ip4_netmask, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv4.netmask", array_buffer);
                            os_free(array_buffer);
                            free(ip4_netmask);
                        }
                        if(ip4_broadcast) {
                            csv_list_to_json_str_array(ip4_broadcast, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv4.broadcast", array_buffer);
                            os_free(array_buffer);
                            free(ip4_broadcast);
                        }
                    }
                }

                if (ip = cJSON_GetObjectItem(iface, "IPv6"), ip) {
                    cJSON * address = cJSON_GetObjectItem(ip, "address");
                    cJSON * netmask = cJSON_GetObjectItem(ip, "netmask");
                    cJSON * broadcast = cJSON_GetObjectItem(ip, "broadcast");
                    cJSON * metric = cJSON_GetObjectItem(ip, "metric");
                    cJSON * gateway = cJSON_GetObjectItem(ip, "gateway");
                    cJSON * dhcp = cJSON_GetObjectItem(ip, "dhcp");

                    snprintf(msg, OS_SIZE_6144 - 1, "agent %s netproto save", lf->agent_id);

                    if (scan_id) {
                        wm_strcat(&msg, id, ' ');
                    } else {
                        wm_strcat(&msg, "NULL", ' ');
                    }

                    if (name) {
                        wm_strcat(&msg, name->valuestring, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    // Information about an IPv6 interface
                    wm_strcat(&msg, "1", '|');

                    if (gateway) {
                        wm_strcat(&msg, gateway->valuestring, '|');
                        fillData(lf, "netinfo.iface.ipv6.gateway",gateway->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (dhcp) {
                        wm_strcat(&msg, dhcp->valuestring, '|');
                        fillData(lf, "netinfo.iface.ipv6.dhcp",dhcp->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (metric) {
                        char _metric[OS_SIZE_128];
                        snprintf(_metric, OS_SIZE_128 - 1, "%d", metric->valueint);
                        fillData(lf,"netinfo.iface.ipv6.metric",_metric);
                        wm_strcat(&msg, _metric, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    char *message;
                    if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                        if (wdbc_parse_result(response, &message) != WDBC_OK) {
                            goto end;
                        }
                    } else {
                        goto end;
                    }

                    if (address) {
                        char *ip6_address = NULL;
                        char *ip6_netmask = NULL;
                        char *ip6_broadcast = NULL;
                        for (i = 0; i < cJSON_GetArraySize(address); i++) {

                            snprintf(msg, OS_SIZE_6144 - 1, "agent %s netaddr save", lf->agent_id);

                            if (scan_id) {
                                wm_strcat(&msg, id, ' ');
                            } else {
                                wm_strcat(&msg, "NULL", ' ');
                            }

                            if (name) {
                                wm_strcat(&msg, name->valuestring, '|');
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            // Information about an IPv6 address
                            wm_strcat(&msg, "1", '|');

                            wm_strcat(&msg, cJSON_GetArrayItem(address,i)->valuestring, '|');
                            if(i == 0){
                                os_strdup(cJSON_GetArrayItem(address,i)->valuestring,ip6_address);
                            } else {
                                wm_strcat(&ip6_address, cJSON_GetArrayItem(address,i)->valuestring, ',');
                            }

                            if (cJSON_GetArrayItem(netmask,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(netmask,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(netmask,i)->valuestring,ip6_netmask);
                                } else {
                                    wm_strcat(&ip6_netmask, cJSON_GetArrayItem(netmask,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            if (cJSON_GetArrayItem(broadcast,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(broadcast,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(broadcast,i)->valuestring, ip6_broadcast);
                                } else {
                                    wm_strcat(&ip6_broadcast, cJSON_GetArrayItem(broadcast,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            char *message;
                            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                                    if (ip6_address) {
                                        free(ip6_address);
                                    }
                                    if(ip6_netmask) {
                                        free(ip6_netmask);
                                    }
                                    if(ip6_broadcast) {
                                        free(ip6_broadcast);
                                    }
                                    goto end;
                                }
                            } else {
                                if (ip6_address) {
                                    free(ip6_address);
                                }
                                if(ip6_netmask) {
                                    free(ip6_netmask);
                                }
                                if(ip6_broadcast) {
                                    free(ip6_broadcast);
                                }
                                goto end;
                            }
                        }

                        char *array_buffer = NULL;
                        if (ip6_address) {
                            csv_list_to_json_str_array(ip6_address, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv6.address", array_buffer);
                            os_free(array_buffer);
                            free(ip6_address);
                        }
                        if(ip6_netmask) {
                            csv_list_to_json_str_array(ip6_netmask, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv6.netmask", array_buffer);
                            os_free(array_buffer);
                            free(ip6_netmask);
                        }
                        if(ip6_broadcast) {
                            csv_list_to_json_str_array(ip6_broadcast, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv6.broadcast", array_buffer);
                            os_free(array_buffer);
                            free(ip6_broadcast);
                        }
                    }
                }
            } else {
                goto end;
            }
        } else {
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "network_end") == 0) {

            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
            snprintf(msg, OS_SIZE_6144 - 1, "agent %s netinfo del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    goto end;
                }
            } else {
                goto end;
            }
        } else {
            merror("at decode_netinfo(): unknown type found.");
            goto end;
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_osinfo( Eventinfo *lf, cJSON * logJSON,int *socket) {
    cJSON * inventory;
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    if (inventory = cJSON_GetObjectItem(logJSON, "inventory"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * os_name = cJSON_GetObjectItem(inventory, "os_name");
        cJSON * os_version = cJSON_GetObjectItem(inventory, "os_version");
        cJSON * os_codename = cJSON_GetObjectItem(inventory, "os_codename");
        cJSON * hostname = cJSON_GetObjectItem(inventory, "hostname");
        cJSON * architecture = cJSON_GetObjectItem(inventory, "architecture");
        cJSON * os_major = cJSON_GetObjectItem(inventory, "os_major");
        cJSON * os_minor = cJSON_GetObjectItem(inventory, "os_minor");
        cJSON * os_build = cJSON_GetObjectItem(inventory, "os_build");
        cJSON * os_platform = cJSON_GetObjectItem(inventory, "os_platform");
        cJSON * sysname = cJSON_GetObjectItem(inventory, "sysname");
        cJSON * release = cJSON_GetObjectItem(inventory, "release");
        cJSON * version = cJSON_GetObjectItem(inventory, "version");
        cJSON * os_release = cJSON_GetObjectItem(inventory, "os_release");

        os_calloc(OS_SIZE_6144, sizeof(char), msg);

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s osinfo save", lf->agent_id);

        if (scan_id) {
            char id[OS_SIZE_1024];
            snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (hostname) {
            wm_strcat(&msg, hostname->valuestring, '|');
            fillData(lf,"os.hostname",hostname->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (architecture) {
            wm_strcat(&msg, architecture->valuestring, '|');
            fillData(lf,"os.architecture",architecture->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_name) {
            wm_strcat(&msg, os_name->valuestring, '|');
            fillData(lf,"os.name",os_name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_version) {
            wm_strcat(&msg, os_version->valuestring, '|');
            fillData(lf,"os.version",os_version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_codename) {
            wm_strcat(&msg, os_codename->valuestring, '|');
            fillData(lf,"os.codename",os_codename->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_major) {
            wm_strcat(&msg, os_major->valuestring, '|');
            fillData(lf,"os.major",os_major->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_minor) {
            wm_strcat(&msg, os_minor->valuestring, '|');
            fillData(lf,"os.minor",os_minor->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_build) {
            wm_strcat(&msg, os_build->valuestring, '|');
            fillData(lf,"os.build",os_build->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_platform) {
            wm_strcat(&msg, os_platform->valuestring, '|');
            fillData(lf,"os.platform",os_platform->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sysname) {
            wm_strcat(&msg, sysname->valuestring, '|');
            fillData(lf,"os.sysname",sysname->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (release) {
            wm_strcat(&msg, release->valuestring, '|');
            fillData(lf,"os.release",release->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (version) {
            wm_strcat(&msg, version->valuestring, '|');
            fillData(lf,"os.release_version",version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_release) {
            wm_strcat(&msg, os_release->valuestring, '|');
            fillData(lf,"os.os_release",os_release->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        os_calloc(OS_SIZE_6144, sizeof(char), response);
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                goto end;
            }
        } else {
            goto end;
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_port( Eventinfo *lf, cJSON * logJSON,int *socket) {

    char * msg = NULL;
    char * response = NULL;
    int retval = -1;
    cJSON * scan_id;

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "port"), inventory) {
        if (error_port) {
            if (scan_id->valueint == prev_port_id) {
                retval = 0;
                goto end;
            } else {
                error_port = 0;
            }
        }
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * protocol = cJSON_GetObjectItem(inventory, "protocol");
        cJSON * local_ip = cJSON_GetObjectItem(inventory, "local_ip");
        cJSON * local_port = cJSON_GetObjectItem(inventory, "local_port");
        cJSON * remote_ip = cJSON_GetObjectItem(inventory, "remote_ip");
        cJSON * remote_port = cJSON_GetObjectItem(inventory, "remote_port");
        cJSON * tx_queue = cJSON_GetObjectItem(inventory, "tx_queue");
        cJSON * rx_queue = cJSON_GetObjectItem(inventory, "rx_queue");
        cJSON * inode = cJSON_GetObjectItem(inventory, "inode");
        cJSON * state = cJSON_GetObjectItem(inventory, "state");
        cJSON * pid = cJSON_GetObjectItem(inventory, "PID");
        cJSON * process = cJSON_GetObjectItem(inventory, "process");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s port save", lf->agent_id);

        char id[OS_SIZE_1024];
        snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
        wm_strcat(&msg, id, ' ');

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (protocol) {
            wm_strcat(&msg, protocol->valuestring, '|');
            fillData(lf,"port.protocol",protocol->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (local_ip) {
            wm_strcat(&msg, local_ip->valuestring, '|');
            fillData(lf,"port.local_ip",local_ip->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (local_port) {
            char lport[OS_SIZE_128];
            snprintf(lport, OS_SIZE_128 - 1, "%d", local_port->valueint);
            fillData(lf,"port.local_port",lport);
            wm_strcat(&msg, lport, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (remote_ip) {
            wm_strcat(&msg, remote_ip->valuestring, '|');
            fillData(lf,"port.remote_ip",remote_ip->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (remote_port) {
            char rport[OS_SIZE_128];
            snprintf(rport, OS_SIZE_128 - 1, "%d", remote_port->valueint);
            fillData(lf,"port.remote_port",rport);
            wm_strcat(&msg, rport, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_queue) {
            char txq[OS_SIZE_512];
            snprintf(txq, OS_SIZE_512 - 1, "%d", tx_queue->valueint);
            fillData(lf,"port.tx_queue",txq);
            wm_strcat(&msg, txq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_queue) {
            char rxq[OS_SIZE_512];
            snprintf(rxq, OS_SIZE_512 - 1, "%d", rx_queue->valueint);
            fillData(lf,"port.rx_queue",rxq);
            wm_strcat(&msg, rxq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (inode) {
            char _inode[OS_SIZE_512];
            snprintf(_inode, OS_SIZE_512 - 1, "%d", inode->valueint);
            fillData(lf,"port.inode",_inode);
            wm_strcat(&msg, _inode, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
            fillData(lf,"port.state",state->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pid) {
            char _pid[OS_SIZE_512];
            snprintf(_pid, OS_SIZE_512 - 1, "%d", pid->valueint);
            fillData(lf,"port.pid",_pid);
            wm_strcat(&msg, _pid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (process) {
            wm_strcat(&msg, process->valuestring, '|');
            fillData(lf,"port.process",process->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                error_port = 1;
                prev_port_id = scan_id->valueint;
                goto end;
            }
        } else {
            error_port = 1;
            prev_port_id = scan_id->valueint;
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "port_end") == 0) {
            if (error_port) {
                if (scan_id->valueint == prev_port_id) {
                    retval = 0;
                    goto end;
                } else {
                    error_port = 0;
                }
            }

            snprintf(msg, OS_SIZE_6144 - 1, "agent %s port del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    error_port = 1;
                    prev_port_id = scan_id->valueint;
                    goto end;
                }
            } else {
                error_port = 1;
                prev_port_id = scan_id->valueint;
                goto end;
            }
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_hardware( Eventinfo *lf, cJSON * logJSON,int *socket) {
    cJSON * inventory;
    int retval = -1;
    char *msg = NULL;
    char *response = NULL;

    if (inventory = cJSON_GetObjectItem(logJSON, "inventory"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * serial = cJSON_GetObjectItem(inventory, "board_serial");
        cJSON * cpu_name = cJSON_GetObjectItem(inventory, "cpu_name");
        cJSON * cpu_cores = cJSON_GetObjectItem(inventory, "cpu_cores");
        cJSON * cpu_mhz = cJSON_GetObjectItem(inventory, "cpu_mhz");
        cJSON * ram_total = cJSON_GetObjectItem(inventory, "ram_total");
        cJSON * ram_free = cJSON_GetObjectItem(inventory, "ram_free");
        cJSON * ram_usage = cJSON_GetObjectItem(inventory, "ram_usage");

        os_calloc(OS_SIZE_6144, sizeof(char), msg);

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s hardware save", lf->agent_id);

        if (scan_id) {
            char id[OS_SIZE_1024];
            snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (serial) {
            wm_strcat(&msg, serial->valuestring, '|');
            fillData(lf,"hardware.serial",serial->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_name) {
            wm_strcat(&msg, cpu_name->valuestring, '|');
            fillData(lf,"hardware.cpu_name",cpu_name->valuestring);

        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_cores) {
            char cores[OS_SIZE_128];
            snprintf(cores, OS_SIZE_128 - 1, "%d", cpu_cores->valueint);
            fillData(lf,"hardware.cpu_cores",cores);
            wm_strcat(&msg, cores, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_mhz) {
            char freq[OS_SIZE_512];
            snprintf(freq, OS_SIZE_512 - 1, "%f", cpu_mhz->valuedouble);
            fillData(lf,"hardware.cpu_mhz",freq);
            wm_strcat(&msg, freq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_total) {
            char total[OS_SIZE_512];
            snprintf(total, OS_SIZE_512 - 1, "%f", ram_total->valuedouble);
            fillData(lf,"hardware.ram_total",total);
            wm_strcat(&msg, total, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_free) {
            char rfree[OS_SIZE_512];
            snprintf(rfree, OS_SIZE_512 - 1, "%f", ram_free->valuedouble);
            fillData(lf,"hardware.ram_free",rfree);
            wm_strcat(&msg, rfree, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_usage) {
            char usage[OS_SIZE_128];
            snprintf(usage, OS_SIZE_128 - 1, "%d", ram_usage->valueint);
            fillData(lf,"hardware.ram_usage",usage);
            wm_strcat(&msg, usage, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        os_calloc(OS_SIZE_6144, sizeof(char), response);
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                goto end;
            }
        } else {
            goto end;
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_package( Eventinfo *lf,cJSON * logJSON,int *socket) {
    char * msg = NULL;
    char * response = NULL;
    cJSON * package;
    cJSON * scan_id;
    int retval = -1;

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    if (package = cJSON_GetObjectItem(logJSON, "program"), package) {
        if (error_package) {
            if (scan_id->valueint == prev_package_id) {
                retval = 0;
                goto end;
            } else {
                error_package = 0;
            }
        }
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * format = cJSON_GetObjectItem(package, "format");
        cJSON * name = cJSON_GetObjectItem(package, "name");
        cJSON * priority = cJSON_GetObjectItem(package, "priority");
        cJSON * section = cJSON_GetObjectItem(package, "group");
        cJSON * size = cJSON_GetObjectItem(package, "size");
        cJSON * vendor = cJSON_GetObjectItem(package, "vendor");
        cJSON * version = cJSON_GetObjectItem(package, "version");
        cJSON * architecture = cJSON_GetObjectItem(package, "architecture");
        cJSON * multiarch = cJSON_GetObjectItem(package, "multi-arch");
        cJSON * source = cJSON_GetObjectItem(package, "source");
        cJSON * description = cJSON_GetObjectItem(package, "description");
        cJSON * installtime = cJSON_GetObjectItem(package, "install_time");
        cJSON * location = cJSON_GetObjectItem(package, "location");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s package save", lf->agent_id);

        char id[OS_SIZE_1024];
        snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
        wm_strcat(&msg, id, ' ');

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (format) {
            wm_strcat(&msg, format->valuestring, '|');
            fillData(lf,"program.format",format->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
            fillData(lf,"program.name",name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (priority) {
            wm_strcat(&msg, priority->valuestring, '|');
            fillData(lf,"program.priority",priority->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (section) {
            wm_strcat(&msg, section->valuestring, '|');
            fillData(lf,"program.section",section->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (size) {
            char _size[OS_SIZE_512];
            snprintf(_size, OS_SIZE_512 - 1, "%d", size->valueint);
            fillData(lf,"program.size",_size);
            wm_strcat(&msg, _size, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (vendor) {
            wm_strcat(&msg, vendor->valuestring, '|');
            fillData(lf,"program.vendor",vendor->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (installtime) {
            wm_strcat(&msg, installtime->valuestring, '|');
            fillData(lf,"program.install_time",installtime->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (version) {
            wm_strcat(&msg, version->valuestring, '|');
            fillData(lf,"program.version",version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (architecture) {
            wm_strcat(&msg, architecture->valuestring, '|');
            fillData(lf,"program.architecture",architecture->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (multiarch) {
            wm_strcat(&msg, multiarch->valuestring, '|');
            fillData(lf,"program.multiarch",multiarch->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (source) {
            wm_strcat(&msg, source->valuestring, '|');
            fillData(lf,"program.source",source->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (description) {
            wm_strcat(&msg, description->valuestring, '|');
            fillData(lf,"program.description",description->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (location) {
            wm_strcat(&msg, location->valuestring, '|');
            fillData(lf,"program.location",location->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                error_package = 1;
                prev_package_id = scan_id->valueint;
                goto end;
            }
        } else {
            error_package = 1;
            prev_package_id = scan_id->valueint;
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "program_end") == 0) {
            if (error_package) {
                if (scan_id->valueint == prev_package_id) {
                    retval = 0;
                    goto end;
                } else {
                    error_package = 0;
                }
            }

            snprintf(msg, OS_SIZE_6144 - 1, "agent %s package del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    error_package = 1;
                    prev_package_id = scan_id->valueint;
                    goto end;
                }
            } else {
                error_package = 1;
                prev_package_id = scan_id->valueint;
                goto end;
            }
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_hotfix(Eventinfo *lf, cJSON * logJSON, int *socket) {
    char * msg = NULL;
    cJSON * hotfix;
    cJSON * scan_id;
    cJSON * scan_time;
    char response[4096];

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_1024, sizeof(char), msg);

    if (hotfix = cJSON_GetObjectItem(logJSON, "hotfix"), hotfix) {
        scan_time = cJSON_GetObjectItem(logJSON, "timestamp");

        snprintf(msg, OS_SIZE_1024, "agent %s hotfix save %d|%s|%s|",
                lf->agent_id,
                scan_id->valueint,
                scan_time->valuestring,
                hotfix->valuestring);

        fillData(lf, "hotfix", hotfix->valuestring);
        if (wdbc_query_ex(socket, msg, response, sizeof(response)) != 0 || wdbc_parse_result(response, NULL) != WDBC_OK) {
            free(msg);
            return -1;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            free(msg);
            return -1;
        } else if (strcmp(msg_type, "hotfix_end") == 0) {
            snprintf(msg, OS_SIZE_1024 - 1, "agent %s hotfix del %d", lf->agent_id, scan_id->valueint);

            if (wdbc_query_ex(socket, msg, response, sizeof(response)) != 0 || wdbc_parse_result(response, NULL) != WDBC_OK) {
                free(msg);
                return -1;
            }
        }
    }

    free(msg);

    return 0;
}

int decode_process(Eventinfo *lf, cJSON * logJSON,int *socket) {

    int i;
    char * msg = NULL;
    char * response = NULL;
    cJSON * scan_id;
    int retval = -1;

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "process"), inventory) {
        if (error_process) {
            if (scan_id->valueint == prev_process_id) {
                retval = 0;
                goto end;
            } else {
                error_process = 0;
            }
        }
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * pid = cJSON_GetObjectItem(inventory, "pid");
        cJSON * name = cJSON_GetObjectItem(inventory, "name");
        cJSON * state = cJSON_GetObjectItem(inventory, "state");
        cJSON * ppid = cJSON_GetObjectItem(inventory, "ppid");
        cJSON * utime = cJSON_GetObjectItem(inventory, "utime");
        cJSON * stime = cJSON_GetObjectItem(inventory, "stime");
        cJSON * cmd = cJSON_GetObjectItem(inventory, "cmd");
        cJSON * argvs = cJSON_GetObjectItem(inventory, "argvs");
        cJSON * euser = cJSON_GetObjectItem(inventory, "euser");
        cJSON * ruser = cJSON_GetObjectItem(inventory, "ruser");
        cJSON * suser = cJSON_GetObjectItem(inventory, "suser");
        cJSON * egroup = cJSON_GetObjectItem(inventory, "egroup");
        cJSON * rgroup = cJSON_GetObjectItem(inventory, "rgroup");
        cJSON * sgroup = cJSON_GetObjectItem(inventory, "sgroup");
        cJSON * fgroup = cJSON_GetObjectItem(inventory, "fgroup");
        cJSON * priority = cJSON_GetObjectItem(inventory, "priority");
        cJSON * nice = cJSON_GetObjectItem(inventory, "nice");
        cJSON * size = cJSON_GetObjectItem(inventory, "size");
        cJSON * vm_size = cJSON_GetObjectItem(inventory, "vm_size");
        cJSON * resident = cJSON_GetObjectItem(inventory, "resident");
        cJSON * share = cJSON_GetObjectItem(inventory, "share");
        cJSON * start_time = cJSON_GetObjectItem(inventory, "start_time");
        cJSON * pgrp = cJSON_GetObjectItem(inventory, "pgrp");
        cJSON * session = cJSON_GetObjectItem(inventory, "session");
        cJSON * nlwp = cJSON_GetObjectItem(inventory, "nlwp");
        cJSON * tgid = cJSON_GetObjectItem(inventory, "tgid");
        cJSON * tty = cJSON_GetObjectItem(inventory, "tty");
        cJSON * processor = cJSON_GetObjectItem(inventory, "processor");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s process save", lf->agent_id);

        char id[OS_SIZE_1024];
        snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
        wm_strcat(&msg, id, ' ');

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pid) {
            char _pid[OS_SIZE_128];
            snprintf(_pid, OS_SIZE_128 - 1, "%d", pid->valueint);
            fillData(lf,"process.pid",_pid);
            wm_strcat(&msg, _pid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
            fillData(lf,"process.name",name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
            fillData(lf,"process.state",state->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ppid) {
            char _ppid[OS_SIZE_128];
            snprintf(_ppid, OS_SIZE_128 - 1, "%d", ppid->valueint);
            fillData(lf,"process.ppid",_ppid);
            wm_strcat(&msg, _ppid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (utime) {
            char _utime[OS_SIZE_128];
            snprintf(_utime, OS_SIZE_128 - 1, "%d", utime->valueint);
            fillData(lf,"process.utime",_utime);
            wm_strcat(&msg, _utime, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (stime) {
            char _stime[OS_SIZE_128];
            snprintf(_stime, OS_SIZE_128 - 1, "%d", stime->valueint);
            fillData(lf,"process.stime",_stime);
            wm_strcat(&msg, _stime, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cmd) {
            wm_strcat(&msg, cmd->valuestring, '|');
            fillData(lf,"process.cmd",cmd->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (argvs) {
            char * args = NULL;
            for (i = 0; i < cJSON_GetArraySize(argvs); i++){
                wm_strcat(&args, cJSON_GetArrayItem(argvs,i)->valuestring, ',');
            }
            char *array_buffer = cJSON_Print(argvs);
            fillData(lf, "process.args", array_buffer);
            os_free(array_buffer);
            wm_strcat(&msg, args, '|');
            free(args);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (euser) {
            wm_strcat(&msg, euser->valuestring, '|');
            fillData(lf,"process.euser",euser->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ruser) {
            wm_strcat(&msg, ruser->valuestring, '|');
            fillData(lf,"process.ruser",ruser->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (suser) {
            wm_strcat(&msg, suser->valuestring, '|');
            fillData(lf,"process.suser",suser->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (egroup) {
            wm_strcat(&msg, egroup->valuestring, '|');
            fillData(lf,"process.egroup",egroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rgroup) {
            wm_strcat(&msg, rgroup->valuestring, '|');
            fillData(lf,"process.rgroup",rgroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sgroup) {
            wm_strcat(&msg, sgroup->valuestring, '|');
            fillData(lf,"process.sgroup",sgroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (fgroup) {
            wm_strcat(&msg, fgroup->valuestring, '|');
            fillData(lf,"process.fgroup",fgroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (priority) {
            char prior[OS_SIZE_128];
            snprintf(prior, OS_SIZE_128 - 1, "%d", priority->valueint);
            fillData(lf,"process.priority",prior);
            wm_strcat(&msg, prior, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (nice) {
            char _nice[OS_SIZE_128];
            snprintf(_nice, OS_SIZE_128 - 1, "%d", nice->valueint);
            fillData(lf,"process.nice",_nice);
            wm_strcat(&msg, _nice, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (size) {
            char _size[OS_SIZE_512];
            snprintf(_size, OS_SIZE_512 - 1, "%d", size->valueint);
            fillData(lf,"process.size",_size);
            wm_strcat(&msg, _size, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (vm_size) {
            char vms[OS_SIZE_512];
            snprintf(vms, OS_SIZE_512 - 1, "%d", vm_size->valueint);
            fillData(lf,"process.vm_size",vms);
            wm_strcat(&msg, vms, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (resident) {
            char _resident[OS_SIZE_512];
            snprintf(_resident, OS_SIZE_512 - 1, "%d", resident->valueint);
            fillData(lf,"process.resident",_resident);
            wm_strcat(&msg, _resident, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (share) {
            char _share[OS_SIZE_512];
            snprintf(_share, OS_SIZE_512 - 1, "%d", share->valueint);
            fillData(lf,"process.share",_share);
            wm_strcat(&msg, _share, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (start_time) {
            char start[OS_SIZE_512];
            snprintf(start, OS_SIZE_512 - 1, "%d", start_time->valueint);
            fillData(lf,"process.start_time",start);
            wm_strcat(&msg, start, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pgrp) {
            char _pgrp[OS_SIZE_512];
            snprintf(_pgrp, OS_SIZE_512 - 1, "%d", pgrp->valueint);
            fillData(lf,"process.pgrp",_pgrp);
            wm_strcat(&msg, _pgrp, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (session) {
            char _session[OS_SIZE_512];
            snprintf(_session, OS_SIZE_512 - 1, "%d", session->valueint);
            fillData(lf,"process.session",_session);
            wm_strcat(&msg, _session, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (nlwp) {
            char _nlwp[OS_SIZE_512];
            snprintf(_nlwp, OS_SIZE_512 - 1, "%d", nlwp->valueint);
            fillData(lf,"process.nlwp",_nlwp);
            wm_strcat(&msg, _nlwp, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tgid) {
            char _tgid[OS_SIZE_512];
            snprintf(_tgid, OS_SIZE_512 - 1, "%d", tgid->valueint);
            fillData(lf,"process.tgid",_tgid);
            wm_strcat(&msg, _tgid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tty) {
            char _tty[OS_SIZE_512];
            snprintf(_tty, OS_SIZE_512 - 1, "%d", tty->valueint);
            fillData(lf,"process.tty",_tty);
            wm_strcat(&msg, _tty, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (processor) {
            char proc[OS_SIZE_512];
            snprintf(proc, OS_SIZE_512 - 1, "%d", processor->valueint);
            fillData(lf,"process.processor",proc);
            wm_strcat(&msg, proc, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                error_process = 1;
                prev_process_id = scan_id->valueint;
                goto end;
            }
        } else {
            error_process = 1;
            prev_process_id = scan_id->valueint;
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "process_end") == 0) {

            if (error_process) {
                if (scan_id->valueint == prev_process_id) {
                    retval = 0;
                    goto end;
                } else {
                    error_process = 0;
                }
            }

            snprintf(msg, OS_SIZE_6144 - 1, "agent %s process del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    error_process = 1;
                    prev_process_id = scan_id->valueint;
                    goto end;
                }
            } else {
                error_process = 1;
                prev_process_id = scan_id->valueint;
                goto end;
            }
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}
