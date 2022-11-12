/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remoted.h"
#include "state.h"
#include "remoted_op.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "os_net/os_net.h"
#include "shared_download.h"
#include "os_crypto/sha256/sha256_op.h"
#include <pthread.h>

#if defined(__FreeBSD__) || defined(__MACH__) || defined(__sun__)
#define HOST_NAME_MAX 64
#endif

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
  #define STATIC
#else
  #define STATIC static
#endif

/* Internal structures */
typedef struct _file_sum {
    char *name;
    os_md5 sum;
} file_sum;

typedef struct group_t {
    char *name;
    file_sum **f_sum;
    bool has_changed;
    bool exists;
} group_t;

static OSHash *invalid_files;

/* Internal functions prototypes */

/**
 * @brief Process group, update file sum structure and create merged.mg file
 * @param group Group name
 * @param _f_sum File sum structure to update
 * @param sharedcfg_dir Group directory
 * @param create_merged Flag indicating if merged.mg needs to be created
 */
STATIC void c_group(const char *group, file_sum ***_f_sum, char * sharedcfg_dir, bool create_merged);

/**
 * @brief Process multigroup, update file sum structure and create merged.mg file
 * @param multi_group Multigroup name
 * @param _f_sum File sum structure to update
 * @param hash_multigroup Multigroup hash
 * @param create_merged Flag indicating if merged.mg needs to be created
 */
STATIC void c_multi_group(char *multi_group, file_sum ***_f_sum, char *hash_multigroup, bool create_merged);

/**
 * @brief Process groups and multigroups files
 */
STATIC void c_files(void);

/**
 * @brief Analize and generate new groups, update existing groups
 */
STATIC void process_groups();

/**
 * @brief Analize and generate new multigroups, update existing multigroups
 */
STATIC void process_multi_groups();

/**
 * @brief Delete all groups that no longer exist
 */
STATIC void process_deleted_groups();

/**
 * @brief Delete all multigroups that no longer exist
 */
STATIC void process_deleted_multi_groups();

/**
 * @brief Find a group structure from its name
 * @param group Group name
 * @return Group structure if exists, NULL otherwise
 */
STATIC group_t* find_group(const char *group);

/**
 * @brief Find a multigroup structure from its name
 * @param multigroup Multigroup name
 * @return Multigroup structure if exists, NULL otherwise
 */
STATIC group_t* find_multi_group(const char *multigroup);

/**
 * @brief Find a group structure from a file name and md5
 * @param file File name
 * @param md5 MD5 of the file
 * @param group Array to store the group name if exists
 * @return Group structure if exists, NULL otherwise
 */
STATIC group_t* find_group_from_file(const char * file, const char * md5, char group[OS_SIZE_65536]);

/**
 * @brief Find a multigroup structure from a file name and md5
 * @param file File name
 * @param md5 MD5 of the file
 * @param multigroup Array to store the multigroup name if exists
 * @return Multigroup structure if exists, NULL otherwise
 */
STATIC group_t* find_multi_group_from_file(const char * file, const char * md5, char multigroup[OS_SIZE_65536]);

/**
 * @brief Compare and check if the file sum has changed
 * @param old_sum File sum of previous scan
 * @param new_sum File sum of new scan
 * @return true Changed
 * @return false Didn't change
 */
STATIC bool fsum_changed(file_sum **old_sum, file_sum **new_sum);

/**
 * @brief Check if any group of a given multigroup has changed
 * @param multi_group Multigroup name
 * @return true Any group changed
 * @return false Groups didn't change
 */
STATIC bool group_changed(const char *multi_group);

/**
 * @brief Get agent group
 * @param agent_id. Agent id to assign a group
 * @param msg. Message from agent to process and validate current configuration files
 * @param group. Name of the found group, it will include the name of the group or 'default' group or NULL if it fails.
 * @param wdb_sock Wazuh-DB socket.
 * @return OS_SUCCESS if it found or assigned a group, OS_INVALID otherwise
 */
STATIC int lookfor_agent_group(const char *agent_id, char *msg, char **group, int* wdb_sock);

/**
 * @brief Send a shared file to an agent
 * @param agent_id ID of the destination agent
 * @param group Name of the group where the file is located
 * @param name Name of the file
 * @param sum MD5 of the file
 * @param sharedcfg_dir Directory where the file is located
 * @return OS_SUCCESS if the file was sent, OS_INVALID otherwise
 */
static int send_file_toagent(const char *agent_id, const char *group, const char *name, const char *sum, char *sharedcfg_dir);

/**
 * @brief Validate files to be shared with agents, update invalid file hash table
 * @param src_path Source path of the files to validate
 * @param group Group name
 * @param merged_tmp Name of temporal merged.mg file
 * @param f_sum File sum structure to update
 * @param f_size File size variable to update
 * @param create_merged Flag indicating if merged.mg needs to be created
 * @param path_offset Variable that indicates the necessary offset for the MergeAppendFile function
 * @return 1 on shared file creation success, 0 on shared file creation failure
 */
STATIC int validate_shared_files(const char *src_path, const char *group, const char *merged_tmp, file_sum ***f_sum, unsigned int *f_size, bool create_merged, int path_offset);

/**
 * @brief Copy the contents of one directory to another
 * @param src_path Source path of the files to copy
 * @param dst_path Destination path of the files
 * @param group Group name
 * @param initial_iteration Flag indicating if it is the first iteration
 */
STATIC void copy_directory(const char *src_path, const char *dst_path, char *group, bool initial_iteration);

/* Groups structures and sizes */
static group_t **groups;
static group_t **multi_groups;
static int groups_size = 0;
static int multi_groups_size = 0;

static time_t _stime;
int INTERVAL;

/* For the last message tracking */
static w_linked_queue_t *pending_queue;
OSHash *pending_data;

/* pthread mutex variables */
static pthread_mutex_t lastmsg_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Hash table for multigroups */
OSHash *m_hash;

/* Interval polling */
static int poll_interval_time = 0;

/* This variable is used to prevent flooding when group files exceed the maximum size */
static int reported_path_size_exceeded = 0;

// Frees data in m_hash table
void cleaner(void* data) {
    os_free(data);
}

// Frees file sum structure
void free_file_sum(file_sum **f_sum) {
    if (f_sum) {
        for (unsigned int i = 0; f_sum[i]; i++) {
            os_free(f_sum[i]->name);
            os_free(f_sum[i]);
        }
        os_free(f_sum);
    }
}

/* Save a control message received from an agent
 * wait_for_msgs (other thread) is going to deal with it
 * (only if message changed)
 */
void save_controlmsg(const keyentry * key, char *r_msg, size_t msg_length, int *wdb_sock)
{
    char msg_ack[OS_FLSIZE + 1] = "";
    char *msg = NULL;
    char *end = NULL;
    pending_data_t *data = NULL;
    agent_info_data *agent_data = NULL;
    const char * agent_ip_label = "#\"_agent_ip\":";
    const char * manager_label = "#\"_manager_hostname\":";
    const char * node_label = "#\"_node_name\":";
    const char * version_label = "#\"_wazuh_version\":";
    int is_startup = 0;
    int is_shutdown = 0;
    int agent_id = 0;
    int result = 0;

    if (strncmp(r_msg, HC_REQUEST, strlen(HC_REQUEST)) == 0) {
        char * counter = r_msg + strlen(HC_REQUEST);
        char * payload = NULL;

        if (payload = strchr(counter, ' '), !payload) {
            merror("Request control format error.");
            mdebug2("r_msg = \"%s\"", r_msg);
            return;
        }

        *(payload++) = '\0';

        req_save(counter, payload, msg_length - (payload - r_msg));

        rem_inc_recv_ctrl_request(key->id);
        return;
    }

    /* Reply to the agent */
    snprintf(msg_ack, OS_FLSIZE, "%s%s", CONTROL_HEADER, HC_ACK);
    if (send_msg(key->id, msg_ack, -1) >= 0) {
        rem_inc_send_ack(key->id);
    }

    /* Filter UTF-8 characters */
    char * clean = w_utf8_filter(r_msg, true);
    r_msg = clean;

    if ((strcmp(r_msg, HC_STARTUP) == 0) || (strcmp(r_msg, HC_SHUTDOWN) == 0)) {
        char aux_ip[IPSIZE + 1] = {0};
        switch (key->peer_info.ss_family) {
        case AF_INET:
            get_ipv4_string(((struct sockaddr_in *)&(key->peer_info))->sin_addr, aux_ip, IPSIZE);
            break;
        case AF_INET6:
            get_ipv6_string(((struct sockaddr_in6 *)&(key->peer_info))->sin6_addr, aux_ip, IPSIZE);
            break;
        default:
            break;
        }
        if (strcmp(r_msg, HC_STARTUP) == 0) {
            mdebug1("Agent %s sent HC_STARTUP from '%s'", key->name, aux_ip);
            is_startup = 1;
            rem_inc_recv_ctrl_startup(key->id);
        } else {
            mdebug1("Agent %s sent HC_SHUTDOWN from '%s'", key->name, aux_ip);
            is_shutdown = 1;
            rem_inc_recv_ctrl_shutdown(key->id);
        }
    } else {
        /* Clean msg and shared files (remove random string) */
        msg = r_msg;

        if ((r_msg = strchr(r_msg, '\n'))) {
            /* Forward to random string (pass shared files) */
            for (r_msg++; (end = strchr(r_msg, '\n')); r_msg = end + 1);
            *r_msg = '\0';
        } else {
            mwarn("Invalid message from agent: '%s' (%s)", key->name, key->id);
            os_free(clean);
            return;
        }

        rem_inc_recv_ctrl_keepalive(key->id);
    }

    w_mutex_lock(&lastmsg_mutex);

    /* Check if there is a keep alive already for this agent */
    if (data = OSHash_Get(pending_data, key->id), data && data->changed && data->message && msg && strcmp(data->message, msg) == 0) {
        w_mutex_unlock(&lastmsg_mutex);

        agent_id = atoi(key->id);

        result = wdb_update_agent_keepalive(agent_id, AGENT_CS_ACTIVE, logr.worker_node ? "syncreq" : "synced", wdb_sock);

        if (OS_SUCCESS != result) {
            mwarn("Unable to save last keepalive and set connection status as active for agent: %s", key->id);
        }
    } else {
        if (!data) {
            os_calloc(1, sizeof(pending_data_t), data);

            if (OSHash_Add(pending_data, key->id, data) != 2) {
                merror("Couldn't add pending data into hash table.");
                w_mutex_unlock(&lastmsg_mutex);
                os_free(data);
                os_free(clean);
                return;
            }
        }

        if (is_startup) {
            w_mutex_unlock(&lastmsg_mutex);

            agent_id = atoi(key->id);

            result = wdb_update_agent_keepalive(agent_id, AGENT_CS_PENDING, logr.worker_node ? "syncreq" : "synced", wdb_sock);

            if (OS_SUCCESS != result) {
                mwarn("Unable to save last keepalive and set connection status as pending for agent: %s", key->id);
            }
        } else if (is_shutdown) {
            w_mutex_unlock(&lastmsg_mutex);

            agent_id = atoi(key->id);

            result = wdb_update_agent_connection_status(agent_id, AGENT_CS_DISCONNECTED, logr.worker_node ? "syncreq" : "synced", wdb_sock);

            if (OS_SUCCESS != result) {
                mwarn("Unable to set connection status as disconnected for agent: %s", key->id);
            } else {
                /* Generate alert */
                char srcmsg[OS_SIZE_256];
                char msg[OS_SIZE_1024];

                memset(srcmsg, '\0', OS_SIZE_256);
                memset(msg, '\0', OS_SIZE_1024);

                snprintf(srcmsg, OS_SIZE_256, "[%s] (%s) %s", key->id, key->name, key->ip->ip);
                snprintf(msg, OS_SIZE_1024, AG_STOP_MSG, key->name, key->ip->ip);

                /* Send stopped message */
                if (SendMSG(logr.m_queue, msg, srcmsg, SECURE_MQ) < 0) {
                    merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

                    // Try to reconnect infinitely
                    logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

                    minfo("Successfully reconnected to '%s'", DEFAULTQUEUE);

                    if (SendMSG(logr.m_queue, msg, srcmsg, SECURE_MQ) < 0) {
                        // Something went wrong sending a message after an immediate reconnection...
                        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                    }
                }
            }
        } else {
            /* Update message */
            mdebug2("save_controlmsg(): inserting '%s'", msg);

            os_free(data->message);
            os_free(data->group);
            memset(&data->merged_sum, 0, sizeof(os_md5));

            os_strdup(msg, data->message);

            if (OS_SUCCESS == lookfor_agent_group(key->id, data->message, &data->group, wdb_sock)) {
                group_t *aux = NULL;

                w_mutex_lock(&files_mutex);

                if (aux = find_group(data->group), !aux || !aux->f_sum) {
                    if (aux = find_multi_group(data->group), !aux || !aux->f_sum) {
                        mdebug1("No such group '%s' for agent '%s'", data->group, key->id);
                    }
                }

                if (aux && aux->f_sum && aux->f_sum[0] && *(aux->f_sum[0]->sum)) {
                    // Copy sum before unlock mutex
                    memcpy(data->merged_sum, aux->f_sum[0]->sum, sizeof(os_md5));
                }

                w_mutex_unlock(&files_mutex);
            } else {
                merror("Error getting group for agent '%s'", key->id);
            }

            w_mutex_unlock(&lastmsg_mutex);

            /* Parsing msg */
            os_calloc(1, sizeof(agent_info_data), agent_data);

            result = parse_agent_update_msg(msg, agent_data);

            if (OS_SUCCESS != result) {
                merror("Error parsing message for agent '%s'", key->id);
                wdb_free_agent_info_data(agent_data);
                os_free(clean);
                return;
            }

            // Appending system labels
            os_calloc(HOST_NAME_MAX, sizeof(char), agent_data->manager_host);

            if (gethostname(agent_data->manager_host, HOST_NAME_MAX) < 0) {
                mwarn("Unable to get hostname due to: '%s'", strerror(errno));
            } else {
                wm_strcat(&agent_data->labels, manager_label, agent_data->labels ? '\n' : 0);
                wm_strcat(&agent_data->labels, agent_data->manager_host, 0);
            }

            if (agent_data->agent_ip) {
                wm_strcat(&agent_data->labels, agent_ip_label, agent_data->labels ? '\n' : 0);
                wm_strcat(&agent_data->labels, agent_data->agent_ip, 0);
            }

            if (node_name) {
                wm_strcat(&agent_data->labels, node_label, agent_data->labels ? '\n' : 0);
                wm_strcat(&agent_data->labels, node_name, 0);
                os_strdup(node_name, agent_data->node_name);
            }

            if (agent_data->version) {
                wm_strcat(&agent_data->labels, version_label, agent_data->labels ? '\n' : 0);
                wm_strcat(&agent_data->labels, agent_data->version, 0);
            }

            agent_data->id = atoi(key->id);
            os_strdup(AGENT_CS_ACTIVE, agent_data->connection_status);
            os_strdup(logr.worker_node ? "syncreq" : "synced", agent_data->sync_status);

            w_mutex_lock(&lastmsg_mutex);

            if (data->merged_sum[0] && (!agent_data->merged_sum || (strcmp(data->merged_sum, agent_data->merged_sum) != 0))) {
                /* Mark data as changed and insert into queue */
                if (!data->changed) {
                    char *id;
                    os_strdup(key->id, id);
                    linked_queue_push_ex(pending_queue, id);

                    data->changed = 1;
                }
                os_strdup("not synced", agent_data->group_config_status);
            } else {
                os_strdup("synced", agent_data->group_config_status);
            }

            w_mutex_unlock(&lastmsg_mutex);

            // Updating version and keepalive in global.db
            result = wdb_update_agent_data(agent_data, wdb_sock);

            if (OS_INVALID == result) {
                mdebug1("Unable to update information in global.db for agent: %s", key->id);
            }

            wdb_free_agent_info_data(agent_data);
        }
    }

    os_free(clean);
}

/* Generate merged file for groups */
STATIC void c_group(const char *group, file_sum ***_f_sum, char * sharedcfg_dir, bool create_merged) {
    os_md5 md5sum;
    int merged_ok = 1;
    unsigned int f_size = 0;
    char merged_tmp[PATH_MAX + 1];
    char merged[PATH_MAX + 1];
    char group_path[PATH_MAX + 1];
    remote_files_group *r_group = NULL;

    *merged_tmp = '\0';

    /* Create merged file */
    os_calloc(2, sizeof(file_sum *), (*_f_sum));
    os_calloc(1, sizeof(file_sum), (*_f_sum)[f_size]);

    (*_f_sum)[f_size]->name = NULL;
    (*_f_sum)[f_size]->sum[0] = '\0';

    snprintf(merged, PATH_MAX + 1, "%s/%s/%s", sharedcfg_dir, group, SHAREDCFG_FILENAME);

    if (create_merged && (r_group = w_parser_get_group(group), r_group)) {
        if (r_group->current_polling_time <= 0) {
            r_group->current_polling_time = r_group->poll;

            char *file_url;
            char *file_name;
            char destination_path[PATH_MAX + 1];
            char download_path[PATH_MAX + 1];
            int downloaded;

            // Check if we have merged.mg file in this group
            if (r_group->merge_file_index >= 0) {
                file_url = r_group->files[r_group->merge_file_index].url;
                file_name = SHAREDCFG_FILENAME;
                snprintf(destination_path, PATH_MAX + 1, "%s/%s", DOWNLOAD_DIR, file_name);
                mdebug1("Downloading shared file '%s' from '%s'", merged, file_url);
                downloaded = wurl_request(file_url, destination_path, NULL, NULL, 0);
                w_download_status(downloaded, file_url, destination_path);
                r_group->merged_is_downloaded = !downloaded;

                // Validate the file
                if (r_group->merged_is_downloaded) {
                    // File is invalid
                    if (!TestUnmergeFiles(destination_path, OS_TEXT))
                    {
                        int fd = unlink(destination_path);

                        merror("The downloaded file '%s' is corrupted.", destination_path);

                        if (fd == -1) {
                            merror("Failed to delete file '%s'", destination_path);
                        }
                        return;
                    }

                    OS_MoveFile(destination_path, merged);
                }
            } else { // Download all files
                int i;

                if (r_group->files) {
                    for (i = 0; r_group->files[i].name; i++) {
                        file_url = r_group->files[i].url;
                        file_name = r_group->files[i].name;
                        snprintf(destination_path, PATH_MAX + 1, "%s/%s/%s", sharedcfg_dir, group, file_name);
                        snprintf(download_path, PATH_MAX + 1, "%s/%s", DOWNLOAD_DIR, file_name);
                        mdebug1("Downloading shared file '%s' from '%s'", destination_path, file_url);
                        downloaded = wurl_request(file_url, download_path, NULL, NULL, 0);

                        if (!w_download_status(downloaded, file_url, destination_path)) {
                            OS_MoveFile(download_path, destination_path);
                        }
                    }
                }
            }
        } else {
            r_group->current_polling_time -= poll_interval_time;
        }
    }

    f_size++;

    if (r_group && r_group->merged_is_downloaded) {
        // Validate the file
        if (OS_MD5_File(merged, md5sum, OS_TEXT) != 0) {
            (*_f_sum)[0]->sum[0] = '\0';
            merror("Accessing file '%s'", merged);
        } else {
            snprintf((*_f_sum)[0]->sum, sizeof((*_f_sum)[0]->sum), "%s", md5sum);
            os_strdup(SHAREDCFG_FILENAME, (*_f_sum)[0]->name);
        }

        (*_f_sum)[f_size] = NULL;
    } else {
        if (create_merged) {
            snprintf(merged_tmp, PATH_MAX + 1, "%s/%s/%s.tmp", sharedcfg_dir, group, SHAREDCFG_FILENAME);
            // First call, truncate merged file
            if (merged_ok = MergeAppendFile(merged_tmp, NULL, group, -1), merged_ok == 0) {
                unlink(merged_tmp);
                return;
            }
        }

        // Merge ar.conf always
        if (OS_MD5_File(DEFAULTAR, md5sum, OS_TEXT) == 0) {
            if (create_merged) {
                if (merged_ok = MergeAppendFile(merged_tmp, DEFAULTAR, NULL, -1), merged_ok == 0) {
                    unlink(merged_tmp);
                    return;
                }
            }
            os_realloc((*_f_sum), (f_size + 2) * sizeof(file_sum *), (*_f_sum));
            os_calloc(1, sizeof(file_sum), (*_f_sum)[f_size]);
            snprintf((*_f_sum)[f_size]->sum, sizeof((*_f_sum)[f_size]->sum), "%s", md5sum);
            os_strdup(DEFAULTAR_FILE, (*_f_sum)[f_size]->name);
            (*_f_sum)[f_size + 1] = NULL;
            f_size++;
        }

        snprintf(group_path, PATH_MAX + 1, "%s/%s", sharedcfg_dir, group);

        merged_ok = validate_shared_files(group_path, group, merged_tmp, _f_sum, &f_size, create_merged, -1);

        if (create_merged) {
            if (merged_ok == 0) {
                unlink(merged_tmp);
                return;
            }
            OS_MoveFile(merged_tmp, merged);
        }

        if (OS_MD5_File(merged, md5sum, OS_TEXT) != 0) {
            if (create_merged) {
                merror("Accessing file '%s'", merged);
            }

            (*_f_sum)[0]->sum[0] = '\0';
        }

        snprintf((*_f_sum)[0]->sum, sizeof((*_f_sum)[0]->sum), "%s", md5sum);
        os_strdup(SHAREDCFG_FILENAME, (*_f_sum)[0]->name);
    }
}

/* Generate merged file for multigroups */
STATIC void c_multi_group(char *multi_group, file_sum ***_f_sum, char *hash_multigroup, bool create_merged) {
    DIR *dp;
    char *group;
    char *save_ptr = NULL;
    const char delim[2] = ",";
    char multi_path[PATH_MAX] = {0};

    if (!hash_multigroup) {
        return;
    }

    if (create_merged) {
        /* Get each group of the multi-group */
        group = strtok_r(multi_group, delim, &save_ptr);

        /* Delete agent.conf from multi group before appending to it */
        snprintf(multi_path, PATH_MAX, "%s/%s", MULTIGROUPS_DIR, hash_multigroup);
        cldir_ex(multi_path);

        while (group != NULL) {
            /* Now for each group copy the files to the multi-group folder */
            char dir[PATH_MAX + 1] = {0};

            snprintf(dir, PATH_MAX + 1, "%s/%s", SHAREDCFG_DIR, group);

            dp = opendir(SHAREDCFG_DIR);

            if (!dp) {
                mdebug2("Opening directory: '%s': %s", SHAREDCFG_DIR, strerror(errno));
                return;
            }

            copy_directory(dir, multi_path, group, true);

            group = strtok_r(NULL, delim, &save_ptr);
            closedir(dp);
        }
    }

    /* Open the multi-group files and generate merged */
    dp = opendir(MULTIGROUPS_DIR);

    if (!dp) {
        mdebug2("Opening directory: '%s': %s", MULTIGROUPS_DIR, strerror(errno));
        return;
    }

    c_group(hash_multigroup, _f_sum, MULTIGROUPS_DIR, create_merged);

    closedir(dp);
}

/* Create/update the structure with the files and checksums */
STATIC void c_files()
{
    mdebug2("Updating shared files sums.");

    w_mutex_lock(&files_mutex);

    /* Analize groups */
    process_groups();

    /* Analize multigroups */
    process_multi_groups();

    /* Delete residual groups */
    process_deleted_groups();

    /* Delete residual multigroups */
    process_deleted_multi_groups();

    w_mutex_unlock(&files_mutex);

    if (!reported_path_size_exceeded) {
        reported_path_size_exceeded = 1;
    }

    mdebug2("End updating shared files sums.");
}

STATIC void process_groups() {
    DIR *dp;
    char ** subdir;
    struct dirent *entry = NULL;
    char path[PATH_MAX + 1];

    dp = opendir(SHAREDCFG_DIR);

    if (!dp) {
        mdebug1("Opening directory: '%s': %s", SHAREDCFG_DIR, strerror(errno));
        return;
    }

    while (entry = readdir(dp), entry) {
        // Skip "." and ".."
        if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
            continue;
        }

        snprintf(path, PATH_MAX + 1, SHAREDCFG_DIR "/%s", entry->d_name);

        // Try to open directory, avoid TOCTOU hazard
        if (subdir = wreaddir(path), !subdir) {
            if (errno != ENOTDIR) {
                mdebug1("At process_groups(): Could not open directory '%s'", path);
            }
            continue;
        }

        group_t *group = NULL;
        if (group = find_group(entry->d_name), !group) {
            // New group
            os_realloc(groups, (groups_size + 2) * sizeof(group_t *), groups);
            os_calloc(1, sizeof(group_t), groups[groups_size]);
            groups[groups_size]->name = strdup(entry->d_name);
            c_group(entry->d_name, &groups[groups_size]->f_sum, SHAREDCFG_DIR, !logr.nocmerged);
            groups[groups_size]->has_changed = true;
            groups[groups_size]->exists = true;
            groups[groups_size + 1] = NULL;
            groups_size++;

        } else {
            file_sum **old_sum = group->f_sum;
            group->f_sum = NULL;
            c_group(entry->d_name, &group->f_sum, SHAREDCFG_DIR, false);
            if (fsum_changed(old_sum, group->f_sum)) {
                // Group has changed
                if (!logr.nocmerged) {
                    free_file_sum(group->f_sum);
                    c_group(entry->d_name, &group->f_sum, SHAREDCFG_DIR, true);
                }
                group->has_changed = true;
                mdebug2("Group '%s' has changed.", group->name);
            } else {
                // Group didn't change
                group->has_changed = false;
            }
            free_file_sum(old_sum);
            group->exists = true;
        }

        free_strarray(subdir);
    }

    closedir(dp);
    return;
}

STATIC void process_multi_groups() {
    char ** subdir;
    char path[PATH_MAX + 1];
    OSHashNode *my_node;
    unsigned int i;

    int *agents_array = wdb_get_all_agents(false, NULL);

    if(agents_array) {
        for(int i = 0; agents_array[i] != -1; i++ ) {
            cJSON* j_agent_info = wdb_get_agent_info(agents_array[i], NULL);
            if(j_agent_info) {
                char* agent_groups = cJSON_GetStringValue(cJSON_GetObjectItem(j_agent_info->child, "group"));
                // If we don't duplicate the group_hash, the cJSON_Delete() will remove the string pointer from m_hash
                char* agent_groups_hash = NULL;
                w_strdup(cJSON_GetStringValue(cJSON_GetObjectItem(j_agent_info->child, "group_hash")), agent_groups_hash);

                // If it's not a multigroup, skip it
                if(agent_groups && agent_groups_hash && strstr(agent_groups, ",")) {
                    if (OSHash_Add_ex(m_hash, agent_groups, agent_groups_hash) != 2) {
                        os_free(agent_groups_hash);
                        mdebug2("Couldn't add multigroup '%s' to hash table 'm_hash'", agent_groups);
                    }
                } else {
                    os_free(agent_groups_hash);
                }

                cJSON_Delete(j_agent_info);
            }
        }
        os_free(agents_array);
    }

    for (my_node = OSHash_Begin(m_hash, &i); my_node; my_node = OSHash_Next(m_hash, &i, my_node)) {
        char *key = NULL;
        char *data = NULL;

        os_strdup(my_node->key, key);
        if (my_node->data) {
            os_strdup(my_node->data, data);
        } else {
            os_free(key);
            return;
        }

        snprintf(path, PATH_MAX + 1, MULTIGROUPS_DIR "/%s", data);

        // Try to open directory, avoid TOCTOU hazard
        if (subdir = wreaddir(path), !subdir) {
            switch (errno) {
                case ENOENT:
                    mdebug2("Making multi-group directory: %s", path);

                    int oldmask = umask(0006);
                    int retval = mkdir(path, 0770);
                    umask(oldmask);

                    if (retval < 0) {
                        merror("Cannot create multigroup directory '%s': %s (%d)", path, strerror(errno), errno);
                        os_free(key);
                        os_free(data);
                        continue;
                    }

                    break;

                default:
                    merror("Cannot open multigroup directory '%s': %s (%d)", path, strerror(errno), errno);
                    os_free(key);
                    os_free(data);
                    continue;
            }
        }

        group_t *multigroup = NULL;
        if (multigroup = find_multi_group(key), !multigroup) {
            // New multigroup
            os_realloc(multi_groups, (multi_groups_size + 2) * sizeof(group_t *), multi_groups);
            os_calloc(1, sizeof(group_t), multi_groups[multi_groups_size]);
            multi_groups[multi_groups_size]->name = strdup(key);
            c_multi_group(key, &multi_groups[multi_groups_size]->f_sum, data, !logr.nocmerged);
            multi_groups[multi_groups_size]->exists = true;
            multi_groups[multi_groups_size + 1] = NULL;
            multi_groups_size++;

        } else {
            if (group_changed(key)) {
                // Multigroup needs to be updated
                free_file_sum(multigroup->f_sum);
                c_multi_group(key, &multigroup->f_sum, data, !logr.nocmerged);
                mdebug2("Multigroup '%s' has changed.", multigroup->name);

            } else {
                file_sum **old_sum = multigroup->f_sum;
                multigroup->f_sum = NULL;
                c_multi_group(key, &multigroup->f_sum, data, false);
                if (fsum_changed(old_sum, multigroup->f_sum)) {
                    // Multigroup was modified from outside
                    if (!logr.nocmerged) {
                        free_file_sum(multigroup->f_sum);
                        c_multi_group(key, &multigroup->f_sum, data, true);
                        mwarn("Multigroup '%s' was modified from outside, so it was regenerated.", multigroup->name);
                    } else {
                        mdebug2("Multigroup '%s' was modified from outside.", multigroup->name);
                    }
                }
                free_file_sum(old_sum);
            }
            multigroup->exists = true;
        }

        free_strarray(subdir);
        os_free(key);
        os_free(data);
    }

    return;
}

STATIC void process_deleted_groups() {
    bool update = 0;
    unsigned int i;

    for (i = 0; groups[i]; i++) {
        if (!groups[i]->exists) {
            update = true;
            break;
        }
    }

    if (update) {
        group_t **old_groups = NULL;

        old_groups = groups;
        groups = NULL;

        os_calloc(1, sizeof(group_t *), groups);
        groups_size = 0;

        for (i = 0; old_groups[i]; i++) {
            if (old_groups[i]->exists) {
                os_realloc(groups, (groups_size + 2) * sizeof(group_t *), groups);
                groups[groups_size] = old_groups[i];
                groups[groups_size]->has_changed = false;
                groups[groups_size]->exists = false;
                groups[groups_size + 1] = NULL;
                groups_size++;
            } else {
                free_file_sum(old_groups[i]->f_sum);
                os_free(old_groups[i]->name);
                os_free(old_groups[i]);
            }
        }
        os_free(old_groups);

    } else {
        for (i = 0; groups[i]; i++) {
            groups[i]->has_changed = false;
            groups[i]->exists = false;
        }
    }
}

STATIC void process_deleted_multi_groups() {
    char multi_path[PATH_MAX] = {0};
    os_sha256 multi_group_hash;
    bool update = 0;
    unsigned int i;

    OSHash_Clean(m_hash, cleaner);
    m_hash = OSHash_Create();

    for (i = 0; multi_groups[i]; i++) {
        if (!multi_groups[i]->exists) {
            update = true;
            break;
        }
    }

    if (update) {
        group_t **old_multi_groups = NULL;

        old_multi_groups = multi_groups;
        multi_groups = NULL;

        os_calloc(1, sizeof(group_t *), multi_groups);
        multi_groups_size = 0;

        for (i = 0; old_multi_groups[i]; i++) {
            if (old_multi_groups[i]->exists) {
                os_realloc(multi_groups, (multi_groups_size + 2) * sizeof(group_t *), multi_groups);
                multi_groups[multi_groups_size] = old_multi_groups[i];
                multi_groups[multi_groups_size]->exists = false;
                multi_groups[multi_groups_size + 1] = NULL;
                multi_groups_size++;
            } else {
                OS_SHA256_String(old_multi_groups[i]->name, multi_group_hash);
                snprintf(multi_path, PATH_MAX,"%s/%.8s", MULTIGROUPS_DIR, multi_group_hash);
                rmdir_ex(multi_path);
                free_file_sum(old_multi_groups[i]->f_sum);
                os_free(old_multi_groups[i]->name);
                os_free(old_multi_groups[i]);
            }
        }
        os_free(old_multi_groups);

    } else {
        for (i = 0; multi_groups[i]; i++) {
            multi_groups[i]->exists = false;
        }
    }
}

STATIC int validate_shared_files(const char *src_path, const char *group, const char *merged_tmp, file_sum ***f_sum, unsigned int *f_size, bool create_merged, int path_offset) {
    char ** files;
    char file[MAX_SHARED_PATH + 1];
    int merged_ok = 1;
    unsigned int i;
    os_md5 md5sum;

    // Try to open directory, avoid TOCTOU hazard
    if (files = wreaddir(src_path), !files) {
        if (errno != ENOTDIR) {
            mdebug1("At validate_shared_files(): Could not open directory '%s'", src_path);
        }
        return 1;
    }

    /* Read directory */
    for (i = 0; files[i]; ++i) {
        /* Ignore hidden files  */
        /* Leave the shared config file for later */
        /* Also discard merged.mg.tmp */
        if (files[i][0] == '.' || !strncmp(files[i], SHAREDCFG_FILENAME, strlen(SHAREDCFG_FILENAME))) {
            continue;
        }
        int ignored = 0;
        time_t *modify_time = NULL;
        struct stat attrib;

        if (snprintf(file, MAX_SHARED_PATH + 1, "%s/%s", src_path, files[i]) > MAX_SHARED_PATH) {
            if (!reported_path_size_exceeded) {
                mwarn("At validate_shared_files(): path too long '%s'", file);
            } else {
                mdebug2("At validate_shared_files(): path too long '%s'", file);
            }
            continue;
        }

        if (path_offset < 0) {
            char filename[MAX_SHARED_PATH + 1];
            char * basedir;

            strncpy(filename, file, sizeof(filename));
            filename[sizeof(filename) - 1] = '\0';
            basedir = dirname(filename);
            path_offset = strlen(basedir);

            if (basedir[path_offset - 1] != '/') {
                path_offset++;
            }
        }

        if (stat(file, &attrib) != 0 ) {
            merror("At validate_shared_files(): Unable to get entry attributes '%s'", file);
            continue;
        }

        if (S_ISDIR(attrib.st_mode)) {
            if (merged_ok = validate_shared_files(file, group, merged_tmp, f_sum, f_size, create_merged, path_offset), merged_ok == 0) {
                free_strarray(files);
                return 0;
            }
        } else {
            // Is a file
            if (OS_MD5_File(file, md5sum, OS_TEXT) != 0) {
                merror("Accessing file '%s'", file);
                continue;
            }

            if (modify_time = (time_t*) OSHash_Get(invalid_files, file), modify_time != NULL) {
                time_t last_modify;

                last_modify = attrib.st_mtime;
                ignored = 1;

                if (*modify_time != last_modify) {
                    *modify_time = last_modify;
                    if (checkBinaryFile(file)) {
                        OSHash_Set(invalid_files, file, modify_time);
                        mdebug1("File '%s' in group '%s' modified but still invalid.", file, group);
                    } else {
                        os_free(modify_time);
                        OSHash_Delete(invalid_files, file);
                        minfo("File '%s' in group '%s' is valid after last modification.", file, group);
                        ignored = 0;
                    }
                }
            } else {
                if (checkBinaryFile(file)) {
                    int ret_val;

                    os_calloc(1, sizeof(time_t), modify_time);

                    *modify_time = attrib.st_mtime;
                    ignored = 1;

                    if (ret_val = OSHash_Add(invalid_files, file, modify_time), ret_val != 2) {
                        os_free(modify_time);
                        if (ret_val == 0) {
                            merror("Unable to add file '%s' to hash table of invalid files.", file);
                        }
                    } else {
                        merror("Invalid shared file '%s' in group '%s'. Ignoring it.", file, group);
                    }
                }
            }

            if (!ignored) {
                if (create_merged) {
                    if (merged_ok = MergeAppendFile(merged_tmp, file, NULL, path_offset), merged_ok == 0) {
                        (*f_sum)[*f_size] = NULL;
                        free_strarray(files);
                        return 0;
                    }
                }
                os_realloc(*f_sum, ((*f_size) + 2) * sizeof(file_sum *), *f_sum);
                os_calloc(1, sizeof(file_sum), (*f_sum)[(*f_size)]);
                snprintf((*f_sum)[*f_size]->sum, sizeof((*f_sum)[*f_size]->sum), "%s", md5sum);
                os_strdup(file, (*f_sum)[(*f_size)]->name);
                (*f_size) = (*f_size) + 1;
            }
        }
    }
    (*f_sum)[*f_size] = NULL;
    free_strarray(files);
    return 1;
}

STATIC void copy_directory(const char *src_path, const char *dst_path, char *group, bool initial_iteration) {
    unsigned int i;
    time_t *modify_time = NULL;
    int ignored;
    DIR *dir;
    char ** files;

    if (files = wreaddir(src_path), !files) {
        if (errno != ENOTDIR) {
            if (initial_iteration) {
                mwarn("Could not open directory '%s'. Group folder was deleted.", src_path);
                wdb_remove_group_db(group, NULL);
            } else {
                mdebug2("Could not open directory '%s': %s (%d)", src_path, strerror(errno), errno);
            }
        }
        return;
    }

    for (i = 0; files[i]; ++i) {
        /* Ignore hidden files  */
        /* Leave the shared config file for later */
        /* Also discard merged.mg.tmp */
        if (files[i][0] == '.' || !strncmp(files[i], SHAREDCFG_FILENAME, strlen(SHAREDCFG_FILENAME))) {
            continue;
        }

        char source_path[MAX_SHARED_PATH + 1] = {0};
        char destination_path[MAX_SHARED_PATH + 1] = {0};

        if (snprintf(source_path, MAX_SHARED_PATH + 1, "%s/%s", src_path, files[i]) > MAX_SHARED_PATH ) {
            if (!reported_path_size_exceeded) {
                mwarn("At copy_directory(): source path too long '%s'", source_path);
            } else {
                mdebug2("At copy_directory(): source path too long '%s'", source_path);
            }
            continue;
        }

        if (snprintf(destination_path, MAX_SHARED_PATH + 1, "%s/%s", dst_path, files[i]) > MAX_SHARED_PATH) {
            if (!reported_path_size_exceeded) {
                mwarn("At copy_directory(): destination path too long '%s'", destination_path);
            } else {
                mdebug2("At copy_directory(): destination path too long '%s'", destination_path);
            }
            continue;
        }

        /* Is a file */
        if (dir = opendir(source_path), !dir) {
            ignored = 0;

            char agent_conf_chunck_message[PATH_MAX + 1]= {0};

            if (modify_time = (time_t*) OSHash_Get(invalid_files, source_path), modify_time != NULL) {
                ignored = 1;
            }
            if (!ignored) {
                /* If the file is agent.conf, append */
                if (strcmp(files[i],"agent.conf") == 0) {
                    snprintf(agent_conf_chunck_message, PATH_MAX + 1,"<!-- Source file: %s/agent.conf -->\n", group);
                    w_copy_file(source_path, destination_path,'a', agent_conf_chunck_message, 1);
                } else {
                    w_copy_file(source_path, destination_path,'c', NULL, 1);
                }
            }
        } else {
            /* Is a directory */
            mdebug2("Making new directory: %s", files[i]);

            int oldmask = umask(0006);
            int retval = mkdir(destination_path, 0770);
            umask(oldmask);

            if (retval < 0) {
                if (errno != EEXIST) {
                    merror("Cannot create directory '%s': %s (%d)", destination_path, strerror(errno), errno);
                    closedir(dir);
                    continue;
                }
            }

            copy_directory(source_path, destination_path, group, false);
            closedir(dir);
        }
    }
    free_strarray(files);
    return;
}

STATIC group_t* find_group(const char *group) {
    unsigned int i;

    for (i = 0; groups[i]; i++) {
        if (!strcmp(groups[i]->name, group)) {
            return groups[i];
        }
    }
    return NULL;
}

STATIC group_t* find_multi_group(const char *multigroup) {
    unsigned int i;

    for (i = 0; multi_groups[i]; i++) {
        if (!strcmp(multi_groups[i]->name, multigroup)) {
            return multi_groups[i];
        }
    }
    return NULL;
}

STATIC group_t* find_group_from_file(const char * file, const char * md5, char group[OS_SIZE_65536]) {
    file_sum ** f_sum;
    unsigned int i, j;

    for (i = 0; groups[i]; i++) {
        f_sum = groups[i]->f_sum;

        if (f_sum && f_sum[0] && f_sum[0]->name) {
            for (j = 0; f_sum[j]; j++) {
                if (!(strcmp(f_sum[j]->name, file) || strcmp(f_sum[j]->sum, md5))) {
                    snprintf(group, OS_SIZE_65536, "%s", groups[i]->name);
                    return groups[i];
                }
            }
        }
    }
    return NULL;
}

STATIC group_t* find_multi_group_from_file(const char * file, const char * md5, char multigroup[OS_SIZE_65536]) {
    file_sum ** f_sum;
    unsigned int i, j;

    for (i = 0; multi_groups[i]; i++) {
        f_sum = multi_groups[i]->f_sum;

        if (f_sum && f_sum[0] && f_sum[0]->name) {
            for (j = 0; f_sum[j]; j++) {
                if (!(strcmp(f_sum[j]->name, file) || strcmp(f_sum[j]->sum, md5))) {
                    snprintf(multigroup, OS_SIZE_65536, "%s", multi_groups[i]->name);
                    return multi_groups[i];
                }
            }
        }
    }
    return NULL;
}

STATIC bool fsum_changed(file_sum **old_sum, file_sum **new_sum) {
    unsigned int size_old, size_new = 0;
    unsigned int i, j;

    if (!old_sum || !new_sum) {
        if (!old_sum && !new_sum) {
            return false;
        } else {
            return true;
        }
    }

    if (old_sum[0] && new_sum[0]) {
        if (!old_sum[0]->name || !new_sum[0]->name) {
            if (!old_sum[0]->name && !new_sum[0]->name) {
                return false;
            } else {
                return true;
            }
        }
    }

    for (size_old = 0; old_sum[size_old]; size_old++);
    for (size_new = 0; new_sum[size_new]; size_new++);

    if (size_old == size_new) {
        for (i = 0; old_sum[i]; i++) {
            bool found = false;
            for (j = 0; new_sum[j]; j++) {
                if (!strcmp(old_sum[i]->name, new_sum[j]->name)) {
                    found = true;
                    if (strcmp(old_sum[i]->sum, new_sum[j]->sum)) {
                        return true;
                    }
                    break;
                }
            }
            if (!found) {
                return true;
            }
        }
    } else {
        return true;
    }

    return false;
}

STATIC bool group_changed(const char *multi_group) {
    char **mgroups = NULL;
    unsigned int i;

    mgroups = OS_StrBreak(MULTIGROUP_SEPARATOR, multi_group, MAX_GROUPS_PER_MULTIGROUP);

    for (i = 0; mgroups[i]; i++) {
        group_t *group = NULL;

        if (group = find_group(mgroups[i]), !group || !group->exists || group->has_changed) {
            free_strarray(mgroups);
            return true;
        }
    }

    free_strarray(mgroups);
    return false;
}

/* look for agent group */
STATIC int lookfor_agent_group(const char *agent_id, char *msg, char **r_group, int* wdb_sock)
{
    char* group = NULL;
    char *end;
    char *fmsg;
    char *message;

    group = wdb_get_agent_group(atoi(agent_id), wdb_sock);
    if (group) {
        mdebug2("Agent '%s' group is '%s'", agent_id, group);
        *r_group = group;
        return OS_SUCCESS;
    }

    os_strdup(msg, message);
    fmsg = message;

    // Skip agent-info and label data
    if (message = strchr(message, '\n'), !message) {
        merror("Invalid message from agent ID '%s' (strchr \\n)", agent_id);
        os_free(fmsg);
        return OS_INVALID;
    }

    for (message++; (*message == '\"' || *message == '!' || *message == '#') && (end = strchr(message, '\n')); message = end + 1);

    /* Parse message */
    while (*message != '\0') {
        char *md5;
        char *file;

        md5 = message;
        file = message;

        message = strchr(message, '\n');
        if (!message) {
            merror("Invalid message from agent ID '%s' (strchr \\n)", agent_id);
            break;
        }

        *message = '\0';
        message++;

        // Skip labeled data
        if (*md5 == '\"' || *md5 == '!' || *md5 == '#') {
            continue;
        }

        file = strchr(file, ' ');
        if (!file) {
            merror("Invalid message from agent ID '%s' (strchr ' ')", agent_id);
            break;
        }

        *file = '\0';
        file++;

        /* New agents only have merged.mg */
        if (strcmp(file, SHAREDCFG_FILENAME) == 0) {

            // If group was not got, guess it by matching sum
            os_calloc(OS_SIZE_65536 + 1, sizeof(char), group);
            mdebug2("Agent '%s' with file '%s' MD5 '%s'", agent_id, SHAREDCFG_FILENAME, md5);

            w_mutex_lock(&files_mutex);

            if (!guess_agent_group || (!find_group_from_file(file, md5, group) && !find_multi_group_from_file(file, md5, group))) {
                // If the group could not be guessed, set to "default"
                // or if the user requested not to guess the group, through the internal
                // option 'guess_agent_group', set to "default"
                strncpy(group, "default", OS_SIZE_65536);
            }

            w_mutex_unlock(&files_mutex);

            wdb_set_agent_groups_csv(atoi(agent_id),
                                 group,
                                 WDB_GROUP_MODE_EMPTY_ONLY,
                                 w_is_single_node(NULL) ? "synced" : "syncreq",
                                 NULL);
            *r_group = group;

            mdebug2("Group assigned: '%s'", group);

            os_free(fmsg);
            return OS_SUCCESS;
        }
    }

    os_free(fmsg);
    return OS_INVALID;
}

/* Send a file to the agent
 * Returns -1 on error
 */
static int send_file_toagent(const char *agent_id, const char *group, const char *name, const char *sum, char *sharedcfg_dir)
{
    int i = 0;
    size_t n = 0;
    char file[OS_SIZE_1024 + 1];
    char buf[OS_SIZE_1024 + 1];
    FILE *fp;
    os_sha256 multi_group_hash;
    int protocol = -1; // Agent client net protocol

    /* Check if it is multigroup */
    if (strchr(group, MULTIGROUP_SEPARATOR)) {
        OS_SHA256_String(group, multi_group_hash);
        snprintf(file, OS_SIZE_1024, "%s/%.8s/%s", sharedcfg_dir, multi_group_hash, name);
    } else {
        snprintf(file, OS_SIZE_1024, "%s/%s/%s", sharedcfg_dir, group, name);
    }

    fp = fopen(file, "r");
    if (!fp) {
        mdebug1(FOPEN_ERROR, file, errno, strerror(errno));
        return OS_INVALID;
    }

    /* Send the file name first */
    snprintf(buf, OS_SIZE_1024, "%s%s%s %s\n",
             CONTROL_HEADER, FILE_UPDATE_HEADER, sum, name);

    if (send_msg(agent_id, buf, -1) < 0) {
        fclose(fp);
        return OS_INVALID;
    } else {
        rem_inc_send_shared(agent_id);
    }

    /* The following code is used to get the protocol that the client is using in order to answer accordingly */
    key_lock_read();
    protocol = w_get_agent_net_protocol_from_keystore(&keys, agent_id);
    key_unlock();
    if (protocol < 0) {
        merror(AR_NOAGENT_ERROR, agent_id);
        return OS_INVALID;
    }

    /* Send the file contents */
    while ((n = fread(buf, 1, 900, fp)) > 0) {
        buf[n] = '\0';

        if (send_msg(agent_id, buf, -1) < 0) {
            fclose(fp);
            return OS_INVALID;
        } else {
            rem_inc_send_shared(agent_id);
        }
        /* If the protocol being used is UDP, it is necessary to add a delay to avoid flooding */
        if (protocol == REMOTED_NET_PROTOCOL_UDP) {
            /* Sleep 1 every 30 messages -- no flood */
            if (i > 30) {
                sleep(1);
                i = 0;
            }
            i++;
        }
    }

    /* Send the message to close the file */
    snprintf(buf, OS_SIZE_1024, "%s%s", CONTROL_HEADER, FILE_CLOSE_HEADER);

    if (send_msg(agent_id, buf, -1) < 0) {
        fclose(fp);
        return OS_INVALID;
    } else {
        rem_inc_send_shared(agent_id);
    }

    fclose(fp);

    return OS_SUCCESS;
}

/* Wait for new messages to read */
void *wait_for_msgs(__attribute__((unused)) void *none)
{
    pending_data_t *data;

    /* Should never leave this loop */
    while (1) {
        char *group = NULL;
        os_md5 merged_sum;

        memset(&merged_sum, 0, sizeof(os_md5));

        /* Pop data from queue */
        char *agent_id = linked_queue_pop_ex(pending_queue);

        w_mutex_lock(&lastmsg_mutex);

        if (data = OSHash_Get(pending_data, agent_id), data) {
            w_strdup(data->group, group);
            memcpy(merged_sum, data->merged_sum, sizeof(os_md5));
        } else {
            merror("Couldn't get pending data from hash table for agent ID '%s'.", agent_id);
            os_free(agent_id);
            agent_id = NULL;
        }

        w_mutex_unlock(&lastmsg_mutex);

        if (agent_id && group && merged_sum[0]) {
            mdebug1("Sending file '%s/%s' to agent '%s'.", group, SHAREDCFG_FILENAME, agent_id);

            /* If the agent has multi group, change the shared path */
            char *multi_group = strchr(group,MULTIGROUP_SEPARATOR);
            char sharedcfg_dir[128] = {0};

            if (multi_group) {
                strcpy(sharedcfg_dir, MULTIGROUPS_DIR);
            } else {
                strcpy(sharedcfg_dir, SHAREDCFG_DIR);
            }

            if (send_file_toagent(agent_id, group, SHAREDCFG_FILENAME, merged_sum, sharedcfg_dir) < 0) {
                mwarn(SHARED_ERROR, SHAREDCFG_FILENAME, agent_id);
            }

            mdebug2("End sending file '%s/%s' to agent '%s'.", group, SHAREDCFG_FILENAME, agent_id);
        }
        os_free(agent_id);
        os_free(group);

        // Mark message as dispatched
        w_mutex_lock(&lastmsg_mutex);

        if (data) {
            data->changed = 0;
        }

        w_mutex_unlock(&lastmsg_mutex);
    }

    return NULL;
}
/* Update shared files */
void *update_shared_files(__attribute__((unused)) void *none)
{
    INTERVAL = getDefine_Int("remoted", "shared_reload", 1, 18000);

    poll_interval_time = INTERVAL;

    while (1) {
        time_t _ctime = time(0);

        /* Every INTERVAL seconds, re-read the files
         * If something changed, notify all agents
         */

        if ((_ctime - _stime) >= INTERVAL) {
            // Check if the yaml file has changed and reload it
            if (w_yaml_file_has_changed()) {
                w_yaml_file_update_structs();
                w_yaml_create_groups();
            }

            c_files();
            _stime = _ctime;
        }

        sleep(1);
    }

    return NULL;
}

void free_pending_data(pending_data_t *data) {
    if (!data) return;
    os_free(data->message);
    os_free(data->group);
    os_free(data);
}

/* Should be called before anything here */
void manager_init()
{
    _stime = time(0);
    m_hash = OSHash_Create();
    invalid_files = OSHash_Create();

    mdebug1("Running manager_init");

    os_calloc(1, sizeof(group_t *), groups);
    os_calloc(1, sizeof(group_t *), multi_groups);

    /* Clean multigroups directory */
    if (!logr.nocmerged) {
        cldir_ex(MULTIGROUPS_DIR);
    }

    /* Run initial groups and multigroups scan */
    c_files();

    w_yaml_create_groups();

    pending_queue = linked_queue_init();
    pending_data = OSHash_Create();

    if (!m_hash || !pending_data) merror_exit("At manager_init(): OSHash_Create() failed");

    OSHash_SetFreeDataPointer(pending_data, (void (*)(void *))free_pending_data);
}

void manager_free() {
    linked_queue_free(pending_queue);
}
