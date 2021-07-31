/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_H
#define WDB_H

#include <shared.h>
#include <pthread.h>
#include <openssl/evp.h>
#include "external/sqlite/sqlite3.h"
#include "syscheck_op.h"
#include "rootcheck_op.h"
#include "wazuhdb_op.h"

#define WDB_AGENT_EMPTY 0
#define WDB_AGENT_PENDING 1
#define WDB_AGENT_UPDATED 2

#define WDB_FILE_TYPE_FILE 0
#define WDB_FILE_TYPE_REGISTRY 1

#define WDB_FIM_NOT_FOUND 0
#define WDB_FIM_ADDED 1
#define WDB_FIM_MODIFIED 2
#define WDB_FIM_READDED 3
#define WDB_FIM_DELETED 4

#define WDB_GROUPS 0
#define WDB_SHARED_GROUPS 1
#define WDB_NETADDR_IPV4 0

#define WDB_MULTI_GROUP_DELIM '-'

#define WDB_RESPONSE_BEGIN_SIZE 16

#define WDB_DATABASE_LOGTAG ARGV0 ":wdb_agent"

#define WDB_MAX_COMMAND_SIZE    512
#define WDB_MAX_RESPONSE_SIZE   OS_MAXSTR-WDB_MAX_COMMAND_SIZE

#define AGENT_CS_NEVER_CONNECTED "never_connected"
#define AGENT_CS_PENDING         "pending"
#define AGENT_CS_ACTIVE          "active"
#define AGENT_CS_DISCONNECTED    "disconnected"

typedef enum wdb_stmt {
    WDB_STMT_FIM_LOAD,
    WDB_STMT_FIM_FIND_ENTRY,
    WDB_STMT_FIM_INSERT_ENTRY,
    WDB_STMT_FIM_INSERT_ENTRY2,
    WDB_STMT_FIM_UPDATE_ENTRY,
    WDB_STMT_FIM_DELETE,
    WDB_STMT_FIM_UPDATE_DATE,
    WDB_STMT_FIM_FIND_DATE_ENTRIES,
    WDB_STMT_FIM_GET_ATTRIBUTES,
    WDB_STMT_FIM_UPDATE_ATTRIBUTES,
    WDB_STMT_OSINFO_INSERT,
    WDB_STMT_OSINFO_INSERT2,
    WDB_STMT_OSINFO_DEL,
    WDB_STMT_PROGRAM_INSERT,
    WDB_STMT_PROGRAM_INSERT2,
    WDB_STMT_PROGRAM_DEL,
    WDB_STMT_PROGRAM_UPD,
    WDB_STMT_PROGRAM_GET,
    WDB_STMT_HWINFO_INSERT,
    WDB_STMT_HWINFO_INSERT2,
    WDB_STMT_HOTFIX_INSERT,
    WDB_STMT_HOTFIX_INSERT2,
    WDB_STMT_HWINFO_DEL,
    WDB_STMT_HOTFIX_DEL,
    WDB_STMT_SET_HOTFIX_MET,
    WDB_STMT_PORT_INSERT,
    WDB_STMT_PORT_INSERT2,
    WDB_STMT_PORT_DEL,
    WDB_STMT_PROC_INSERT,
    WDB_STMT_PROC_INSERT2,
    WDB_STMT_PROC_DEL,
    WDB_STMT_NETINFO_INSERT,
    WDB_STMT_NETINFO_INSERT2,
    WDB_STMT_PROTO_INSERT,
    WDB_STMT_PROTO_INSERT2,
    WDB_STMT_ADDR_INSERT,
    WDB_STMT_ADDR_INSERT2,
    WDB_STMT_NETINFO_DEL,
    WDB_STMT_PROTO_DEL,
    WDB_STMT_ADDR_DEL,
    WDB_STMT_CISCAT_INSERT,
    WDB_STMT_CISCAT_DEL,
    WDB_STMT_SCAN_INFO_UPDATEFS,
    WDB_STMT_SCAN_INFO_UPDATEFE,
    WDB_STMT_SCAN_INFO_UPDATESS,
    WDB_STMT_SCAN_INFO_UPDATEES,
    WDB_STMT_SCAN_INFO_UPDATE1C,
    WDB_STMT_SCAN_INFO_UPDATE2C,
    WDB_STMT_SCAN_INFO_UPDATE3C,
    WDB_STMT_SCAN_INFO_GETFS,
    WDB_STMT_SCAN_INFO_GETFE,
    WDB_STMT_SCAN_INFO_GETSS,
    WDB_STMT_SCAN_INFO_GETES,
    WDB_STMT_SCAN_INFO_GET1C,
    WDB_STMT_SCAN_INFO_GET2C,
    WDB_STMT_SCAN_INFO_GET3C,
    WDB_STMT_SCA_FIND,
    WDB_STMT_SCA_UPDATE,
    WDB_STMT_SCA_INSERT,
    WDB_STMT_SCA_SCAN_INFO_INSERT,
    WDB_STMT_SCA_SCAN_INFO_UPDATE,
    WDB_STMT_SCA_INSERT_COMPLIANCE,
    WDB_STMT_SCA_INSERT_RULES,
    WDB_STMT_SCA_FIND_SCAN,
    WDB_STMT_SCA_SCAN_INFO_UPDATE_START,
    WDB_STMT_SCA_POLICY_FIND,
    WDB_STMT_SCA_POLICY_SHA256,
    WDB_STMT_SCA_POLICY_INSERT,
    WDB_STMT_SCA_CHECK_GET_ALL_RESULTS,
    WDB_STMT_SCA_POLICY_GET_ALL,
    WDB_STMT_SCA_POLICY_DELETE,
    WDB_STMT_SCA_CHECK_DELETE,
    WDB_STMT_SCA_SCAN_INFO_DELETE,
    WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE,
    WDB_STMT_SCA_CHECK_RULES_DELETE,
    WDB_STMT_SCA_CHECK_FIND,
    WDB_STMT_SCA_CHECK_DELETE_DISTINCT,
    WDB_STMT_FIM_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_DELETE_AROUND,
    WDB_STMT_FIM_DELETE_RANGE,
    WDB_STMT_FIM_CLEAR,
    WDB_STMT_SYNC_UPDATE_ATTEMPT,
    WDB_STMT_SYNC_UPDATE_COMPLETION,
    WDB_STMT_FIM_FILE_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_FILE_CLEAR,
    WDB_STMT_FIM_FILE_DELETE_AROUND,
    WDB_STMT_FIM_FILE_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_CLEAR,
    WDB_STMT_FIM_REGISTRY_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_DELETE_RANGE,
    WDB_STMT_ROOTCHECK_INSERT_PM,
    WDB_STMT_ROOTCHECK_UPDATE_PM,
    WDB_STMT_ROOTCHECK_DELETE_PM,
    WDB_STMT_GLOBAL_INSERT_AGENT,
    WDB_STMT_GLOBAL_UPDATE_AGENT_NAME,
    WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION,
    WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP,
    WDB_STMT_GLOBAL_LABELS_GET,
    WDB_STMT_GLOBAL_LABELS_DEL,
    WDB_STMT_GLOBAL_LABELS_SET,
    WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE,
    WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_DELETE_AGENT,
    WDB_STMT_GLOBAL_SELECT_AGENT_NAME,
    WDB_STMT_GLOBAL_SELECT_AGENT_GROUP,
    WDB_STMT_GLOBAL_FIND_AGENT,
    WDB_STMT_GLOBAL_FIND_GROUP,
    WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP,
    WDB_STMT_GLOBAL_INSERT_AGENT_GROUP,
    WDB_STMT_GLOBAL_INSERT_AGENT_BELONG,
    WDB_STMT_GLOBAL_DELETE_AGENT_BELONG,
    WDB_STMT_GLOBAL_DELETE_GROUP_BELONG,
    WDB_STMT_GLOBAL_DELETE_GROUP,
    WDB_STMT_GLOBAL_SELECT_GROUPS,
    WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE,
    WDB_STMT_GLOBAL_SYNC_REQ_GET,
    WDB_STMT_GLOBAL_SYNC_SET,
    WDB_STMT_GLOBAL_UPDATE_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_AGENTS,
    WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS,
    WDB_STMT_GLOBAL_GET_AGENT_INFO,
    WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT,
    WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS,
    WDB_STMT_TASK_INSERT_TASK,
    WDB_STMT_TASK_GET_LAST_AGENT_TASK,
    WDB_STMT_TASK_GET_LAST_AGENT_UPGRADE_TASK,
    WDB_STMT_TASK_UPDATE_TASK_STATUS,
    WDB_STMT_TASK_GET_TASK_BY_STATUS,
    WDB_STMT_TASK_DELETE_OLD_TASKS,
    WDB_STMT_TASK_DELETE_TASK,
    WDB_STMT_TASK_CANCEL_PENDING_UPGRADE_TASKS,
    WDB_STMT_PRAGMA_JOURNAL_WAL,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PORTS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_HWINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_OSINFO_CLEAR,
    WDB_STMT_VULN_CVE_INSERT,
    WDB_STMT_VULN_CVE_CLEAR,
    WDB_STMT_SIZE // This must be the last constant
} wdb_stmt;


struct stmt_cache {
    sqlite3_stmt *stmt;
    char *query;
};

struct stmt_cache_list {
    struct stmt_cache value;
    struct stmt_cache_list *next;
};

typedef struct wdb_t {
    sqlite3 * db;
    sqlite3_stmt * stmt[WDB_STMT_SIZE];
    char * id;
    unsigned int refcount;
    unsigned int transaction:1;
    time_t last;
    time_t transaction_begin_time;
    pthread_mutex_t mutex;
    struct stmt_cache_list *cache_list;
    struct wdb_t * next;
} wdb_t;

typedef struct wdb_config {
    int sock_queue_size;
    int worker_pool_size;
    int commit_time_min;
    int commit_time_max;
    int open_db_limit;
} wdb_config;

/// Enumeration of components supported by the integrity library.
typedef enum {
    WDB_FIM,                         ///< File integrity monitoring.
    WDB_FIM_FILE,                    ///< File integrity monitoring.
    WDB_FIM_REGISTRY,                ///< Registry integrity monitoring.
    WDB_SYSCOLLECTOR_PROCESSES,      ///< Processes integrity monitoring.
    WDB_SYSCOLLECTOR_PACKAGES,       ///< Packages integrity monitoring.
    WDB_SYSCOLLECTOR_HOTFIXES,       ///< Hotfixes integrity monitoring.
    WDB_SYSCOLLECTOR_PORTS,          ///< Ports integrity monitoring.
    WDB_SYSCOLLECTOR_NETPROTO,       ///< Net protocols integrity monitoring.
    WDB_SYSCOLLECTOR_NETADDRESS,     ///< Net addresses integrity monitoring.
    WDB_SYSCOLLECTOR_NETINFO,        ///< Net info integrity monitoring.
    WDB_SYSCOLLECTOR_HWINFO,         ///< Hardware info integrity monitoring.
    WDB_SYSCOLLECTOR_OSINFO,         ///< OS info integrity monitoring.
} wdb_component_t;

extern char *schema_global_sql;
extern char *schema_agents_sql;
extern char *schema_task_manager_sql;
extern char *schema_upgrade_v1_sql;
extern char *schema_upgrade_v2_sql;
extern char *schema_upgrade_v3_sql;
extern char *schema_upgrade_v4_sql;
extern char *schema_upgrade_v5_sql;
extern char *schema_upgrade_v6_sql;
extern char *schema_upgrade_v7_sql;
extern char *schema_upgrade_v8_sql;
extern char *schema_global_upgrade_v1_sql;
extern char *schema_global_upgrade_v2_sql;

extern wdb_config wconfig;
extern pthread_mutex_t pool_mutex;
extern wdb_t * db_pool;
extern int db_pool_size;
extern OSHash * open_dbs;

typedef struct os_data {
    char *os_name;
    char *os_version;
    char *os_major;
    char *os_minor;
    char *os_codename;
    char *os_platform;
    char *os_build;
    char *os_uname;
    char *os_arch;
} os_data;

typedef struct agent_info_data {
    int id;
    os_data *osd;
    char *version;
    char *config_sum;
    char *merged_sum;
    char *manager_host;
    char *node_name;
    char *agent_ip;
    char *labels;
    char *connection_status;
    char *sync_status;
} agent_info_data;

typedef enum {
    FIELD_INTEGER,
    FIELD_TEXT,
    FIELD_REAL
} field_type_t;

struct field {
    field_type_t type;
    int index;
    bool is_old_implementation;
    bool is_pk;
    char name[OS_SIZE_256];
};

struct column_list {
    struct field value;
    const struct column_list *next;
};

struct kv {
    char key[OS_SIZE_256];
    char value[OS_SIZE_256];
    bool single_row_table;
    struct column_list const *column_list;
};

struct kv_list {
    struct kv current;
    const struct kv_list *next;
};

/**
 * @brief Opens global database and stores it in DB pool.
 *
 * It is opened every time a query to global database is done.
 *
 * @return wdb_t* Database Structure locked or NULL.
 */
wdb_t * wdb_open_global();

/**
 * @brief Open mitre database and store in DB poll.
 *
 * It is opened every time a query to Mitre database is done.
 *
 * @return wdb_t* Database Structure that store mitre database or NULL on failure.
 */
wdb_t * wdb_open_mitre();

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name);

// Open database for agent and store in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_agent2(int agent_id);

/**
 * @brief Open task database and store in DB poll.
 *
 * It is opened every time a query to Task database is done.
 *
 * @return wdb_t* Database Structure that store task database or NULL on failure.
 */
wdb_t * wdb_open_tasks();

/* Get agent name from location string */
char* wdb_agent_loc2name(const char *location);

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_find_file(sqlite3 *db, const char *path, int type);

/* Find file, Returns ID, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type);

/* Get last event from file: returns WDB_FIM_*, or -1 on error. */
int wdb_get_last_fim(sqlite3 *db, const char *path, int type);

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(sqlite3 *db, int type, long timestamp, const char *f_name, const char *event, const sk_sum_t *sum);

int wdb_syscheck_load(wdb_t * wdb, const char * file, char * output, size_t size);

int wdb_syscheck_save(wdb_t * wdb, int ftype, char * checksum, const char * file);
int wdb_syscheck_save2(wdb_t * wdb, const char * payload);

// Find file entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_fim_find_entry(wdb_t * wdb, const char * path);

int wdb_fim_insert_entry(wdb_t * wdb, const char * file, int ftype, const sk_sum_t * sum);
int wdb_fim_insert_entry2(wdb_t * wdb, const cJSON * data);

int wdb_fim_update_entry(wdb_t * wdb, const char * file, const sk_sum_t * sum);

int wdb_fim_delete(wdb_t * wdb, const char * file);

/* Insert configuration assessment entry. Returns ID on success or -1 on error. */
int wdb_rootcheck_insert(wdb_t * wdb, const rk_event_t *event);

/* Update configuration assessment last date. Returns number of affected rows on success or -1 on error. */
int wdb_rootcheck_update(wdb_t * wdb, const rk_event_t *event);

/* Look for a configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_find(wdb_t * wdb, int pm_id, char * output);

/* Update a configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_update(wdb_t * wdb, char * result, int id,int scan_id, char * status, char * reason);

/* Insert configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_save(wdb_t *wdb, int id, int scan_id, char *title, char *description, char *rationale,
        char *remediation, char *condition, char *file, char *directory, char *process, char *registry,
        char *reference, char *result, char *policy_id, char *command, char *status, char *reason);

/* Insert scan info configuration assessment entry. Returns ID on success or -1 on error (new) */
int wdb_sca_scan_info_save(wdb_t * wdb, int start_scan, int end_scan, int scan_id,char * policy_id,int pass,int fail,int invalid, int total_checks,int score,char * hash);

/* Update scan info configuration assessment entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_scan_info_update(wdb_t * wdb, char * module, int end_scan);

/* Insert global configuration assessment compliance entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_compliance_save(wdb_t * wdb, int id_check, char *key, char *value);

/* Insert the rules of the policy checks,. Returns number of affected rows or -1 on error.  */
int wdb_sca_rules_save(wdb_t * wdb, int id_check, char *type, char *rule);

/* Look for a scan configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_scan_find(wdb_t * wdb, char *policy_id, char * output);

/* Update scan info configuration assessment entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_scan_info_update_start(wdb_t * wdb, char * policy_id, int start_scan,int end_scan,int scan_id,int pass,int fail,int invalid,int total_checks,int score,char * hash);

/* Look for a scan policy entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_policy_find(wdb_t * wdb, char *id, char * output);

/* Gets the result of all checks in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_checks_get_result(wdb_t * wdb, char * policy_id, char * output);

/* Insert policy entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_policy_info_save(wdb_t * wdb,char *name,char * file,char * id,char * description,char *references, char *hash_file);

/* Gets the result of all policies in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_policy_get_id(wdb_t * wdb, char * output);

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_policy_delete(wdb_t * wdb,char * policy_id);

/* Delete a configuration assessment check. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_delete(wdb_t * wdb,char * policy_id);

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_scan_info_delete(wdb_t * wdb,char * policy_id);

/* Delete a configuration assessment check compliances. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_compliances_delete(wdb_t * wdb);

/* Delete a configuration assessment check rules. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_rules_delete(wdb_t * wdb);

/* Delete distinct configuration assessment check. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_delete_distinct(wdb_t * wdb,char * policy_id,int scan_id);

/* Gets the policy SHA256. Returns 1 if found, 0 if not or -1 on error */
int wdb_sca_policy_sha256(wdb_t * wdb, char *id, char * output);

/**
 * @brief Frees agent_info_data struct memory.
 *
 * @param[in] agent_data Pointer to the struct to be freed.
 */
void wdb_free_agent_info_data(agent_info_data *agent_data);

/**
 * @brief Function to parse a chunk response that contains the status of the query and a json array.
 *        This function will create or realloc an int array to place the values of the chunk.
 *        These values are obtained based on the provided json item string.
 *
 * @param [in] input The chunk obtained from WazuhDB to be parsed.
 * @param [out] output An int array containing the parsed values. Must be freed by the caller.
 * @param [in] item Json string to search elements on the chunks.
 * @param [out] last_item Value of the last parsed item. If NULL no value is written.
 * @param [out] last_size Size of the returned array. If NULL no value is written.
 * @return JSON array with the statement execution results. NULL On error.
 */
wdbc_result wdb_parse_chunk_to_int(char* input, int** output, const char* item, int* last_item, int* last_size);

/**
 * @brief Function to initialize a new transaction and cache the statement.
 *
 * @param [in] wdb The global struct database.
 * @param [in] statement_index The index of the statement to be cached.
 * @return Pointer to the statement already cached. NULL On error.
 */
sqlite3_stmt* wdb_init_stmt_in_cache(wdb_t* wdb, wdb_stmt statement_index);

/**
 * @brief Create database for agent from profile.
 *
 * @param[in] id Id of the agent.
 * @param[in] name Name of the agent.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_create_agent_db(int id, const char *name);

/**
 * @brief Create database for agent from profile.
 *
 * @param[in] agent_id Id of the agent.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_create_agent_db2(const char * agent_id);

/**
 * @brief Remove an agent's database.
 *
 * @param[in] id Id of the agent for whom its database must be deleted.
 * @param[in] name Name of the agent for whom its database must be deleted.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_agent_db(int id, const char * name);

/* Remove agents databases from id's list. */
cJSON *wdb_remove_multiple_agents(char *agent_list);

/* Insert or update metadata entries. Returns 0 on success or -1 on error. */
int wdb_fim_fill_metadata(wdb_t * wdb, char *data);

/* Find metadata entries. Returns 0 if doesn't found, 1 on success or -1 on error. */
int wdb_metadata_find_entry(wdb_t * wdb, const char * key);

/* Insert entry. Returns 0 on success or -1 on error. */
int wdb_metadata_insert_entry (wdb_t * wdb, const char *key, const char *value);

/* Update entries. Returns 0 on success or -1 on error. */
int wdb_metadata_update_entry (wdb_t * wdb, const char *key, const char *value);

/* Insert metadata for minor and major version. Returns 0 on success or -1 on error. */
int wdb_metadata_fill_version(sqlite3 *db);

/* Get value data in output variable. Returns 0 if doesn't found, 1 on success or -1 on error. */
int wdb_metadata_get_entry (wdb_t * wdb, const char *key, char *output);

/**
 * @brief Checks if the table exists in the database.
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[in] key Name of the table to find.
 * @return 1 if the table exists, 0 if the table doesn't exist or OS_INVALID on failure.
 */
 int wdb_metadata_table_check(wdb_t * wdb, const char * key);

/* Update field date for specific fim_entry. */
int wdb_fim_update_date_entry(wdb_t * wdb, const char *path);

/* Clear entries prior to the first scan. */
int wdb_fim_clean_old_entries(wdb_t * wdb);

/* Prepare SQL query with availability waiting */
int wdb_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail);

/* Execute statement with availability waiting */
int wdb_step(sqlite3_stmt *stmt);

/* Begin transaction */
int wdb_begin(sqlite3 *db);
int wdb_begin2(wdb_t * wdb);

/* Commit transaction */
int wdb_commit(sqlite3 *db);
int wdb_commit2(wdb_t * wdb);

/* Create global database */
int wdb_create_global(const char *path);

/* Create profile database */
int wdb_create_profile(const char *path);

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source);

/* Delete FIM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_fim(int id);

/* Delete FIM events of all agents. */
void wdb_delete_fim_all();

/* Delete PM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_pm(int id);

/* Delete PM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_rootcheck_delete(wdb_t * wdb);

/* Deletes PM events of all agents */
void wdb_delete_pm_all();

/* Rebuild database. Returns 0 on success or -1 on error. */
int wdb_vacuum(sqlite3 *db);

/* Insert key-value pair into info table */
int wdb_insert_info(const char *key, const char *value);

// Insert network info tuple. Return 0 on success or -1 on error.
int wdb_netinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped, const char * checksum, const char * item_id, const bool replace);

// Save Network info into DB.
int wdb_netinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped, const char * checksum, const char * item_id, const bool replace);

// Delete Network info from DB.
int wdb_netinfo_delete(wdb_t * wdb, const char * scan_id);

// Delete Hotfix info from DB.
int wdb_hotfix_delete(wdb_t * wdb, const char * scan_id);

// Set hotfix metadata.
int wdb_set_hotfix_metadata(wdb_t * wdb, const char * scan_id);

// Insert IPv4/IPv6 protocol info tuple. Return 0 on success or -1 on error.
int wdb_netproto_insert(wdb_t * wdb, const char * scan_id, const char * iface,  int type, const char * gateway, const char * dhcp, int metric, const char * checksum, const char * item_id, const bool replace);

// Save IPv4/IPv6 protocol info into DB.
int wdb_netproto_save(wdb_t * wdb, const char * scan_id, const char * iface,  int type, const char * gateway, const char * dhcp, int metric, const char * checksum, const char * item_id, const bool replace);

// Insert IPv4/IPv6 address info tuple. Return 0 on success or -1 on error.
int wdb_netaddr_insert(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast, const char * checksum, const char * item_id, const bool replace);

// Save IPv4/IPv6 address info into DB.
int wdb_netaddr_save(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast, const char * checksum, const char * item_id, const bool replace);

// Insert OS info tuple. Return 0 on success or -1 on error.
int wdb_osinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_patch, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release, const char * checksum, const bool replace);

// Save OS info into DB.
int wdb_osinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_patch, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version, const char * os_release, const char * checksum, const bool replace);

// Insert HW info tuple. Return 0 on success or -1 on error.
int wdb_hardware_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, double cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage, const char * checksum, const bool replace);

// Save HW info into DB.
int wdb_hardware_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, double cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage, const char * checksum, const bool replace);

// Insert package info tuple. Return 0 on success or -1 on error.
int wdb_package_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location, const char triaged, const char * checksum, const char * item_id, const bool replace);

// Save Packages info into DB.
int wdb_package_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location, const char* checksum, const char * item_id, const bool replace);

// Insert hotfix info tuple. Return 0 on success or -1 on error.
int wdb_hotfix_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix, const char * checksum, const bool replace);

// Save Hotfixes info into DB.
int wdb_hotfix_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix, const char * checksum, const bool replace);

// Update the new Package info with the previous scan.
int wdb_package_update(wdb_t * wdb, const char * scan_id);

// Delete Packages info about previous scan from DB.
int wdb_package_delete(wdb_t * wdb, const char * scan_id);

// Insert process info tuple. Return 0 on success or -1 on error.
int wdb_process_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, int start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor, const char * checksum, const bool replace);

// Save Process info into DB.
int wdb_process_save(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, int start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor, const char* checksum, const bool replace);

// Delete Process info about previous scan from DB.
int wdb_process_delete(wdb_t * wdb, const char * scan_id);

// Insert port info tuple. Return 0 on success or -1 on error.
int wdb_port_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, const char * state, int pid, const char * process, const char * checksum, const char * item_id, const bool replace);

// Save port info into DB.
int wdb_port_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, const char * state, int pid, const char * process, const char * checksum, const char * item_id, const bool replace);

// Delete port info about previous scan from DB.
int wdb_port_delete(wdb_t * wdb, const char * scan_id);

int wdb_syscollector_save2(wdb_t * wdb, wdb_component_t component, const char * payload);

// Save CIS-CAT scan results.
int wdb_ciscat_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, const char * profile, int pass, int fail, int error, int notchecked, int unknown, int score);

// Insert CIS-CAT results tuple. Return 0 on success or -1 on error.
int wdb_ciscat_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, const char * profile, int pass, int fail, int error, int notchecked, int unknown, int score);

// Delete old information from the 'ciscat_results' table
int wdb_ciscat_del(wdb_t * wdb, const char * scan_id);

wdb_t * wdb_init(sqlite3 * db, const char * id);

void wdb_destroy(wdb_t * wdb);

void wdb_pool_append(wdb_t * wdb);

void wdb_pool_remove(wdb_t * wdb);

/**
 * @brief Duplicate the database pool
 *
 * Gets a copy of the database pool. This function fills the member "id" and
 * creates the mutex only.
 *
 * @return Pointer to a database list.
 */
wdb_t * wdb_pool_copy();

void wdb_close_all();

void wdb_commit_old();

void wdb_close_old();

int wdb_remove_database(const char * agent_id);

/**
 * @brief Function to execute one row of an SQL statement and save the result in a JSON array.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [out] status The status code of the statement execution. If NULL no value is written.
 * @return JSON array with the statement execution results. NULL On error.
 */
cJSON* wdb_exec_row_stmt(sqlite3_stmt * stmt, int* status);

/**
 * @brief Function to execute an SQL statement without a response.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @return OS_SUCCESS on success, OS_INVALID on error.
 */
int wdb_exec_stmt_silent(sqlite3_stmt* stmt);

/**
 * @brief Function to execute a SQL statement and save the result in a JSON array limited by size.
 *        Each step of the statemente will be printed to know the size.
 *        The result of each step will be placed in returned result while fits.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @param [out] status The status code of the statement execution.
 *                     SQLITE_DONE means the statement is completed.
 *                     SQLITE_ROW means the statement has pending elements.
 *                     SQLITE_ERROR means an error occurred.
 * @return JSON array with the statement execution results. NULL On error.
 */
cJSON * wdb_exec_stmt_sized(sqlite3_stmt * stmt, const size_t max_size, int* status);

/**
 * @brief Function to execute a SQL statement and save the result in a JSON array.
 *
 * @param [in] stmt The SQL statement to be executed.
 * @return JSON array with the statement execution results. NULL On error.
 */
cJSON * wdb_exec_stmt(sqlite3_stmt * stmt);

/**
 * @brief Function to execute a SQL query and save the result in a JSON array.
 *
 * @param [in] db The SQL database to be queried.
 * @param [in] sql The SQL query.
 * @return JSON array with the query results. NULL On error.
 */
cJSON * wdb_exec(sqlite3 * db, const char * sql);

// Execute SQL script into an database
int wdb_sql_exec(wdb_t *wdb, const char *sql_exec);

int wdb_close(wdb_t * wdb, bool commit);

void wdb_leave(wdb_t * wdb);

wdb_t * wdb_pool_find_prev(wdb_t * wdb);

int wdb_stmt_cache(wdb_t * wdb, int index);

int wdb_parse(char * input, char * output);

int wdb_parse_syscheck(wdb_t * wdb, wdb_component_t component, char * input, char * output);
int wdb_parse_syscollector(wdb_t * wdb, const char * query, char * input, char * output);

/**
 * @brief Parses a rootcheck command
 * Commands:
 * 1. delete: Deletes pm table
 * 2. save: Inserts the entry or updates if it already exists
 * @param wdb Database of an agent
 * @param input buffer input
 * @param output buffer output, on success responses are:
 *        "ok 0" -> If entry was deleted
 *        "ok 1" -> If entry was updated
 *        "ok 2" -> If entry was inserted
 * */
int wdb_parse_rootcheck(wdb_t * wdb, char * input , char * output) __attribute__((nonnull));

int wdb_parse_netinfo(wdb_t * wdb, char * input, char * output);

int wdb_parse_netproto(wdb_t * wdb, char * input, char * output);

int wdb_parse_netaddr(wdb_t * wdb, char * input, char * output);

int wdb_parse_osinfo(wdb_t * wdb, char * input, char * output);

int wdb_parse_hardware(wdb_t * wdb, char * input, char * output);

int wdb_parse_packages(wdb_t * wdb, char * input, char * output);

int wdb_parse_hotfixes(wdb_t * wdb, char * input, char * output);

int wdb_parse_ports(wdb_t * wdb, char * input, char * output);

int wdb_parse_processes(wdb_t * wdb, char * input, char * output);

int wdb_parse_ciscat(wdb_t * wdb, char * input, char * output);

int wdb_parse_sca(wdb_t * wdb, char * input, char * output);


/**
 * @brief Function to parse generic dbsync message operation, and generate
 * a message to process in wazuh-db process.
 *
 * @param wdb The Global struct database.
 * @param input buffer input
 * @param output buffer output, on success responses are:
 *        "ok" -> If entry was processed
 *        "error" -> If entry wasn't processed.
 * @return -1 on error, and 0 on success.
 */
int wdb_parse_dbsync(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent insert request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_insert_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent name request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_name(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent data request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_data(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the labels request for a particular agent.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query in JSON format.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_get_agent_labels(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to get all the agent information in global.db.
 *
 * @param wdb The global struct database.
 * @param input String with 'agent_id'.
 * @param output Response of the query in JSON format.
 * @retval 0 Success: response contains the value.
 * @retval -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_agent_info(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse string with agent's labels and set them in labels table in global database.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id labels_string'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_set_agent_labels(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent keepalive request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_keepalive(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent connection status.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_connection_status(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent delete from agent table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_delete_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent name request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_agent_name(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select agent group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the agent delete from belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_id'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_delete_agent_belong(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the find agent request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String JSON with the agent name and ip.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_find_agent(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the update agent group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agent and group data in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_update_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the find group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_find_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the insert group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_insert_agent_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the insert agent to belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group id and agent id in JSON format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_insert_agent_belong(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the delete group from belongs table request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_delete_group_belong(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the delete group request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the group name.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_delete_group(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the select groups request.
 *
 * @param [in] wdb The global struct database.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_groups(wdb_t * wdb, char * output);

/**
 * @brief Function to parse the select keepalive request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'agent_name agent_ip'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_select_agent_keepalive(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse sync-agent-info-get params and set next ID to iterate on further calls.
 *        If no last_id is provided. Last obtained ID is used.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with starting ID [optional].
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_sync_agent_info_get(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse agent_info and update the agents info from workers.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the agents information in JSON format.
 * @param [out] output Response of the query in JSON format.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_sync_agent_info_set(wdb_t * wdb, char * input, char * output);

/**
 * @brief Function to parse the disconnect-agents command data.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the time threshold before which consider an agent as disconnected and last id to continue.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_global_disconnect_agents(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse last_id get-all-agents.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with last_id.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains the value. -1 On error: invalid DB query syntax.
 */
int wdb_parse_global_get_all_agents(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse the reset agent connection status request.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the 'sync_status'.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_reset_agents_connection(wdb_t * wdb, char* input, char * output);

/**
 * @brief Function to parse the get agents by connection status request.
 *
 * @param wdb The global struct database.
 * @param [in] wdb The global struct database.
 * @param [in] input String with 'last_id' and 'connection_status'.
 * @param [out] output Response of the query in JSON format.
 * @retval 0 Success: Response contains the value.
 * @retval -1 On error: Response contains details of the error.
 */
int wdb_parse_global_get_agents_by_connection_status(wdb_t* wdb, char* input, char* output);

int wdbi_checksum_range(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, os_sha1 hexdigest);

int wdbi_delete(wdb_t * wdb, wdb_component_t component, const char * begin, const char * end, const char * tail);

void wdbi_update_attempt(wdb_t * wdb, wdb_component_t component, long timestamp);

// Functions to manage scan_info table, this table contains the timestamp of every scan of syscheck ¿and syscollector?

int wdb_scan_info_update(wdb_t * wdb, const char *module, const char *field, long value);
int wdb_scan_info_get(wdb_t * wdb, const char *module, char *field, long *output);
int wdb_scan_info_fim_checks_control (wdb_t * wdb, const char *last_check);

// Upgrade agent database to last version
wdb_t * wdb_upgrade(wdb_t *wdb);

/**
 * @brief Function to upgrade Global DB to the latest version.
 *
 * @param [in] wdb The global.db database to upgrade.
 * @return wdb The global.db database updated on success.
 */
wdb_t * wdb_upgrade_global(wdb_t *wdb);

// Create backup and generate an empty DB
wdb_t * wdb_backup(wdb_t *wdb, int version);

/* Create backup for agent. Returns 0 on success or -1 on error. */
int wdb_create_backup(const char * agent_id, int version);

/**
 * @brief Function to backup Global DB in case of an upgrade failure.
 *
 * @param [in] wdb The global.db database to backup.
 * @param [in] version The global.db database version to backup.
 * @return wdb The new empty global.db database on success or NULL on error
 */
wdb_t * wdb_backup_global(wdb_t *wdb, int version);

/**
 * @brief Function to create the Global DB backup file.
 *
 * @param [in] wdb The global.db database to backup.
 * @param [in] version The global.db database version to backup.
 * @return wdb OS_SUCESS on success or OS_INVALID on error.
 */
int wdb_create_backup_global(int version);

/**
 * @brief Check the agent 0 status in the global database
 *
 * The table "agent" must have a tuple with id=0 and last_keepalive=9999/12/31 23:59:59 UTC.
 * Otherwise, the database is either corrupt or old.
 *
 * @return Number of tuples matching that condition.
 * @retval 1 The agent 0 status is OK.
 * @retval 0 No tuple matching conditions exists.
 * @retval -1 The table "agent" is missing or an error occurred.
 */
int wdb_upgrade_check_manager_keepalive(wdb_t *wdb);

/**
 * @brief Query the checksum of a data range
 *
 * Check that the accumulated checksum of every item between begin and
 * end (included) ordered alphabetically matches the checksum provided.
 *
 * On success, also delete every file between end and tail (if provided),
 * none of them included.
 *
 * @param [in] wdb Database node.
 * @param [in] component Name of the component.
 * @param [in] command Integrity check subcommand: "integrity_check_global", "integrity_check_left" or "integrity_check_right".
 * @param [in] payload Operation arguments in JSON format.
 * @pre payload must contain strings "id", "begin", "end" and "checksum", and optionally "tail".
 * @retval 2 Success: checksum matches.
 * @retval 1 Success: checksum does not match.
 * @retval 0 Success: no files were found in this range.
 * @retval -1 On error.
 */
int wdbi_query_checksum(wdb_t * wdb, wdb_component_t component, const char * command, const char * payload);

/**
 * @brief Query a complete table clear
 *
 * @param [in] wdb Database node.
 * @param [in] component Name of the component.
 * @param [in] payload Operation arguments in JSON format.
 * @pre payload must contain string "id".
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdbi_query_clear(wdb_t * wdb, wdb_component_t component, const char * payload);

/**
 * @brief Set the database journal mode to write-ahead logging
 *
 * @param [in] db Pointer to an open database.
 * @retval 0 On success.
 * @retval -1 On error.
 */
int wdb_journal_wal(sqlite3 *db);

/**
 * @brief Function to insert an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] name The agent name
 * @param [in] ip The agent IP address
 * @param [in] register_ip The agent registration IP address
 * @param [in] internal_key The agent key
 * @param [in] group The agent group
 * @param [in] date_add The agent addition date.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key, char* group, int date_add);

/**
 * @brief Function to update an agent name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] name The agent name
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_name(wdb_t *wdb, int id, char* name);

/**
 * @brief Function to update an agent version data.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID.
 * @param [in] os_name The agent's operating system name.
 * @param [in] os_version The agent's operating system version.
 * @param [in] os_major The agent's operating system major version.
 * @param [in] os_minor The agent's operating system minor version.
 * @param [in] os_codename The agent's operating system code name.
 * @param [in] os_platform The agent's operating system platform.
 * @param [in] os_build The agent's operating system build number.
 * @param [in] os_uname The agent's operating system uname.
 * @param [in] os_arch The agent's operating system architecture.
 * @param [in] version The agent's version.
 * @param [in] config_sum The agent's configuration sum.
 * @param [in] merged_sum The agent's merged sum.
 * @param [in] manager_host The agent's manager host name.
 * @param [in] node_name The agent's manager node name.
 * @param [in] agent_ip The agent's IP address.
 * @param [in] connection_status The agent's connection status.
 * @param [in] sync_status The agent's synchronization status in cluster.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_version(wdb_t *wdb,
                                    int id,
                                    const char *os_name,
                                    const char *os_version,
                                    const char *os_major,
                                    const char *os_minor,
                                    const char *os_codename,
                                    const char *os_platform,
                                    const char *os_build,
                                    const char *os_uname,
                                    const char *os_arch,
                                    const char *version,
                                    const char *config_sum,
                                    const char *merged_sum,
                                    const char *manager_host,
                                    const char *node_name,
                                    const char *agent_ip,
                                    const char *connection_status,
                                    const char *sync_status);

/**
 * @brief Function to get the labels of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with labels on success. NULL on error.
 */
cJSON* wdb_global_get_agent_labels(wdb_t *wdb, int id);

/**
 * @brief Function to delete the labels of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return 0 On success. -1 On error.
 */
int wdb_global_del_agent_labels(wdb_t *wdb, int id);

/**
 * @brief Function to insert a label of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] key A string with the label key.
 * @param [in] value A string with the label value.
 * @return 0 On success. -1 On error.
 */
int wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value);

/**
 * @brief Function to update an agent keepalive and the synchronization status.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] connection_status The agent's connection status.
 * @param [in] sync_status The value of sync_status
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_keepalive(wdb_t *wdb, int id, const char *connection_status, const char *sync_status);

/**
 * @brief Function to update an agent connection status and the synchronization status.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID.
 * @param [in] connection_status The connection status to be set.
 * @param [in] sync_status The value of sync_status
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_connection_status(wdb_t *wdb, int id, const char* connection_status, const char *sync_status);

/**
 * @brief Function to delete an agent from the agent table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_agent(wdb_t *wdb, int id);

/**
 * @brief Function to get the name of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with the agent name on success. NULL on error.
 */
cJSON* wdb_global_select_agent_name(wdb_t *wdb, int id);

/**
 * @brief Function to get the group of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id Agent id.
 * @return JSON with the agent group on success. NULL on error.
 */
cJSON* wdb_global_select_agent_group(wdb_t *wdb, int id);

/**
 * @brief Function to delete an agent from the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_agent_belong(wdb_t *wdb, int id);

/**
 * @brief Function to get an agent id using the agent name and register ip.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] name The agent name
 * @param [in] ip The agent ip
 * @return JSON with id on success. NULL on error.
 */
cJSON* wdb_global_find_agent(wdb_t *wdb, const char *name, const char *ip);

/**
 * @brief Function to update an agent group.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] group The group to be set
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_update_agent_group(wdb_t *wdb, int id, char *group);

/**
 * @brief Function to get a group id using the group name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return JSON with group id on success. NULL on error.
 */
cJSON* wdb_global_find_group(wdb_t *wdb, char* group_name);

/**
 * @brief Function to insert a group using the group name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent_group(wdb_t *wdb, char* group_name);

/**
 * @brief Function to insert an agent to the belongs table.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id_group The group id.
 * @param [in] id_agent The agent id.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent);

/**
 * @brief Function to delete a group from belongs table using the group name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_group_belong(wdb_t *wdb, char* group_name);

/**
 * @brief Function to delete a group by using the name.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] group_name The group name.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_global_delete_group(wdb_t *wdb, char* group_name);

/**
 * @brief Function to get a list of groups.
 *
 * @param [in] wdb The Global struct database.
 * @return JSON with all the groups on success. NULL on error.
 */
cJSON* wdb_global_select_groups(wdb_t *wdb);

/**
 * @brief Function to get an agent keepalive using the agent name and register ip.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] name The agent name
 * @param [in] ip The agent ip
 * @return JSON with last_keepalive on success. NULL on error.
 */
cJSON* wdb_global_select_agent_keepalive(wdb_t *wdb, char* name, char* ip);

/**
 * @brief Function to update sync_status of a particular agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] id The agent ID
 * @param [in] sync_status The value of sync_status
 * @return 0 On success. -1 On error.
 */
int wdb_global_set_sync_status(wdb_t *wdb, int id, const char *sync_status);

/**
 * @brief Gets and parses agents with 'syncreq' sync_status and sets them to 'synced'.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [out] output A buffer where the response is written. Must be de-allocated by the caller.
 * @return wdbc_result to represent if all agents has being obtained.
 */
wdbc_result wdb_global_sync_agent_info_get(wdb_t *wdb, int* last_agent_id, char **output);

/**
 * @brief Function to update the information of an agent.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] agent_info A JSON array with the agent information.
 * @return 0 On success. -1 On error.
 */
int wdb_global_sync_agent_info_set(wdb_t *wdb, cJSON *agent_info);

/**
 * @brief Function to get the information of a particular agent stored in Wazuh DB.
 *
 * @param wdb The Global struct database.
 * @param id Agent id.
 * @retval JSON with agent information on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agent_info(wdb_t *wdb, int id);

/**
 * @brief Gets every agent ID.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_all_agents(wdb_t *wdb, int last_agent_id, wdbc_result* status);

/**
 * @brief Function to reset connection_status column of every agent (excluding the manager).
 *        If connection_status is pending or connected it will be changed to disconnected.
 *        If connection_status is disconnected or never_connected it will not be changed.
 *        It also set the 'sync_status' with the specified value.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] sync_status The value of sync_status.
 * @return 0 On success. -1 On error.
 */
int wdb_global_reset_agents_connection(wdb_t *wdb, const char *sync_status);

/**
 * @brief Function to get the id of every agent with a specific connection_status.
 *        Response is prepared in one chunk, if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE
 *        parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [in] connection_status Connection status of the agents requested.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, wdbc_result* status);

/**
 * @brief Gets all the agents' IDs (excluding the manager) that satisfy the keepalive condition to be disconnected.
 *        Response is prepared in one chunk,
 *        if the size of the chunk exceeds WDB_MAX_RESPONSE_SIZE parsing stops and reports the amount of agents obtained.
 *        Multiple calls to this function can be required to fully obtain all agents.
 *
 * @param [in] wdb The Global struct database.
 * @param [in] last_agent_id ID where to start querying.
 * @param [in] sync_status The value of sync_status.
 * @param [out] status wdbc_result to represent if all agents has being obtained or any error occurred.
 * @retval JSON with agents IDs on success.
 * @retval NULL on error.
 */
cJSON* wdb_global_get_agents_to_disconnect(wdb_t *wdb, int last_agent_id, int keep_alive, const char *sync_status, wdbc_result* status);

/**
 * @brief Check the agent 0 status in the global database
 *
 * The table "agent" must have a tuple with id=0 and last_keepalive=1999/12/31 23:59:59 UTC.
 * Otherwise, the database is either corrupt or old.
 *
 * @return Number of tuples matching that condition.
 * @retval 1 The agent 0 status is OK.
 * @retval 0 No tuple matching conditions exists.
 * @retval -1 The table "agent" is missing or an error occurred.
 */
int wdb_global_check_manager_keepalive(wdb_t *wdb);

/**
 * @brief Function to clean table and write new values, this is only
 * for single row tables. Its necessary to have the table PKs well.
 *
 * @param wdb The Global struct database.
 * @param kv_value Table metadata to build dynamic queries.
 * @param data Values separated with pipe character '|'.
 * @retval true when the database single row insertion is executed successfully.
 * @retval false on error.
 */
bool wdb_single_row_insert_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data);

/**
 * @brief Function to insert new rows with a dynamic query based on metadata.
 * Its necessary to have the table PKs well.
 *
 * @param wdb The Global struct database.
 * @param kv_value Table metadata to build dynamic queries.
 * @param data Values separated with pipe character '|'.
 * @retval true when the database insertion is executed successfully.
 * @retval false on error.
 */
bool wdb_insert_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data);

/**
 * @brief Function to modify existing rows with a dynamic query based on metadata.
 * Its necessary to have the table PKs well.
 *
 * @param wdb The Global struct database.
 * @param kv_value Table metadata to build dynamic queries.
 * @param data Values separated with pipe character '|'.
 * @retval true when the database update is executed successfully.
 * @retval false on error.
 */
bool wdb_modify_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data);

/**
 * @brief Function to delete rows with a dynamic query based on metadata.
 * Its necessary to have the table PKs well.
 *
 * @param wdb The Global struct database.
 * @param kv_value Table metadata to build dynamic queries.
 * @param data Values separated with pipe character '|'.
 * @retval true when the database delete is executed successfully.
 * @retval false on error.
 */
bool wdb_delete_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data);

/**
 * @brief Function to parse the insert upgrade request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param command Command to be insert in task
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade(wdb_t* wdb, const cJSON *parameters, const char *command, char* output);

/**
 * @brief Function to parse the upgrade_get_status request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_get_status(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the upgrade_update_status request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_update_status(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the upgrade_result request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_result(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the upgrade_cancel_tasks request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_upgrade_cancel_tasks(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the set_timeout request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_set_timeout(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the delete_old request.
 *
 * @param [in] wdb The global struct database.
 * @param parameters JSON with the parameters
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
int wdb_parse_task_delete_old(wdb_t* wdb, const cJSON *parameters, char* output);

/**
 * @brief Function to parse the vuln_cve requests.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the action and the data if needed.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
 int wdb_parse_vuln_cve(wdb_t* wdb, char* input, char* output);

 /**
 * @brief Function to parse the vuln_cve insert action.
 *
 * @param [in] wdb The global struct database.
 * @param [in] input String with the the data in json format.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
 int wdb_parse_agents_insert_vuln_cve(wdb_t* wdb, char* input, char* output);

/**
 * @brief Function to parse the vuln_cve clear action.
 *
 * @param [in] wdb The global struct database.
 * @param [out] output Response of the query.
 * @return 0 Success: response contains "ok".
 *        -1 On error: response contains "err" and an error description.
 */
 int wdb_parse_agents_clear_vuln_cve(wdb_t* wdb, char* output);


/**
 * Update old tasks with status in progress to status timeout
 * @param wdb The task struct database
 * @param now Actual time
 * @param timeout Task timeout
 * @param next_timeout Next task in progress timeout
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_set_timeout_status(wdb_t* wdb, time_t now, int timeout, time_t *next_timeout);

/**
 * Delete old tasks from the tasks DB
 * @param wdb The task struct database
 * @param timestamp Deletion limit time
 * @return OS_SUCCESS on success, OS_INVALID on errors
 * */
int wdb_task_delete_old_entries(wdb_t* wdb, int timestamp);

/**
 * Insert a new task in the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task will be executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the message comes from.
 * @param command Command to be executed in the agent.
 * @return ID of the task recently created when succeed, <=0 otherwise.
 * */
int wdb_task_insert_task(wdb_t* wdb, int agent_id, const char *node, const char *module, const char *command);

/**
 * Get the status of an upgrade task from the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param status String where the status of the task will be stored.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wdb_task_get_upgrade_task_status(wdb_t* wdb, int agent_id, const char *node, char **status);

/**
 * Update the status of a upgrade task in the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param status New status of the task.
 * @param error Error string of the task in case of failure.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wdb_task_update_upgrade_task_status(wdb_t* wdb, int agent_id, const char *node, const char *status, const char *error);

/**
 * Cancel the upgrade tasks of a given node in the tasks DB.
 * @param wdb The task struct database
 * @param node Node that executed the upgrades.
 * @return 0 when succeed, !=0 otherwise.
 * */
int wdb_task_cancel_upgrade_tasks(wdb_t* wdb, const char *node);

/**
 * Get task by agent_id and module from the tasks DB.
 * @param wdb The task struct database
 * @param agent_id ID of the agent where the task is being executed.
 * @param node Node that executed the command.
 * @param module Name of the module where the command comes from.
 * @param command String where the command of the task will be stored.
 * @param status String where the status of the task will be stored.
 * @param error String where the error message of the task will be stored.
 * @param create_time Integer where the create_time of the task will be stored.
 * @param last_update_time Integer where the last_update_time of the task will be stored.
 * @return task_id when succeed, < 0 otherwise.
 * */
int wdb_task_get_upgrade_task_by_agent_id(wdb_t* wdb, int agent_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time);

// Finalize a statement securely
#define wdb_finalize(x) { if (x) { sqlite3_finalize(x); x = NULL; } }

#endif
