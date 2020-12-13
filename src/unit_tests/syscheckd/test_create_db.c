/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wrappers/common.h"
#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_check_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_realtime_wrappers.h"
#include "../wrappers/wazuh/syscheckd/seechanges_wrappers.h"
#include "../wrappers/wazuh/syscheckd/win-registry_wrappers.h"
#include "../wrappers/wazuh/os_crypto/md5_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"
#include "../syscheckd/fim_db.h"

extern fim_state_db _db_state;

/* auxiliary structs */
typedef struct __fim_data_s {
    fim_element *item;
    whodata_evt *w_evt;
    fim_entry *fentry;
    fim_inode_data *inode_data;
    fim_entry_data *new_data;
    fim_entry_data *old_data;
    fim_entry_data *local_data; // Used on certain tests, not affected by group setup/teardown
    struct dirent *entry;       // Used on fim_directory tests, not affected by group setup/teardown
    cJSON *json;
}fim_data_t;

/* redefinitons/wrapping */

#ifdef TEST_WINAGENT
void __wrap_decode_win_attributes(char *str, unsigned int attrs) {
    check_expected(str);
    check_expected(attrs);
}
#endif

/* setup/teardowns */

static int setup_fim_data(void **state) {
    fim_data_t *fim_data = calloc(1, sizeof(fim_data_t));

    test_mode = 0;

    if(fim_data == NULL)
        return -1;

    if(fim_data->item = calloc(1, sizeof(fim_element)), fim_data->item == NULL)
        return -1;

    if(fim_data->w_evt = calloc(1, sizeof(whodata_evt)), fim_data->w_evt == NULL)
        return -1;

    if(fim_data->new_data = calloc(1, sizeof(fim_entry_data)), fim_data->new_data == NULL)
        return -1;

    if(fim_data->old_data = calloc(1, sizeof(fim_entry_data)), fim_data->old_data == NULL)
        return -1;

    // Setup mock whodata event
    fim_data->w_evt->user_id = strdup("100");
    fim_data->w_evt->user_name = strdup("test");
    fim_data->w_evt->process_name = strdup("test_proc");
    fim_data->w_evt->path = strdup("./test/test.file");
#ifndef TEST_WINAGENT
    fim_data->w_evt->group_id = strdup("1000");
    fim_data->w_evt->group_name = "testing";
    fim_data->w_evt->audit_uid = strdup("99");
    fim_data->w_evt->audit_name = strdup("audit_user");
    fim_data->w_evt->effective_uid = strdup("999");
    fim_data->w_evt->effective_name = strdup("effective_user");
    fim_data->w_evt->inode = strdup("606060");
    fim_data->w_evt->dev = strdup("12345678");
    fim_data->w_evt->parent_name = strdup("parent_name");
    fim_data->w_evt->parent_cwd = strdup("parent_cwd");
    fim_data->w_evt->ppid = 1000;
    fim_data->w_evt->cwd = strdup("process_cwd");
#endif
    fim_data->w_evt->process_id = 1001;

    // Setup mock old fim_entry
    fim_data->old_data->size = 1500;
    fim_data->old_data->perm = strdup("0664");
    fim_data->old_data->attributes = strdup("r--r--r--");
    fim_data->old_data->uid = strdup("100");
    fim_data->old_data->gid = strdup("1000");
    fim_data->old_data->user_name = strdup("test");
    fim_data->old_data->group_name = strdup("testing");
    fim_data->old_data->mtime = 1570184223;
    fim_data->old_data->inode = 606060;
    strcpy(fim_data->old_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->old_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->old_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->old_data->mode = FIM_REALTIME;
    fim_data->old_data->last_event = 1570184220;
    fim_data->old_data->entry_type = FIM_TYPE_FILE;
    fim_data->old_data->dev = 12345678;
    fim_data->old_data->scanned = 123456;
    fim_data->old_data->options = 511;
    strcpy(fim_data->old_data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    // Setup mock new fim_entry
    fim_data->new_data->size = 1501;
    fim_data->new_data->perm = strdup("0666");
    fim_data->new_data->attributes = strdup("rw-rw-rw-");
    fim_data->new_data->uid = strdup("101");
    fim_data->new_data->gid = strdup("1001");
    fim_data->new_data->user_name = strdup("test1");
    fim_data->new_data->group_name = strdup("testing1");
    fim_data->new_data->mtime = 1570184224;
    fim_data->new_data->inode = 606061;
    strcpy(fim_data->new_data->hash_md5, "3691689a513ace7e508297b583d7550d");
    strcpy(fim_data->new_data->hash_sha1, "07f05add1049244e7e75ad0f54f24d8094cd8f8b");
    strcpy(fim_data->new_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e9959643c6262667b61fbe57694df224d40");
    fim_data->new_data->mode = FIM_REALTIME;
    fim_data->new_data->last_event = 1570184221;
    fim_data->new_data->entry_type = FIM_TYPE_FILE;
    fim_data->new_data->dev = 12345678;
    fim_data->new_data->scanned = 123456;
    fim_data->new_data->options = 511;
    strcpy(fim_data->new_data->checksum, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");

    fim_data->json = NULL;

    *state = fim_data;

    return 0;
}

static int teardown_fim_data(void **state) {
    fim_data_t *fim_data = *state;

    free(fim_data->item);
    free_whodata_event(fim_data->w_evt);
    free_entry_data(fim_data->new_data);
    free_entry_data(fim_data->old_data);
    free(fim_data);

    return 0;
}

static int setup_group(void **state) {
    if(setup_fim_data(state) != 0)
        return -1;

    test_mode = 0;
    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    // Read and setup global values.
    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.rt_delay = 1;
    syscheck.max_depth = 256;
    syscheck.file_max_size = 1024;

    test_mode = 1;

    return 0;
}

static int setup_root_group(void **state) {
    if(setup_fim_data(state) != 0)
        return -1;

    test_mode = 0;
    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    // Read and setup global values.
    Read_Syscheck_Config("test_syscheck_top_level.conf");

    syscheck.rt_delay = 1;
    syscheck.max_depth = 256;
    syscheck.file_max_size = 1024;

    test_mode = 1;

    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;

    if(teardown_fim_data(state) != 0)
        return -1;

    Free_Syscheck(&syscheck);

    syscheck.audit_key = NULL;

#ifdef TEST_WINAGENT
    syscheck.registry_ignore = NULL;
    syscheck.registry_ignore_regex = NULL;
#endif

    return 0;
}

static int teardown_delete_json(void **state) {
    fim_data_t *fim_data = *state;
    cJSON_Delete(fim_data->json);
    return 0;
}

static int setup_fim_entry(void **state) {
    fim_data_t *fim_data = *state;

    if(fim_data->fentry = calloc(1, sizeof(fim_entry)), fim_data->fentry == NULL)
        return -1;

    if(fim_data->local_data = calloc(1, sizeof(fim_entry_data)), fim_data->local_data == NULL)
        return -1;

    fim_data->fentry->data = fim_data->local_data;
    fim_data->fentry->path = NULL;

    return 0;
}

static int teardown_fim_entry(void **state) {
    fim_data_t *fim_data = *state;

    free_entry(fim_data->fentry);

    return 0;
}

static int teardown_local_data(void **state) {
    fim_data_t *fim_data = *state;

    free_entry_data(fim_data->local_data);
    return 0;
}

static int setup_struct_dirent(void **state) {
    fim_data_t *fim_data = *state;

    if(fim_data->entry = calloc(1, sizeof(struct dirent)), fim_data->entry == NULL)
        return -1;

    return 0;
}

static int teardown_struct_dirent(void **state) {
    fim_data_t *fim_data = *state;

    free(fim_data->entry);

    return 0;
}

static int setup_file_limit(void **state) {
    syscheck.file_limit_enabled = false;
    syscheck.file_limit = 0;

    return 0;
}

static int teardown_file_limit(void **state) {
    syscheck.file_limit_enabled = true;
    syscheck.file_limit = 50000;

    return 0;
}

static int setup_fim_double_scan(void **state) {
    activate_full_db = true;
    struct dirent *dirent_st = calloc(1, sizeof(struct dirent));
    syscheck.database = calloc (1, sizeof(fdb_t));

    if (!dirent_st || !syscheck.database ) {
        return -1;
    }

    strcpy(dirent_st->d_name, "test_file");

#ifndef TEST_WINAGENT
    dirent_st->d_type = DT_REG;
    dirent_st->d_ino = 1;
#else
    dirent_st->d_ino = 0;
    dirent_st->d_reclen = 0;
    dirent_st->d_namlen = 9;
#endif
    *state = dirent_st;

    return 0;
}

static int teardown_fim_double_scan(void **state) {
    struct dirent *sd = state[0];
    free(sd);
    free(syscheck.database);
    syscheck.database = NULL;
    sd = NULL;
    activate_full_db = false;

#ifdef TEST_WINAGENT
    char *file = state[1];
    free(file);
#endif

    return 0;
}

static int setup_fim_not_double_scan(void **state) {
    syscheck.database = calloc (1, sizeof(fdb_t));

    if(!syscheck.database ) {
        return -1;
    }
    syscheck.database->full = true;
    return 0;
}

static int teardown_fim_not_double_scan(void **state) {
    free(syscheck.database);
    syscheck.database = NULL;
    return 0;
}

#ifndef TEST_WINAGENT
static int setup_fim_scan_realtime(void **state) {

    syscheck.database = calloc (1, sizeof(fdb_t));

    if (!syscheck.database) {
        return -1;
    }

    syscheck.database->full = true;
    return 0;
}

static int teardown_fim_scan_realtime(void **state) {
    int *dir_opts = *state;
    int it = 0;

    while (syscheck.dir[it] != NULL) {
        syscheck.opts[it] = dir_opts[it];
        it++;
    }

    free(dir_opts);
    os_free(syscheck.database);

    syscheck.realtime = NULL; // Used with local variables in some tests

    return 0;
}
#endif

/* Auxiliar functions */
/**
 * @brief This function will prepare the successfull execution of the double scan in Windows tests
 * @param test_file_path File path that will be used in the function fim_db_insert.
 * @param dir_file_path Directory of the file.
 * @param file Dirent structure for the file.
 */
void prepare_win_double_scan_success (char *test_file_path, char *dir_file_path, struct dirent *file) {

    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_string(__wrap_stat, __file, dir_file_path);
    will_return(__wrap_stat, S_IFDIR);
    will_return(__wrap_stat, 0);
    expect_string(__wrap_HasFilesystem, path, dir_file_path);
    will_return(__wrap_HasFilesystem, 0);
    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, file);

    expect_string(__wrap_stat, __file, test_file_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, 0);
    expect_string(__wrap_HasFilesystem, path, test_file_path);
    will_return(__wrap_HasFilesystem, 0);

    // fim_file
    {
        // fim_get_data

        expect_string(__wrap_w_get_file_permissions, file_path, test_file_path);
        will_return(__wrap_w_get_file_permissions, "permissions");
        will_return(__wrap_w_get_file_permissions, 0);

        expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
        will_return(__wrap_decode_win_permissions, "decoded_perms");

        expect_string(__wrap_w_get_file_attrs, file_path, test_file_path);
        will_return(__wrap_w_get_file_attrs, 123456);

        expect_string(__wrap_get_UTC_modification_time, file_path, test_file_path);
        will_return(__wrap_get_UTC_modification_time, 123456);

        expect_string(__wrap_get_user, path, test_file_path);
        will_return(__wrap_get_user, "0");
        will_return(__wrap_get_user, strdup("user"));

        expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
        expect_string(__wrap_fim_db_get_path, file_path, test_file_path);
        will_return(__wrap_fim_db_get_path, 0);

        expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
        expect_string(__wrap_fim_db_insert, file_path, test_file_path);
        will_return(__wrap_fim_db_insert, FIMDB_FULL);
        // fim_json_event;
    }

    will_return(__wrap_readdir, NULL);

    expect_value(__wrap_fim_db_set_all_unscanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_set_all_unscanned, FIMDB_OK);
}

/* tests */
static void test_fim_json_event(void **state) {
    fim_data_t *fim_data = *state;

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606061);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);
#endif

    fim_data->json = fim_json_event(
                    "test.file",
                    fim_data->old_data,
                    fim_data->new_data,
                    1,
                    FIM_MODIFICATION,
                    FIM_REALTIME,
                    NULL,
                    NULL
                );

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "realtime");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
#ifdef TEST_WINAGENT
    assert_null(tags);
#else
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_null(hard_links);
#endif
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 10);
#else
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 11);
#endif
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);

}


static void test_fim_json_event_whodata(void **state) {
    fim_data_t *fim_data = *state;

    syscheck.opts[1] |= CHECK_SEECHANGES;

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606061);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);
#endif

    fim_data->json = fim_json_event(
        "test.file",
        fim_data->old_data,
        fim_data->new_data,
        1,
        FIM_MODIFICATION,
        FIM_WHODATA,
        fim_data->w_evt,
        "diff"
    );

    syscheck.opts[1] &= ~CHECK_SEECHANGES;

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "whodata");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
#ifdef TEST_WINAGENT
    assert_null(tags);
#else
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_null(hard_links);
#endif
    cJSON *audit = cJSON_GetObjectItem(data, "audit");
    assert_non_null(audit);
#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(audit), 4);
#else
    assert_int_equal(cJSON_GetArraySize(audit), 14);
#endif
    cJSON *diff = cJSON_GetObjectItem(data, "content_changes");
    assert_string_equal(cJSON_GetStringValue(diff), "diff");
}


static void test_fim_json_event_no_changes(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_json_event(
                        "test.file",
                        fim_data->new_data,
                        fim_data->new_data,
                        1,
                        FIM_MODIFICATION,
                        FIM_WHODATA,
                        NULL,
                        NULL
                    );

    assert_null(fim_data->json);
}


static void test_fim_json_event_hardlink_one_path(void **state) {
    fim_data_t *fim_data = *state;

    char **paths = calloc(2, sizeof(char *));
    paths[0] = strdup("test.file");
    paths[1] = NULL;

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606061);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, paths);
#endif

    fim_data->json = fim_json_event(
                    "test.file",
                    fim_data->old_data,
                    fim_data->new_data,
                    2,
                    FIM_MODIFICATION,
                    FIM_REALTIME,
                    NULL,
                    NULL
                );

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "realtime");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
#ifdef TEST_WINAGENT
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
#else
    assert_null(tags);
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_null(hard_links);
#endif
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

#ifndef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 11);
#else
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 10);
#endif
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);
}


static void test_fim_json_event_hardlink_two_paths(void **state) {
    fim_data_t *fim_data = *state;

    char **paths = calloc(3, sizeof(char *));
    paths[0] = strdup("test.file");
    paths[1] = strdup("hard_link.file");
    paths[2] = NULL;

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606061);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, paths);
#endif

    fim_data->json = fim_json_event(
                    "test.file",
                    fim_data->old_data,
                    fim_data->new_data,
                    2,
                    FIM_MODIFICATION,
                    FIM_REALTIME,
                    NULL,
                    NULL
                );

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "event");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *path = cJSON_GetObjectItem(data, "path");
    assert_string_equal(cJSON_GetStringValue(path), "test.file");
    cJSON *mode = cJSON_GetObjectItem(data, "mode");
    assert_string_equal(cJSON_GetStringValue(mode), "realtime");
    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    assert_string_equal(cJSON_GetStringValue(data_type), "modified");
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184221);
    cJSON *tags = cJSON_GetObjectItem(data, "tags");
#ifdef TEST_WINAGENT
    assert_string_equal(cJSON_GetStringValue(tags), "tag1,tag2");
#else
    assert_null(tags);
    cJSON *hard_links = cJSON_GetObjectItem(data, "hard_links");
    assert_non_null(hard_links);
#endif
    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    cJSON *changed_attributes = cJSON_GetObjectItem(data, "changed_attributes");
    assert_non_null(changed_attributes);
    cJSON *old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);

#ifndef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(hard_links), 1);
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 11);
#else
    assert_int_equal(cJSON_GetArraySize(changed_attributes), 10);
#endif
    assert_int_equal(cJSON_GetArraySize(attributes), 13);
    assert_int_equal(cJSON_GetArraySize(old_attributes), 13);
}


static void test_fim_attributes_json(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_attributes_json(fim_data->old_data);

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 13);

    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "file");
    cJSON *size = cJSON_GetObjectItem(fim_data->json, "size");
    assert_non_null(size);
    assert_int_equal(size->valueint, 1500);
    cJSON *perm = cJSON_GetObjectItem(fim_data->json, "perm");
    assert_string_equal(cJSON_GetStringValue(perm), "0664");
    cJSON *uid = cJSON_GetObjectItem(fim_data->json, "uid");
    assert_string_equal(cJSON_GetStringValue(uid), "100");
    cJSON *gid = cJSON_GetObjectItem(fim_data->json, "gid");
    assert_string_equal(cJSON_GetStringValue(gid), "1000");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *group_name = cJSON_GetObjectItem(fim_data->json, "group_name");
    assert_string_equal(cJSON_GetStringValue(group_name), "testing");
    cJSON *inode = cJSON_GetObjectItem(fim_data->json, "inode");
    assert_non_null(inode);
    assert_int_equal(inode->valueint, 606060);
    cJSON *mtime = cJSON_GetObjectItem(fim_data->json, "mtime");
    assert_non_null(mtime);
    assert_int_equal(mtime->valueint, 1570184223);
    cJSON *hash_md5 = cJSON_GetObjectItem(fim_data->json, "hash_md5");
    assert_string_equal(cJSON_GetStringValue(hash_md5), "3691689a513ace7e508297b583d7050d");
    cJSON *hash_sha1 = cJSON_GetObjectItem(fim_data->json, "hash_sha1");
    assert_string_equal(cJSON_GetStringValue(hash_sha1), "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    cJSON *hash_sha256 = cJSON_GetObjectItem(fim_data->json, "hash_sha256");
    assert_string_equal(cJSON_GetStringValue(hash_sha256), "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    cJSON *checksum = cJSON_GetObjectItem(fim_data->json, "checksum");
    assert_string_equal(cJSON_GetStringValue(checksum), "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}

static void test_fim_attributes_json_without_options(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->old_data->options = 0;

    fim_data->json = fim_attributes_json(fim_data->old_data);

    fim_data->old_data->options = 511;

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 4);

    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(cJSON_GetStringValue(type), "file");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *group_name = cJSON_GetObjectItem(fim_data->json, "group_name");
    assert_string_equal(cJSON_GetStringValue(group_name), "testing");
    cJSON *checksum = cJSON_GetObjectItem(fim_data->json, "checksum");
    assert_string_equal(cJSON_GetStringValue(checksum), "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
}


static void test_fim_entry_json(void **state) {
    fim_data_t *fim_data = *state;
    const char *f_path = "/dir/test";

    fim_data->json = fim_entry_json(f_path, fim_data->old_data);

    assert_non_null(fim_data->json);
    cJSON *path = cJSON_GetObjectItem(fim_data->json, "path");
    assert_non_null(path);
    assert_string_equal(path->valuestring, f_path);
    cJSON *timestamp = cJSON_GetObjectItem(fim_data->json, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}

static void test_fim_entry_json_null_path(void **state) {
    fim_data_t *fim_data = *state;

    expect_assert_failure(fim_entry_json(NULL, fim_data->old_data));
}
static void test_fim_entry_json_null_data(void **state) {
    expect_assert_failure(fim_entry_json("/a/path", NULL));
}

static void test_fim_json_compare_attrs(void **state) {
    fim_data_t *fim_data = *state;
    int i = 0;

    fim_data->json = fim_json_compare_attrs(
        fim_data->old_data,
        fim_data->new_data
    );

    assert_non_null(fim_data->json);
#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 10);
#else
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 11);
#endif

    cJSON *size = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(size), "size");
    cJSON *permission = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(permission), "permission");
    cJSON *uid = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(uid), "uid");
    cJSON *user_name = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(user_name), "user_name");
    cJSON *gid = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(gid), "gid");
    cJSON *group_name = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(group_name), "group_name");
    cJSON *mtime = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(mtime), "mtime");
#ifndef TEST_WINAGENT
    cJSON *inode = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(inode), "inode");
#endif
    cJSON *md5 = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(md5), "md5");
    cJSON *sha1 = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(sha1), "sha1");
    cJSON *sha256 = cJSON_GetArrayItem(fim_data->json, i++);
    assert_string_equal(cJSON_GetStringValue(sha256), "sha256");

}

static void test_fim_json_compare_attrs_without_options(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->old_data->options = 0;

    fim_data->json = fim_json_compare_attrs(
        fim_data->old_data,
        fim_data->new_data
    );

    fim_data->old_data->options = 511;

    assert_non_null(fim_data->json);
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 0);

}


static void test_fim_audit_json(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_audit_json(fim_data->w_evt);

    assert_non_null(fim_data->json);
#ifdef TEST_WINAGENT
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 4);
#else
    assert_int_equal(cJSON_GetArraySize(fim_data->json), 14);
#endif

    cJSON *user_id = cJSON_GetObjectItem(fim_data->json, "user_id");
    assert_string_equal(cJSON_GetStringValue(user_id), "100");
    cJSON *user_name = cJSON_GetObjectItem(fim_data->json, "user_name");
    assert_string_equal(cJSON_GetStringValue(user_name), "test");
    cJSON *process_name = cJSON_GetObjectItem(fim_data->json, "process_name");
    assert_string_equal(cJSON_GetStringValue(process_name), "test_proc");
    cJSON *process_id = cJSON_GetObjectItem(fim_data->json, "process_id");
    assert_non_null(process_id);
    assert_int_equal(process_id->valueint, 1001);

#ifndef TEST_WINAGENT
    cJSON *cwd = cJSON_GetObjectItem(fim_data->json, "cwd");
    assert_string_equal(cJSON_GetStringValue(cwd), "process_cwd");
    cJSON *group_id = cJSON_GetObjectItem(fim_data->json, "group_id");
    assert_string_equal(cJSON_GetStringValue(group_id), "1000");
    cJSON *group_name = cJSON_GetObjectItem(fim_data->json, "group_name");
    assert_string_equal(cJSON_GetStringValue(group_name), "testing");
    cJSON *audit_uid = cJSON_GetObjectItem(fim_data->json, "audit_uid");
    assert_string_equal(cJSON_GetStringValue(audit_uid), "99");
    cJSON *audit_name = cJSON_GetObjectItem(fim_data->json, "audit_name");
    assert_string_equal(cJSON_GetStringValue(audit_name), "audit_user");
    cJSON *effective_uid = cJSON_GetObjectItem(fim_data->json, "effective_uid");
    assert_string_equal(cJSON_GetStringValue(effective_uid), "999");
    cJSON *effective_name = cJSON_GetObjectItem(fim_data->json, "effective_name");
    assert_string_equal(cJSON_GetStringValue(effective_name), "effective_user");
    cJSON *ppid = cJSON_GetObjectItem(fim_data->json, "ppid");
    assert_non_null(ppid);
    assert_int_equal(ppid->valueint, 1000);
    cJSON *parent_cwd = cJSON_GetObjectItem(fim_data->json, "parent_cwd");
    assert_string_equal(cJSON_GetStringValue(parent_cwd), "parent_cwd");
    cJSON *parent_name = cJSON_GetObjectItem(fim_data->json, "parent_name");
    assert_string_equal(cJSON_GetStringValue(parent_name), "parent_name");
#endif
}

#ifndef TEST_WINAGENT
static void test_fim_check_ignore_strncasecmp(void **state) {
   int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6204): Ignoring 'file' '/EtC/dumPDateS' due to '/etc/dumpdates'");

    ret = fim_check_ignore("/EtC/dumPDateS");

    assert_int_equal(ret, 1);
}
#else
static void test_fim_check_ignore_strncasecmp(void **state) {
    int ret;
    char *path = "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\DeskTop.ini";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    snprintf(debug_msg, OS_MAXSTR, "(6204): Ignoring 'file' '%s' due to '%s'", expanded_path, syscheck.ignore[0]);

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);


    ret = fim_check_ignore(expanded_path);

    assert_int_equal(ret, 1);
}
#endif

static void test_fim_check_ignore_regex(void **state) {
   int ret;

#ifndef TEST_WINAGENT
    expect_string(__wrap__mdebug2, formatted_msg, "(6205): Ignoring 'file' '/test/files/test.swp' due to sregex '.log$|.swp$'");
#else
    expect_string(__wrap__mdebug2, formatted_msg, "(6205): Ignoring 'file' '/test/files/test.swp' due to sregex '.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$|.swp$'");
#endif

    ret = fim_check_ignore("/test/files/test.swp");

    assert_int_equal(ret, 1);
}


static void test_fim_check_ignore_failure(void **state) {
   int ret;

    ret = fim_check_ignore("/test/files/test.sp");

    assert_int_equal(ret, 0);
}


static void test_fim_check_restrict_success(void **state) {
   int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    ret = fim_check_restrict("my_test", restriction);
    OSMatch_FreePattern(restriction);
    free(restriction);

    assert_int_equal(ret, 0);
}


static void test_fim_check_restrict_failure(void **state) {
   int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6203): Ignoring file 'my_test_' due to restriction 'test$'");

    ret = fim_check_restrict("my_test_", restriction);
    OSMatch_FreePattern(restriction);
    free(restriction);

    assert_int_equal(ret, 1);
}

static void test_fim_check_restrict_null_filename(void **state) {
   int ret;

    OSMatch *restriction;
    restriction = calloc(1, sizeof(OSMatch));
    OSMatch_Compile("test$", restriction, 0);

    expect_string(__wrap__merror, formatted_msg, "(1105): Attempted to use null string.");

    ret = fim_check_restrict(NULL, restriction);
    OSMatch_FreePattern(restriction);
    free(restriction);

    assert_int_equal(ret, 1);
}

static void test_fim_check_restrict_null_restriction(void **state) {
   int ret;

    ret = fim_check_restrict("my_test", NULL);

    assert_int_equal(ret, 0);
}


static void test_fim_scan_info_json_start(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_scan_info_json(FIM_SCAN_START, 1570184220);

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(type->valuestring, "scan_start");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}


static void test_fim_scan_info_json_end(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->json = fim_scan_info_json(FIM_SCAN_END, 1570184220);

    assert_non_null(fim_data->json);
    cJSON *type = cJSON_GetObjectItem(fim_data->json, "type");
    assert_string_equal(type->valuestring, "scan_end");
    cJSON *data = cJSON_GetObjectItem(fim_data->json, "data");
    assert_non_null(data);
    cJSON *timestamp = cJSON_GetObjectItem(data, "timestamp");
    assert_non_null(timestamp);
    assert_int_equal(timestamp->valueint, 1570184220);
}


static void test_fim_get_checksum(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    fim_get_checksum(fim_data->local_data);
    assert_string_equal(fim_data->local_data->checksum, "2bbaf80d6c1af7d5b2c89c27e8a21eda17de6019");
}


static void test_fim_get_checksum_wrong_size(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->local_data->size = -1;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    fim_get_checksum(fim_data->local_data);
    assert_string_equal(fim_data->local_data->checksum, "551cab7f774d4633a3be09207b4cdea1db03b9c0");
}

static void test_fim_check_depth_success(void **state) {
    int ret;

#ifndef TEST_WINAGENT
    // Pos 4 = "/usr/bin"
    char * path = "/usr/bin/folder1/folder2/folder3/file";
#else
    // Pos 4 = "%WINDIR%\\SysNative\\wbem"
    char *aux_path = "%WINDIR%\\SysNative\\wbem\\folder1\\folder2\\folder3\\path.exe";
    char path[OS_MAXSTR];

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();
#endif
    ret = fim_check_depth(path, 4);

    assert_int_equal(ret, 3);
}


static void test_fim_check_depth_failure_strlen(void **state) {
   int ret;

    char * path = "fl/fd";
    // Pos 4 = "/usr/bin"
    ret = fim_check_depth(path, 4);

    assert_int_equal(ret, -1);

}

static void test_fim_check_depth_failure_null_directory(void **state) {
   int ret;

    char * path = "/usr/bin";
    // Pos 4 = "/usr/bin"
    ret = fim_check_depth(path, 6);

    assert_int_equal(ret, -1);

}

static void test_fim_configuration_directory_no_path(void **state) {
    int ret;

    const char * entry = "file";

    ret = fim_configuration_directory(NULL, entry);

    assert_int_equal(ret, -1);
}


#ifndef TEST_WINAGENT
static void test_fim_configuration_directory_file(void **state) {
    int ret;

    const char * path = "/media";
    const char * entry = "file";

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, 3);
}
#else
static void test_fim_configuration_directory_file(void **state) {
    char *aux_path = "%WINDIR%\\SysNative\\drivers\\etc";
    char path[OS_MAXSTR];
    const char * entry = "file";
    int ret;

    if(!ExpandEnvironmentStrings(aux_path, path, OS_MAXSTR))
        fail();

    str_lowercase(path);

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, 3);
}
#endif


static void test_fim_configuration_directory_not_found(void **state) {
    int ret;

    const char *path = "/invalid";
    const char *entry = "file";

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/invalid'");

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, -1);
}

#ifdef TEST_WINAGENT
static void test_fim_configuration_directory_registry_not_found(void **state) {
    int ret;

    const char *path = "invalid";
    const char *entry = "registry";

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (registry):'invalid'");

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, -1);
}

static void test_fim_configuration_directory_registry_found(void **state) {
    char *path = "[x32] HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    const char * entry = "registry";
    int ret;

    ret = fim_configuration_directory(path, entry);

    assert_int_equal(ret, 20);
}
#endif

static void test_init_fim_data_entry(void **state) {
    fim_data_t *fim_data = *state;

    init_fim_data_entry(fim_data->local_data);

    assert_int_equal(fim_data->local_data->size, 0);
    assert_null(fim_data->local_data->perm);
    assert_null(fim_data->local_data->attributes);
    assert_null(fim_data->local_data->uid);
    assert_null(fim_data->local_data->gid);
    assert_null(fim_data->local_data->user_name);
    assert_null(fim_data->local_data->group_name);
    assert_int_equal(fim_data->local_data->mtime, 0);
    assert_int_equal(fim_data->local_data->inode, 0);
    assert_int_equal(fim_data->local_data->hash_md5[0], 0);
    assert_int_equal(fim_data->local_data->hash_sha1[0], 0);
    assert_int_equal(fim_data->local_data->hash_sha256[0], 0);
}

static void test_fim_file_add(void **state) {
    fim_data_t *fim_data = *state;
    int ret;
    struct stat buf;

    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    buf.st_ino = 1234;
    buf.st_dev = 2345;
    buf.st_mtime = 3456;

    fim_data->item->index = 1;
    fim_data->item->statbuf = buf;
    fim_data->item->configuration = CHECK_SIZE |
                                    CHECK_PERM  |
                                    CHECK_OWNER |
                                    CHECK_GROUP |
                                    CHECK_MD5SUM |
                                    CHECK_SHA1SUM |
                                    CHECK_SHA256SUM;

    fim_data->item->configuration |= CHECK_SEECHANGES;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "file");

    expect_string(__wrap_w_get_file_permissions, file_path, "file");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "c:\\windows\\system32\\cmd.exe");
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "file");
    will_return(__wrap_fim_db_get_path, NULL);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 1234);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 2345);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);
#endif

    expect_string(__wrap_seechanges_addfile, filename, "file");
    will_return(__wrap_seechanges_addfile, strdup("diff"));

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "file");
    will_return(__wrap_fim_db_insert, 0);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, "file");
    will_return(__wrap_fim_db_set_scanned, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    ret = fim_file("file", fim_data->item, NULL, 1);

    fim_data->item->configuration &= ~CHECK_SEECHANGES;

    assert_int_equal(ret, 0);
}


static void test_fim_file_modify(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;
    fim_data->item->configuration = CHECK_SIZE |
                                    CHECK_PERM  |
                                    CHECK_OWNER |
                                    CHECK_GROUP |
                                    CHECK_MD5SUM |
                                    CHECK_SHA1SUM |
                                    CHECK_SHA256SUM;

    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "file");

    expect_string(__wrap_w_get_file_permissions, file_path, "file");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "c:\\windows\\system32\\cmd.exe");
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "file");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 1234);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 2345);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);
#endif

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "file");
    will_return(__wrap_fim_db_insert, 0);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, "file");
    will_return(__wrap_fim_db_set_scanned, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_file_no_attributes(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "file");

    expect_string(__wrap_w_get_file_permissions, file_path, "file");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "c:\\windows\\system32\\cmd.exe");
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "(6324): Couldn't generate hashes for 'file'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6331): Couldn't get attributes for file: 'file'");

#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_file_error_on_insert(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    fim_data->item->index = 1;
    fim_data->item->configuration = CHECK_SIZE |
                                    CHECK_PERM  |
                                    CHECK_OWNER |
                                    CHECK_GROUP |
                                    CHECK_MD5SUM |
                                    CHECK_SHA1SUM |
                                    CHECK_SHA256SUM;

    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    // Inside fim_get_data
#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "file");

    expect_string(__wrap_w_get_file_permissions, file_path, "file");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "file");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "c:\\windows\\system32\\cmd.exe");
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "file");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

#ifndef TEST_WINAGENT
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 1234);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 2345);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);
#endif

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "file");
    will_return(__wrap_fim_db_insert, -1);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    ret = fim_file("file", fim_data->item, NULL, 1);

    assert_int_equal(ret, OS_INVALID);
}

static void test_fim_checker_scheduled_configuration_directory_error(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/not/found/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_SCHEDULED;

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/not/found/test.file'");

    fim_checker(path, fim_data->item, NULL, 1);
}

static void test_fim_checker_not_scheduled_configuration_directory_error(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/not/found/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/not/found/test.file'");

    fim_checker(path, fim_data->item, NULL, 1);
}

#ifndef TEST_WINAGENT
static void test_fim_checker_invalid_fim_mode(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = -1;

    // Nothing to check on this condition

    fim_checker(path, fim_data->item, NULL, 1);
}

static void test_fim_checker_over_max_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/a/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    syscheck.recursion_level[3] = 0;

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 '/media/a/test.file'");

    fim_checker(path, fim_data->item, NULL, 1);

    syscheck.recursion_level[3] = 50;
}

static void test_fim_checker_deleted_file(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    fim_data->item->index = 3;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap__mdebug1, formatted_msg, "(6222): Stat() function failed on: '/media/test.file' due to [(1)-(Operation not permitted)]");

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, -1);

    errno = 1;

    fim_checker(path, fim_data->item, NULL, 1);

    errno = 0;

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 3);
}

static void test_fim_checker_deleted_file_enoent(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    fim_data->item->index = 3;
    syscheck.opts[3] |= CHECK_SEECHANGES;

    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, -1);
    errno = ENOENT;

    char *diff_path = "/var/ossec/queue/diff/local/media/test.file";

    expect_string(__wrap_seechanges_get_diff_path, path, path);
    will_return(__wrap_seechanges_get_diff_path, strdup(diff_path));

    expect_string(__wrap_IsDir, file, diff_path);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, diff_path);
    will_return(__wrap_DirSize, 200);

    expect_string(__wrap_delete_target_file, path, path);
    will_return(__wrap_delete_target_file, 0);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/media/test.file");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    expect_value(__wrap_fim_db_remove_path, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_remove_path, entry, fim_data->fentry);

    fim_checker(path, fim_data->item, NULL, 1);

    errno = 0;
    syscheck.opts[3] &= ~CHECK_SEECHANGES;

    assert_int_equal(fim_data->item->configuration, 41471);
    assert_int_equal(fim_data->item->index, 3);
}

static void test_fim_checker_no_file_system(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, -1);

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 3);
}

static void test_fim_checker_fim_regular(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    fim_data->item->statbuf.st_dev = 1;
    fim_data->item->statbuf.st_ino = 999;
    fim_data->item->statbuf.st_uid = 0;
    fim_data->item->statbuf.st_gid = 0;
    fim_data->item->statbuf.st_mtime = 1433395216;
    fim_data->item->statbuf.st_size = 1500;
    fim_data->item->index = 3;

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");

    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 999);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 1);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/media/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "/media/test.file");
    will_return(__wrap_fim_db_insert, 0);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, "/media/test.file");
    will_return(__wrap_fim_db_set_scanned, 0);

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 3);
}

static void test_fim_checker_fim_regular_warning(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    fim_data->item->statbuf.st_dev = 1;
    fim_data->item->statbuf.st_ino = 999;
    fim_data->item->statbuf.st_uid = 0;
    fim_data->item->statbuf.st_gid = 0;
    fim_data->item->statbuf.st_mtime = 1433395216;
    fim_data->item->statbuf.st_size = 1500;

    fim_data->item->index = 3;
    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/test.file");
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");

    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 999);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 1);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/media/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "/media/test.file");
    will_return(__wrap_fim_db_insert, -1);

    expect_string(__wrap__mwarn, formatted_msg, "(6923): Unable to process file '/media/test.file'");

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 3);
}

static void test_fim_checker_fim_regular_ignore(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/etc/mtab";
    fim_data->item->index = 3;
    fim_data->item->mode = FIM_WHODATA;

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/etc/mtab");
    will_return(__wrap_HasFilesystem, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6204): Ignoring 'file' '/etc/mtab' due to '/etc/mtab'");

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 66047);
    assert_int_equal(fim_data->item->index, 1);
}

static void test_fim_checker_fim_regular_restrict(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test";
    fim_data->item->index = 3;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_HasFilesystem, path, path);
    will_return(__wrap_HasFilesystem, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6203): Ignoring file '/media/test' due to restriction 'file$'");

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 3);
}

static void test_fim_checker_fim_directory(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/";
    fim_data->item->index = 3;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap_lstat, filename, "/media/");
    will_return(__wrap_lstat, S_IFDIR);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_lstat, filename, "/media/test");
    will_return(__wrap_lstat, S_IFDIR);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/media/");
    expect_string(__wrap_HasFilesystem, path, "/media/test");
    will_return_always(__wrap_HasFilesystem, 0);

    expect_string(__wrap_realtime_adddir, dir, "/media/");
    expect_value(__wrap_realtime_adddir, whodata, 0);
    will_return(__wrap_realtime_adddir, 0);
    expect_string(__wrap_realtime_adddir, dir, "/media/test");
    expect_value(__wrap_realtime_adddir, whodata, 0);
    will_return(__wrap_realtime_adddir, 0);

    strcpy(fim_data->entry->d_name, "test");

    will_return_always(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_readdir, NULL);

    fim_checker(path, fim_data->item, NULL, 1);
}

static void test_fim_checker_fim_directory_on_max_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media";
    struct stat buf;
    buf.st_mode = S_IFDIR;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    syscheck.recursion_level[3] = 0;

    expect_string(__wrap_lstat, filename, "/media");
    will_return(__wrap_lstat, S_IFDIR);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_HasFilesystem, path, "/media");
    will_return(__wrap_HasFilesystem, 0);

    expect_string(__wrap_realtime_adddir, dir, "/media");
    expect_value(__wrap_realtime_adddir, whodata, 0);
    will_return(__wrap_realtime_adddir, 0);

    will_return(__wrap_opendir, 1);
    strcpy(fim_data->entry->d_name, "test");
    will_return(__wrap_readdir, fim_data->entry);

    expect_string(__wrap_lstat, filename, "/media/test");
    will_return(__wrap_lstat, S_IFDIR);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_HasFilesystem, path, "/media/test");
    will_return(__wrap_HasFilesystem, 0);

    will_return(__wrap_readdir, NULL);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6347): Directory '/media/test' is already on the max recursion_level (0), it will not be scanned.");

    fim_checker(path, fim_data->item, NULL, 1);

    syscheck.recursion_level[3] = 50;
}

static void test_fim_checker_root_ignore_file_under_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/media/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 0;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 '/media/test.file'");

    fim_checker(path, fim_data->item, NULL, 1);
}

static void test_fim_checker_root_file_within_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "/test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 0;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap_lstat, filename, "/test.file");
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_HasFilesystem, path, "/test.file");
    will_return(__wrap_HasFilesystem, 0);
    // Inside fim_file
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");

    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_any(__wrap_fim_db_get_paths_from_inode, inode);
    expect_any(__wrap_fim_db_get_paths_from_inode, dev);
    will_return(__wrap_fim_db_get_paths_from_inode, NULL);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "/test.file");
    will_return(__wrap_fim_db_insert, 0);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, "/test.file");
    will_return(__wrap_fim_db_set_scanned, 0);

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 33279);
    assert_int_equal(fim_data->item->index, 0);
}

static void test_fim_scan_db_full_double_scan(void **state) {
    struct dirent *file = *state;

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "/var/ossec/queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of '/var/ossec/queue/diff' folder: 0.00000 KB.");

    int it = 0;

    // First scan
    while (syscheck.dir[it]) {
        expect_string(__wrap_lstat, filename, syscheck.dir[it]);
        will_return(__wrap_lstat, S_IFDIR);
        will_return(__wrap_lstat, 0);
        expect_string(__wrap_HasFilesystem, path, syscheck.dir[it]);
        will_return(__wrap_HasFilesystem, 0);
        if (it == 0 || it == 2 || it == 3){
            expect_string_count(__wrap_realtime_adddir, dir, syscheck.dir[it], 2);
            expect_value_count(__wrap_realtime_adddir, whodata, 0, 2);
            will_return_count(__wrap_realtime_adddir, 0, 2);
        }
        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);

        it++;
    }

    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    // Second scan
    expect_string(__wrap_lstat, filename, "/boot");
    will_return(__wrap_lstat, S_IFDIR);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_HasFilesystem, path, "/boot");
    will_return(__wrap_HasFilesystem, 0);
    expect_string(__wrap_realtime_adddir, dir, "/boot");
    expect_value(__wrap_realtime_adddir, whodata, 0);
    will_return(__wrap_realtime_adddir, 0);
    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, file);

    expect_string(__wrap_lstat, filename, "/boot/test_file");
    will_return(__wrap_lstat, S_IFREG);
    will_return(__wrap_lstat, 0);
    expect_string(__wrap_HasFilesystem, path, "/boot/test_file");
    will_return(__wrap_HasFilesystem, 0);

    // fim_file
    {
        // fim_get_data
        expect_value(__wrap_get_user, uid, 0);
        will_return(__wrap_get_user, strdup("user"));
        expect_value(__wrap_get_group, gid, 0);
        will_return(__wrap_get_group, "group");

        expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
        expect_string(__wrap_fim_db_get_path, file_path, "/boot/test_file");
        will_return(__wrap_fim_db_get_path, 0);

        expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
        expect_string(__wrap_fim_db_insert, file_path, "/boot/test_file");
        will_return(__wrap_fim_db_insert, FIMDB_FULL);
        // fim_json_event
        expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
        expect_any(__wrap_fim_db_get_paths_from_inode, inode);
        expect_any(__wrap_fim_db_get_paths_from_inode, dev);
        will_return(__wrap_fim_db_get_paths_from_inode, NULL);
    }

    will_return(__wrap_readdir, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");
    expect_value(__wrap_fim_db_set_all_unscanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_set_all_unscanned, 0);

    // fim_check_db_state
    will_return(__wrap_fim_db_get_count_entry_path, 50000);
    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    // fim_send_scan_info
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_no_realtime(void **state) {
    int *dir_opts;
    int it = 0;

    while (syscheck.dir[it] != NULL) {
        it++;
    }
    dir_opts = calloc(it, sizeof(int));

    if (!dir_opts) {
        fail();
    }

    it = 0;
    while (syscheck.dir[it] != NULL) {
        dir_opts[it] = syscheck.opts[it];
        syscheck.opts[it] &= ~REALTIME_ACTIVE;
        it++;
    }

    *state = dir_opts;

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "/var/ossec/queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of '/var/ossec/queue/diff' folder: 0.00000 KB.");

    it = 0;
    // First scan
    while (syscheck.dir[it]) {
        expect_string(__wrap_lstat, filename, syscheck.dir[it]);
        will_return(__wrap_lstat, S_IFDIR);
        will_return(__wrap_lstat, 0);
        expect_string(__wrap_HasFilesystem, path, syscheck.dir[it]);
        will_return(__wrap_HasFilesystem, 0);
        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);

        it++;
    }

    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_value(__wrap_fim_db_set_all_unscanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_set_all_unscanned, 0);

    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");

    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_db_full_not_double_scan(void **state) {
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "/var/ossec/queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of '/var/ossec/queue/diff' folder: 0.00000 KB.");

    int it = 0;

    // First scan
    while (syscheck.dir[it]) {
        expect_string(__wrap_lstat, filename, syscheck.dir[it]);
        will_return(__wrap_lstat, S_IFDIR);
        will_return(__wrap_lstat, 0);
        expect_string(__wrap_HasFilesystem, path, syscheck.dir[it]);
        will_return(__wrap_HasFilesystem, 0);
        if (it == 0 || it == 2 || it == 3){
            expect_string_count(__wrap_realtime_adddir, dir, syscheck.dir[it], 2);
            expect_value_count(__wrap_realtime_adddir, whodata, 0, 2);
            will_return_count(__wrap_realtime_adddir, 0, 2);
        }
        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);

        it++;
    }

    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_value(__wrap_fim_db_set_all_unscanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_set_all_unscanned, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");
    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_realtime_enabled(void **state) {
    OSHashNode empty_table = { .key = NULL }, *table = &empty_table;
    OSHash dirtb = { .elements = 10, .table = &table, .rows = 0 }; // this hash is not reallistic but works for testing
    rtfim realtime = { .queue_overflow = true, .dirtb = &dirtb };
    int *dir_opts = calloc(6, sizeof(int));
    int it = 0;

    if (!dir_opts) {
        fail();
    }

    syscheck.realtime = &realtime;

    while (syscheck.dir[it] != NULL) {
        dir_opts[it] = syscheck.opts[it];
        syscheck.opts[it] |= REALTIME_ACTIVE;
        it++;
    }

    *state = dir_opts;

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "/var/ossec/queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of '/var/ossec/queue/diff' folder: 0.00000 KB.");

    it = 0;

    // First scan
    while (syscheck.dir[it]) {
        expect_string(__wrap_lstat, filename, syscheck.dir[it]);
        will_return(__wrap_lstat, S_IFDIR);
        will_return(__wrap_lstat, 0);
        expect_string(__wrap_HasFilesystem, path, syscheck.dir[it]);
        will_return(__wrap_HasFilesystem, 0);
        expect_string_count(__wrap_realtime_adddir, dir, syscheck.dir[it], 2);
        expect_value_count(__wrap_realtime_adddir, whodata, 0, 2);
        will_return_count(__wrap_realtime_adddir, 0, 2);
        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);

        it++;
    }

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_value(__wrap_fim_db_set_all_unscanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_set_all_unscanned, 0);

    // fim_scan
    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");

    // fim_check_db_state
    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    // realtime_sanitize_watch_map
    expect_any(__wrap__mdebug2, formatted_msg);

    // fim_scan
    expect_string(__wrap__mdebug2, formatted_msg, "(6345): Folders monitored with real-time engine: 10");

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();

    assert_int_equal(syscheck.realtime->queue_overflow, false);
}

static void test_fim_scan_db_free(void **state) {
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "/var/ossec/queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of '/var/ossec/queue/diff' folder: 0.00000 KB.");

    int it = 0;

    // First scan
    while (syscheck.dir[it]) {
        expect_string(__wrap_lstat, filename, syscheck.dir[it]);
        will_return(__wrap_lstat, S_IFDIR);
        will_return(__wrap_lstat, 0);
        expect_string(__wrap_HasFilesystem, path, syscheck.dir[it]);
        will_return(__wrap_HasFilesystem, 0);
        if (it == 0 || it == 2 || it == 3){
            expect_string_count(__wrap_realtime_adddir, dir, syscheck.dir[it], 2);
            expect_value_count(__wrap_realtime_adddir, whodata, 0, 2);
            will_return_count(__wrap_realtime_adddir, 0, 2);
        }
        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);

        it++;
    }

    will_return(__wrap_fim_db_get_count_entry_path, 1000);

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");

    will_return(__wrap_fim_db_get_count_entry_path, 1000);

    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":1000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_no_limit(void **state) {
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "/var/ossec/queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "/var/ossec/queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of '/var/ossec/queue/diff' folder: 0.00000 KB.");

    int it = 0;

    // First scan
    while (syscheck.dir[it]) {
        expect_string(__wrap_lstat, filename, syscheck.dir[it]);
        will_return(__wrap_lstat, S_IFDIR);
        will_return(__wrap_lstat, 0);
        expect_string(__wrap_HasFilesystem, path, syscheck.dir[it]);
        will_return(__wrap_HasFilesystem, 0);
        if (it == 0 || it == 2 || it == 3){
            expect_string_count(__wrap_realtime_adddir, dir, syscheck.dir[it], 2);
            expect_value_count(__wrap_realtime_adddir, whodata, 0, 2);
            will_return_count(__wrap_realtime_adddir, 0, 2);
        }
        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);

        it++;
    }

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_string(__wrap__mdebug2, formatted_msg, "(6343): No limit set to maximum number of files to be monitored");

    // In fim_scan
    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

#else
static void test_fim_checker_invalid_fim_mode(void **state) {
    fim_data_t *fim_data = *state;

    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 3;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = -1;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    // Nothing to check on this condition
    fim_checker(expanded_path, fim_data->item, NULL, 1);
}

static void test_fim_checker_over_max_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char *path = "%WINDIR%\\System32\\drivers\\etc\\random\\test.exe";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 2;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    syscheck.recursion_level[2] = 0;
    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    snprintf(debug_msg, OS_MAXSTR,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 '%s'", expanded_path);

    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(expanded_path, fim_data->item, NULL, 1);
}

static void test_fim_checker_deleted_file(void **state) {
    fim_data_t *fim_data = *state;

    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    fim_data->item->index = 7;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap__mdebug1, formatted_msg, "(6222): Stat() function failed on: 'c:\\windows\\system32\\drivers\\etc\\test.exe' due to [(1)-(Operation not permitted)]");

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(__wrap_stat, __file, expanded_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, -1);

    errno = 1;

    fim_checker(expanded_path, fim_data->item, NULL, 1);

    errno = 0;

    assert_int_equal(fim_data->item->configuration, 37375);
    assert_int_equal(fim_data->item->index, 7);
}

static void test_fim_checker_deleted_file_enoent(void **state) {
    fim_data_t *fim_data = *state;

    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    fim_data->item->index = 7;
    syscheck.opts[7] |= CHECK_SEECHANGES;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

    expect_string(__wrap_stat, __file, expanded_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, -1);

    errno = ENOENT;

    char *diff_path = "queue/diff/local/c\\windows\\system32\\drivers\\etc\\test.exe";

    expect_string(__wrap_seechanges_get_diff_path, path, expanded_path);
    will_return(__wrap_seechanges_get_diff_path, strdup(diff_path));

    expect_string(__wrap_IsDir, file, diff_path);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, diff_path);
    will_return(__wrap_DirSize, 200);

    expect_string(__wrap_delete_target_file, path, expanded_path);
    will_return(__wrap_delete_target_file, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, expanded_path);
    will_return(__wrap_fim_db_get_path, fim_data->fentry);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_value(__wrap_fim_db_remove_path, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_remove_path, entry, fim_data->fentry);

    fim_checker(expanded_path, fim_data->item, NULL, 1);

    errno = 0;
    syscheck.opts[7] &= ~CHECK_SEECHANGES;

    assert_int_equal(fim_data->item->configuration, 45567);
    assert_int_equal(fim_data->item->index, 7);
}

static void test_fim_checker_fim_regular(void **state) {
    fim_data_t *fim_data = *state;

    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    fim_data->item->index = 7;
    fim_data->item->statbuf.st_size = 1500;

    expect_string(__wrap_stat, __file, expanded_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, 0);

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_string(__wrap_get_UTC_modification_time, file_path, expanded_path);
    will_return(__wrap_get_UTC_modification_time, 123456);

    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, expanded_path);

    expect_string(__wrap_w_get_file_permissions, file_path, expanded_path);
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");

    expect_string(__wrap_w_get_file_attrs, file_path, expanded_path);
    will_return(__wrap_w_get_file_attrs, 123456);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, expanded_path);
    will_return(__wrap_fim_db_get_path, NULL);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, expanded_path);
    will_return(__wrap_fim_db_insert, 0);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, expanded_path);
    will_return(__wrap_fim_db_set_scanned, 0);

    fim_checker(expanded_path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 37375);
    assert_int_equal(fim_data->item->index, 7);
}

static void test_fim_checker_fim_regular_ignore(void **state) {
    fim_data_t *fim_data = *state;

    char *path = "%WINDIR%\\System32\\drivers\\etc\\ignored.file";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];
    fim_data->item->index = 7;
    // fim_data->item->mode = FIM_REALTIME;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(__wrap_stat, __file, expanded_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    snprintf(debug_msg, OS_MAXSTR, "(6204): Ignoring 'file' '%s' due to '%s'", expanded_path, expanded_path);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(expanded_path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 37375);
    assert_int_equal(fim_data->item->index, 7);
}

static void test_fim_checker_fim_regular_restrict(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "%WINDIR%\\System32\\wbem\\restricted.exe";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];
    fim_data->item->index = 8;
    fim_data->item->mode = FIM_REALTIME;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(__wrap_stat, __file, expanded_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    snprintf(debug_msg, OS_MAXSTR, "(6203): Ignoring file '%s' due to restriction 'wmic.exe$'", expanded_path);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    fim_checker(expanded_path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 37375);
    assert_int_equal(fim_data->item->index, 8);
}

static void test_fim_checker_fim_regular_warning(void **state) {
    fim_data_t *fim_data = *state;
    char *path = "%WINDIR%\\System32\\drivers\\etc\\test.exe";
    char expanded_path[OS_MAXSTR];
    char debug_msg[OS_MAXSTR];
    fim_data->item->index = 7;
    fim_data->item->statbuf.st_size = 1500;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    expect_string(__wrap_stat, __file, expanded_path);
    will_return(__wrap_stat, S_IFREG);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    will_return(__wrap_HasFilesystem, 0);

    // Inside fim_file
    expect_string(__wrap_get_UTC_modification_time, file_path, expanded_path);
    will_return(__wrap_get_UTC_modification_time, 123456);

    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, expanded_path);

    expect_string(__wrap_w_get_file_permissions, file_path, expanded_path);
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");

    expect_string(__wrap_w_get_file_attrs, file_path, expanded_path);
    will_return(__wrap_w_get_file_attrs, 123456);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, expanded_path);
    will_return(__wrap_fim_db_get_path, NULL);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, expanded_path);
    will_return(__wrap_fim_db_insert, -1);

    snprintf(debug_msg, OS_MAXSTR, "(6923): Unable to process file '%s'", expanded_path);
    expect_string(__wrap__mwarn, formatted_msg, debug_msg);

    fim_checker(expanded_path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 37375);
    assert_int_equal(fim_data->item->index, 7);
}

static void test_fim_checker_fim_directory(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "%WINDIR%\\System32\\drivers\\etc";
    char skip_directory_message[OS_MAXSTR];
    char expanded_path[OS_MAXSTR];
    char expanded_path_test[OS_MAXSTR];
    fim_data->item->index = 7;
    fim_data->item->mode = FIM_REALTIME;

    if(!ExpandEnvironmentStrings(path, expanded_path, OS_MAXSTR))
        fail();

    str_lowercase(expanded_path);

    snprintf(expanded_path_test, OS_MAXSTR, "%s\\test", expanded_path);

    expect_string(__wrap_stat, __file, expanded_path);
    expect_string(__wrap_stat, __file, expanded_path_test);
    will_return(__wrap_stat, S_IFDIR);
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, S_IFDIR);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_HasFilesystem, path, expanded_path);
    expect_string(__wrap_HasFilesystem, path, expanded_path_test);
    will_return_always(__wrap_HasFilesystem, 0);

    strcpy(fim_data->entry->d_name, "test");

    will_return_always(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);

    snprintf(skip_directory_message, OS_MAXSTR,
        "(6347): Directory '%s' is already on the max recursion_level (0), it will not be scanned.", expanded_path_test);
    expect_string(__wrap__mdebug2, formatted_msg, skip_directory_message);

    fim_checker(expanded_path, fim_data->item, NULL, 1);
}


static void test_fim_checker_root_ignore_file_under_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "c:\\windows\\test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 0;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6217): Maximum level of recursion reached. Depth:1 recursion_level:0 'c:\\windows\\test.file'");

    fim_checker(path, fim_data->item, NULL, 1);
}

static void test_fim_checker_root_file_within_recursion_level(void **state) {
    fim_data_t *fim_data = *state;

    char * path = "c:\\test.file";
    struct stat buf;
    buf.st_mode = S_IFREG;
    fim_data->item->index = 0;
    fim_data->item->statbuf = buf;
    fim_data->item->mode = FIM_REALTIME;

    // Inside fim_file
    expect_string(__wrap_get_UTC_modification_time, file_path, path);
    will_return(__wrap_get_UTC_modification_time, 123456);

    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "c:\\test.file");

    expect_string(__wrap_w_get_file_permissions, file_path, "c:\\test.file");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");

    expect_string(__wrap_w_get_file_attrs, file_path, "c:\\test.file");
    will_return(__wrap_w_get_file_attrs, 123456);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "c:\\test.file");
    will_return(__wrap_fim_db_get_path, NULL);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "c:\\test.file");
    will_return(__wrap_fim_db_insert, 0);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, "c:\\test.file");
    will_return(__wrap_fim_db_set_scanned, 0);

    expect_string(__wrap_stat, __file, "c:\\test.file");
    will_return(__wrap_stat, buf.st_mode);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_HasFilesystem, path, "c:\\test.file");
    will_return(__wrap_HasFilesystem, 0);

    fim_checker(path, fim_data->item, fim_data->w_evt, 1);

    assert_int_equal(fim_data->item->configuration, 37375);
    assert_int_equal(fim_data->item->index, 0);
}

static void test_fim_scan_db_full_double_scan(void **state) {

    struct dirent *file = *state;
    char test_file_path[160];

    char expanded_dirs[10][OS_SIZE_1024];
    char directories[10][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\SysNative",
        "%WINDIR%\\SysNative\\drivers\\etc",
        "%WINDIR%\\SysNative\\wbem",
        "%WINDIR%\\SysNative\\WindowsPowerShell\\v1.0",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 10; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(__wrap_stat, __file, expanded_dirs[i]);
        will_return(__wrap_stat, S_IFDIR);
        will_return(__wrap_stat, 0);
        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    snprintf(test_file_path, 160, "%s\\test_file", expanded_dirs[0]);

    prepare_win_double_scan_success(test_file_path, expanded_dirs[0], file);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");
    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);
    fim_scan();
}

static void test_fim_scan_db_full_not_double_scan(void **state) {
    char expanded_dirs[10][OS_SIZE_1024];
    char directories[10][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\SysNative",
        "%WINDIR%\\SysNative\\drivers\\etc",
        "%WINDIR%\\SysNative\\wbem",
        "%WINDIR%\\SysNative\\WindowsPowerShell\\v1.0",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 10; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(__wrap_stat, __file, expanded_dirs[i]);
        will_return(__wrap_stat, S_IFDIR);
        will_return(__wrap_stat, 0);
        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    will_return(__wrap_fim_db_get_count_entry_path, 50000);

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_value(__wrap_fim_db_set_all_unscanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_set_all_unscanned, 0);

    will_return(__wrap_fim_db_get_count_entry_path, 50000);
    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_db_free(void **state) {
    char expanded_dirs[10][OS_SIZE_1024];
    char directories[10][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\SysNative",
        "%WINDIR%\\SysNative\\drivers\\etc",
        "%WINDIR%\\SysNative\\wbem",
        "%WINDIR%\\SysNative\\WindowsPowerShell\\v1.0",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 10; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(__wrap_stat, __file, expanded_dirs[i]);
        will_return(__wrap_stat, S_IFDIR);
        will_return(__wrap_stat, 0);
        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    will_return(__wrap_fim_db_get_count_entry_path, 1000);

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    will_return(__wrap_fim_db_get_count_entry_path, 1000);

    expect_string(__wrap__mdebug2, formatted_msg, "(6342): Maximum number of files to be monitored: '50000'");

    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":1000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}

static void test_fim_scan_no_limit(void **state) {
    char expanded_dirs[10][OS_SIZE_1024];
    char directories[10][OS_SIZE_256] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%",
        "%WINDIR%\\SysNative",
        "%WINDIR%\\SysNative\\drivers\\etc",
        "%WINDIR%\\SysNative\\wbem",
        "%WINDIR%\\SysNative\\WindowsPowerShell\\v1.0",
        "%WINDIR%\\System32",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
    };
    int i;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_STARTED);

    // fim_diff_folder_size
    expect_string(__wrap_IsDir, file, "queue/diff/local");
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, "queue/diff/local");
    will_return(__wrap_DirSize, 0.0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6348): Size of 'queue/diff' folder: 0.00000 KB.");

    for(i = 0; i < 10; i++) {
        if(!ExpandEnvironmentStrings(directories[i], expanded_dirs[i], OS_SIZE_1024)) {
            fail();
        }
        str_lowercase(expanded_dirs[i]);

        expect_string(__wrap_stat, __file, expanded_dirs[i]);
        will_return(__wrap_stat, S_IFDIR);
        will_return(__wrap_stat, 0);
        expect_string(__wrap_HasFilesystem, path, expanded_dirs[i]);
        will_return(__wrap_HasFilesystem, 0);

        will_return(__wrap_opendir, 1);
        will_return(__wrap_readdir, NULL);
    }

    // check_deleted_files
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_string(__wrap__mdebug2, formatted_msg, "(6343): No limit set to maximum number of files to be monitored");

    expect_string(__wrap__minfo, formatted_msg, FIM_FREQUENCY_ENDED);

    fim_scan();
}
#endif

/* fim_check_db_state */
static void test_fim_check_db_state_normal_to_empty(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_empty(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_full(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 50000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_empty(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":0,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_90_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 46000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 90% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_empty(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":0,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_80_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 41000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 80% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_empty(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 0);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":0,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);
}

static void test_fim_check_db_state_empty_to_normal(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 10000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_EMPTY);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_normal(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 20000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_full(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 50000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_normal(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 10000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":10000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_90_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 46000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 90% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_normal(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 10000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":10000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);
}

static void test_fim_check_db_state_normal_to_80_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 41000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 80% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_80_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 42000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_full(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 50000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_80_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 41000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 80% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_90_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 46000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 90% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_90_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 48000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_full(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 50000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__mwarn, formatted_msg, "(6927): Sending DB 100% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":50000,\"alert_type\":\"full\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_full(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 60000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    assert_int_equal(_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);
}

static void test_fim_check_db_state_full_to_90_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 46000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 90% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":46000,\"alert_type\":\"90_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_FULL);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);
}

static void test_fim_check_db_state_90_percentage_to_80_percentage(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 41000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6039): Sending DB 80% full alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":41000,\"alert_type\":\"80_percentage\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_90_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);
}

static void test_fim_check_db_state_80_percentage_to_normal(void **state) {
    (void) state;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    will_return(__wrap_fim_db_get_count_entry_path, 10000);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__minfo, formatted_msg, "(6038): Sending DB back to normal alert.");
    expect_string(__wrap_send_log_msg, msg, "wazuh: FIM DB: {\"file_limit\":50000,\"file_count\":10000,\"alert_type\":\"normal\"}");
    will_return(__wrap_send_log_msg, 1);

    assert_int_equal(_db_state, FIM_STATE_DB_80_PERCENTAGE);

    fim_check_db_state();

    assert_int_equal(_db_state, FIM_STATE_DB_NORMAL);
}

/* fim_directory */
static void test_fim_directory(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    strcpy(fim_data->entry->d_name, "test");

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);

#ifndef TEST_WINAGENT
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'test/test'");
#else
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'test\\test'");
#endif

    fim_data->item->index = 1;

    ret = fim_directory("test", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_directory_ignore(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    strcpy(fim_data->entry->d_name, ".");

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, fim_data->entry);
    will_return(__wrap_readdir, NULL);

    fim_data->item->index = 1;

    ret = fim_directory(".", fim_data->item, NULL, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_directory_nodir(void **state) {
    int ret;

    expect_string(__wrap__merror, formatted_msg, "(1105): Attempted to use null string.");

    ret = fim_directory(NULL, NULL, NULL, 1);

    assert_int_equal(ret, OS_INVALID);
}

static void test_fim_directory_opendir_error(void **state) {
    int ret;

    will_return(__wrap_opendir, 0);

    expect_string(__wrap__mwarn, formatted_msg, "(6922): Cannot open 'test': Permission denied");

    errno = EACCES;

    ret = fim_directory("test", NULL, NULL, 1);

    errno = 0;

    assert_int_equal(ret, OS_INVALID);
}

/* fim_get_data */
static void test_fim_get_data(void **state) {
    fim_data_t *fim_data = *state;
    struct stat buf;

    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    buf.st_ino = 1234;
    buf.st_dev = 2345;
    buf.st_mtime = 3456;

    fim_data->item->index = 1;
    fim_data->item->statbuf = buf;
    fim_data->item->configuration = CHECK_SIZE |
                                    CHECK_PERM |
                                    CHECK_MTIME |
                                    CHECK_OWNER |
                                    CHECK_GROUP |
                                    CHECK_MD5SUM |
                                    CHECK_SHA1SUM |
                                    CHECK_SHA256SUM;

#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    expect_string(__wrap_get_UTC_modification_time, file_path, "test");
    will_return(__wrap_get_UTC_modification_time, 123456);

    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "test");

    expect_string(__wrap_w_get_file_permissions, file_path, "test");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "test");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "c:\\windows\\system32\\cmd.exe");
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, 0);

    fim_data->local_data = fim_get_data("test", fim_data->item);

#ifndef TEST_WINAGENT
    assert_string_equal(fim_data->local_data->perm, "r--r--r--");
#else
    assert_string_equal(fim_data->local_data->perm, "decoded_perms");
#endif
    assert_string_equal(fim_data->local_data->hash_md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(fim_data->local_data->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(fim_data->local_data->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_fim_get_data_no_hashes(void **state) {
    fim_data_t *fim_data = *state;
    struct stat buf;

    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    buf.st_ino = 1234;
    buf.st_dev = 2345;
    buf.st_mtime = 3456;

    fim_data->item->index = 1;
    fim_data->item->statbuf = buf;
    fim_data->item->configuration = 0 | CHECK_SIZE |
                                    CHECK_PERM |
                                    CHECK_MTIME |
                                    CHECK_OWNER |
                                    CHECK_GROUP;

#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    expect_string(__wrap_get_UTC_modification_time, file_path, "test");
    will_return(__wrap_get_UTC_modification_time, 123456);

    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "test");

    expect_string(__wrap_w_get_file_permissions, file_path, "test");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    fim_data->local_data = fim_get_data("test", fim_data->item);

#ifndef TEST_WINAGENT
    assert_string_equal(fim_data->local_data->perm, "r--r--r--");
#else
    assert_string_equal(fim_data->local_data->perm, "decoded_perms");
#endif
    assert_string_equal(fim_data->local_data->hash_md5, "");
    assert_string_equal(fim_data->local_data->hash_sha1, "");
    assert_string_equal(fim_data->local_data->hash_sha256, "");
}

static void test_fim_get_data_hash_error(void **state) {
    fim_data_t *fim_data = *state;

    fim_data->item->index = 1;
    fim_data->item->configuration = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_MTIME | \
                          CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP;
    struct stat buf;
    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    fim_data->item->statbuf = buf;

#ifndef TEST_WINAGENT
    expect_value(__wrap_get_user, uid, 0);
    will_return(__wrap_get_user, strdup("user"));

    expect_value(__wrap_get_group, gid, 0);
    will_return(__wrap_get_group, "group");
#else
    expect_string(__wrap_get_UTC_modification_time, file_path, "test");
    will_return(__wrap_get_UTC_modification_time, 123456);

    will_return(__wrap_get_user, "0");
    will_return(__wrap_get_user, strdup("user"));
    expect_string(__wrap_get_user, path, "test");

    expect_string(__wrap_w_get_file_permissions, file_path, "test");
    will_return(__wrap_w_get_file_permissions, "permissions");
    will_return(__wrap_w_get_file_permissions, 0);

    expect_string(__wrap_decode_win_permissions, raw_perm, "permissions");
    will_return(__wrap_decode_win_permissions, "decoded_perms");
#endif

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, "test");
#ifndef TEST_WINAGENT
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "/bin/ls");
#else
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, "c:\\windows\\system32\\cmd.exe");
#endif
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, "d41d8cd98f00b204e9800998ecf8427e");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, OS_BINARY);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, 0x400);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "(6324): Couldn't generate hashes for 'test'");

    fim_data->local_data = fim_get_data("test", fim_data->item);

    assert_null(fim_data->local_data);
}

#ifdef TEST_WINAGENT
static void test_fim_get_data_fail_to_get_file_premissions(void **state) {
    fim_data_t *fim_data = *state;
    struct stat buf;

    buf.st_mode = S_IFREG | 00444 ;
    buf.st_size = 1000;
    buf.st_uid = 0;
    buf.st_gid = 0;
    buf.st_ino = 1234;
    buf.st_dev = 2345;
    buf.st_mtime = 3456;

    fim_data->item->index = 1;
    fim_data->item->statbuf = buf;
    fim_data->item->configuration = CHECK_SIZE |
                                    CHECK_PERM |
                                    CHECK_MTIME |
                                    CHECK_OWNER |
                                    CHECK_GROUP |
                                    CHECK_MD5SUM |
                                    CHECK_SHA1SUM |
                                    CHECK_SHA256SUM;

    expect_string(__wrap__mdebug1, formatted_msg, "(6325): It was not possible to extract the permissions of 'test'. Error: 5");

    expect_string(__wrap_w_get_file_permissions, file_path, "test");
    will_return(__wrap_w_get_file_permissions, "");
    will_return(__wrap_w_get_file_permissions, ERROR_ACCESS_DENIED);


    fim_data->local_data = fim_get_data("test", fim_data->item);

    assert_null(fim_data->local_data);
}
#endif

static void test_check_deleted_files(void **state) {
    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->elements = 1;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, file);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_OK);

    expect_value(__wrap_fim_db_delete_not_scanned, fim_sql, syscheck.database);
    will_return(__wrap_fim_db_delete_not_scanned, FIMDB_OK);

    check_deleted_files();

    free(file);
}

static void test_check_deleted_files_error(void **state) {
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_value(__wrap_fim_db_get_not_scanned, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_not_scanned, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_not_scanned, NULL);
    will_return(__wrap_fim_db_get_not_scanned, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, FIM_DB_ERROR_RM_NOT_SCANNED);

    check_deleted_files();
}

static void test_free_inode_data(void **state) {
    fim_inode_data *inode_data = calloc(1, sizeof(fim_inode_data));
    inode_data->items = 1;
    inode_data->paths = os_AddStrArray("test.file", inode_data->paths);

    free_inode_data(&inode_data);

    assert_null(inode_data);
}

static void test_free_inode_data_null(void **state) {
    fim_inode_data *inode_data = NULL;

    free_inode_data(&inode_data);

    assert_null(inode_data);
}

static void test_fim_realtime_event_file_exists(void **state) {

    fim_data_t *fim_data = *state;

    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");

#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, "/test");
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);
#else
    expect_string(__wrap_stat, __file, "/test");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/test'");

    fim_realtime_event("/test");
}

static void test_fim_realtime_event_file_missing(void **state) {

#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, "/test");
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);
#else
    expect_string(__wrap_stat, __file, "/test");
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);
#endif
    errno = ENOENT;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/test");
    will_return(__wrap_fim_db_get_path, NULL);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
#ifdef TEST_WINAGENT
    expect_string(__wrap_fim_db_get_path_range, start, "/test\\");
    expect_string(__wrap_fim_db_get_path_range, top, "/test]");
#else
    expect_string(__wrap_fim_db_get_path_range, start, "/test/");
    expect_string(__wrap_fim_db_get_path_range, top, "/test0");
#endif
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    fim_realtime_event("/test");
    errno = 0;
}

static void test_fim_whodata_event_file_exists(void **state) {

    fim_data_t *fim_data = *state;

#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, fim_data->w_evt->path);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);
#else
    expect_string(__wrap_stat, __file, fim_data->w_evt->path);
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, 0);
#endif

    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'./test/test.file'");

    fim_whodata_event(fim_data->w_evt);
}

static void test_fim_whodata_event_file_missing(void **state) {
    fim_data_t *fim_data = *state;

#ifndef TEST_WINAGENT
    expect_string(__wrap_lstat, filename, fim_data->w_evt->path);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);
#else
    expect_string(__wrap_stat, __file, fim_data->w_evt->path);
    will_return(__wrap_stat, 0);
    will_return(__wrap_stat, -1);
#endif
    errno = ENOENT;

    char **paths = calloc(4, sizeof(char *));
    paths[0] = strdup("./test/test.file");
    paths[1] = strdup("./test/test.file");
    paths[2] = strdup("./test/test.file");
    paths[3] = NULL;

#ifdef TEST_WINAGENT
    // Inside fim_process_missing_entry
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "./test/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
#ifdef TEST_WINAGENT
    expect_string(__wrap_fim_db_get_path_range, start, "./test/test.file\\");
    expect_string(__wrap_fim_db_get_path_range, top, "./test/test.file]");
#else
    expect_string(__wrap_fim_db_get_path_range, start, "./test/test.file/");
    expect_string(__wrap_fim_db_get_path_range, top, "./test/test.file0");
#endif
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);

    expect_function_call(__wrap_pthread_mutex_unlock);
#else
    expect_value(__wrap_fim_db_get_paths_from_inode, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_get_paths_from_inode, inode, 606060);
    expect_value(__wrap_fim_db_get_paths_from_inode, dev, 12345678);
    will_return(__wrap_fim_db_get_paths_from_inode, paths);

    // Inside fim_process_missing_entry
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "./test/test.file");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "./test/test.file/");
    expect_string(__wrap_fim_db_get_path_range, top, "./test/test.file0");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);

    for(int i = 0; paths[i]; i++) {
        // Inside fim_process_missing_entry
        expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
        expect_string(__wrap_fim_db_get_path, file_path, paths[i]);
        will_return(__wrap_fim_db_get_path, NULL);

        expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
        expect_string(__wrap_fim_db_get_path_range, start, "./test/test.file/");
        expect_string(__wrap_fim_db_get_path_range, top, "./test/test.file0");
        expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
        will_return(__wrap_fim_db_get_path_range, NULL);
        will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);
    }
#endif

    fim_whodata_event(fim_data->w_evt);
    errno = 0;
}

static void test_fim_process_missing_entry_no_data(void **state) {
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/test");
    will_return(__wrap_fim_db_get_path, NULL);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
#ifdef TEST_WINAGENT
    expect_string(__wrap_fim_db_get_path_range, start, "/test\\");
    expect_string(__wrap_fim_db_get_path_range, top, "/test]");
#else
    expect_string(__wrap_fim_db_get_path_range, start, "/test/");
    expect_string(__wrap_fim_db_get_path_range, top, "/test0");
#endif
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    fim_process_missing_entry("/test", FIM_REALTIME, NULL);
}

static void test_fim_process_missing_entry_failure(void **state) {

    fim_tmp_file *file = calloc(1, sizeof(fim_tmp_file));
    file->elements = 1;
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/test");
    will_return(__wrap_fim_db_get_path, NULL);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
#ifdef TEST_WINAGENT
    expect_string(__wrap_fim_db_get_path_range, start, "/test\\");
    expect_string(__wrap_fim_db_get_path_range, top, "/test]");
#else
    expect_string(__wrap_fim_db_get_path_range, start, "/test/");
    expect_string(__wrap_fim_db_get_path_range, top, "/test0");
#endif
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_value(__wrap_fim_db_process_missing_entry, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_process_missing_entry, file, file);
    expect_value(__wrap_fim_db_process_missing_entry, storage, FIM_DB_DISK);
    expect_value(__wrap_fim_db_process_missing_entry, mode, FIM_REALTIME);
    will_return(__wrap_fim_db_process_missing_entry, FIMDB_ERR);

#ifndef TEST_WINAGENT
    expect_string(__wrap__merror, formatted_msg, "(6708): Failed to delete a range of paths between '/test/' and '/test0'");
#else
    expect_string(__wrap__merror, formatted_msg, "(6708): Failed to delete a range of paths between '/test\\' and '/test]'");
#endif

    fim_process_missing_entry("/test", FIM_REALTIME, NULL);

    free(file);
}

static void test_fim_process_missing_entry_data_exists(void **state) {

    fim_data_t *fim_data = *state;

    fim_data->fentry->path = strdup("file");
    fim_data->fentry->data = fim_data->local_data;

    fim_data->local_data->size = 1500;
    fim_data->local_data->perm = strdup("0664");
    fim_data->local_data->attributes = strdup("r--r--r--");
    fim_data->local_data->uid = strdup("100");
    fim_data->local_data->gid = strdup("1000");
    fim_data->local_data->user_name = strdup("test");
    fim_data->local_data->group_name = strdup("testing");
    fim_data->local_data->mtime = 1570184223;
    fim_data->local_data->inode = 606060;
    strcpy(fim_data->local_data->hash_md5, "3691689a513ace7e508297b583d7050d");
    strcpy(fim_data->local_data->hash_sha1, "07f05add1049244e7e71ad0f54f24d8094cd8f8b");
    strcpy(fim_data->local_data->hash_sha256, "672a8ceaea40a441f0268ca9bbb33e99f9643c6262667b61fbe57694df224d40");
    fim_data->local_data->mode = FIM_REALTIME;
    fim_data->local_data->last_event = 1570184220;
    fim_data->local_data->entry_type = FIM_TYPE_FILE;
    fim_data->local_data->dev = 12345678;
    fim_data->local_data->scanned = 123456;
    fim_data->local_data->options = 511;
    strcpy(fim_data->local_data->checksum, "");
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_lock);
#endif
    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "/test");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);
#ifdef TEST_WINAGENT
    expect_function_call(__wrap_pthread_mutex_unlock);
#endif
    expect_string(__wrap__mdebug2, formatted_msg, "(6319): No configuration found for (file):'/test'");

    fim_process_missing_entry("/test", FIM_WHODATA, fim_data->w_evt);
}

void test_fim_diff_folder_size(void **state) {
    (void) state;
    char *diff_local;

    diff_local = (char *)calloc(strlen(DIFF_DIR_PATH) + strlen("/local") + 1, sizeof(char));

    snprintf(diff_local, strlen(DIFF_DIR_PATH) + strlen("/local") + 1, "%s/local", DIFF_DIR_PATH);

    expect_string(__wrap_IsDir, file, diff_local);
    will_return(__wrap_IsDir, 0);

    expect_string(__wrap_DirSize, path, diff_local);
    will_return(__wrap_DirSize, 20 * 1024);

    fim_diff_folder_size();

    assert_int_equal(syscheck.diff_folder_size, 20);

    if (diff_local) {
        free(diff_local);
    }
}

// Windows specific tests
#ifdef TEST_WINAGENT
static void test_fim_registry_event_null_data(void **state) {
    expect_assert_failure(fim_registry_event("HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile", NULL, 0));
}

static void test_fim_registry_event_invalid_add(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_insert, -1);

    ret = fim_registry_event("HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile", fim_data->local_data, 0);

    assert_int_equal(ret, OS_INVALID);
}

static void test_fim_registry_event_invalid_modification(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_insert, -1);

    ret = fim_registry_event("HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile", fim_data->new_data, 0);

    assert_int_equal(ret, OS_INVALID);
}

static void test_fim_registry_event_valid_add(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_get_path, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_insert, 1);

    ret = fim_registry_event("HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile", fim_data->local_data, 0);

    assert_int_equal(ret, 1);
}

static void test_fim_registry_event_valid_modification(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_fim_db_insert, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_insert, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_insert, 1);

    ret = fim_registry_event("HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile", fim_data->new_data, 0);

    assert_int_equal(ret, 1);
}

static void test_fim_registry_event_already_scanned(void **state) {
    fim_data_t *fim_data = *state;
    int ret;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_fim_db_get_path, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path, file_path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_get_path, fim_data->fentry);

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_fim_db_set_scanned, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_set_scanned, path, "HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile");
    will_return(__wrap_fim_db_set_scanned, 0);

    ret = fim_registry_event("HKEY_LOCAL_MACHINE\\Software\\Classes\\cmdfile", fim_data->local_data, 0);

    assert_int_equal(ret, 0);
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_json_event */
        cmocka_unit_test_teardown(test_fim_json_event, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_whodata, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_no_changes, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_hardlink_one_path, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_event_hardlink_two_paths, teardown_delete_json),

        /* fim_attributes_json */
        cmocka_unit_test_teardown(test_fim_attributes_json, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_attributes_json_without_options, teardown_delete_json),

        /* fim_entry_json */
        cmocka_unit_test_teardown(test_fim_entry_json, teardown_delete_json),
        cmocka_unit_test(test_fim_entry_json_null_path),
        cmocka_unit_test(test_fim_entry_json_null_data),

        /* fim_json_compare_attrs */
        cmocka_unit_test_teardown(test_fim_json_compare_attrs, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_json_compare_attrs_without_options, teardown_delete_json),

        /* fim_audit_json */
        cmocka_unit_test_teardown(test_fim_audit_json, teardown_delete_json),

        /* fim_check_ignore */
        cmocka_unit_test(test_fim_check_ignore_strncasecmp),
        cmocka_unit_test(test_fim_check_ignore_regex),
        cmocka_unit_test(test_fim_check_ignore_failure),

        /* fim_check_restrict */
        cmocka_unit_test(test_fim_check_restrict_success),
        cmocka_unit_test(test_fim_check_restrict_failure),
        cmocka_unit_test(test_fim_check_restrict_null_filename),
        cmocka_unit_test(test_fim_check_restrict_null_restriction),

        /* fim_scan_info */
        cmocka_unit_test_teardown(test_fim_scan_info_json_start, teardown_delete_json),
        cmocka_unit_test_teardown(test_fim_scan_info_json_end, teardown_delete_json),

        /* fim_get_checksum */
        cmocka_unit_test_setup_teardown(test_fim_get_checksum, setup_fim_entry, teardown_fim_entry),
        cmocka_unit_test_setup_teardown(test_fim_get_checksum_wrong_size, setup_fim_entry, teardown_fim_entry),

        /* fim_check_depth */
        cmocka_unit_test(test_fim_check_depth_success),
        cmocka_unit_test(test_fim_check_depth_failure_strlen),
        cmocka_unit_test(test_fim_check_depth_failure_null_directory),

        /* fim_configuration_directory */
        cmocka_unit_test(test_fim_configuration_directory_no_path),
        cmocka_unit_test(test_fim_configuration_directory_file),
        cmocka_unit_test(test_fim_configuration_directory_not_found),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_fim_configuration_directory_registry_not_found),
        cmocka_unit_test(test_fim_configuration_directory_registry_found),
#endif

        /* init_fim_data_entry */
        cmocka_unit_test_setup_teardown(test_init_fim_data_entry, setup_fim_entry, teardown_fim_entry),

        /* fim_file */
        cmocka_unit_test(test_fim_file_add),
        cmocka_unit_test_setup(test_fim_file_modify, setup_fim_entry),
        cmocka_unit_test(test_fim_file_no_attributes),
        cmocka_unit_test_setup(test_fim_file_error_on_insert, setup_fim_entry),

        /* fim_scan */
        cmocka_unit_test_setup_teardown(test_fim_scan_db_full_double_scan, setup_fim_double_scan, teardown_fim_double_scan),
        cmocka_unit_test_setup_teardown(test_fim_scan_db_full_not_double_scan, setup_fim_not_double_scan, teardown_fim_not_double_scan),
        cmocka_unit_test(test_fim_scan_db_free),
        cmocka_unit_test_setup_teardown(test_fim_scan_no_limit, setup_file_limit, teardown_file_limit),

        /* fim_check_db_state */
        cmocka_unit_test(test_fim_check_db_state_normal_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_empty),
        cmocka_unit_test(test_fim_check_db_state_empty_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_normal),
        cmocka_unit_test(test_fim_check_db_state_normal_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_full),
        cmocka_unit_test(test_fim_check_db_state_full_to_90_percentage),
        cmocka_unit_test(test_fim_check_db_state_90_percentage_to_80_percentage),
        cmocka_unit_test(test_fim_check_db_state_80_percentage_to_normal),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_scan_no_realtime, setup_fim_scan_realtime, teardown_fim_scan_realtime),
        cmocka_unit_test_setup_teardown(test_fim_scan_realtime_enabled, setup_fim_scan_realtime, teardown_fim_scan_realtime),
#endif

        /* fim_checker */
        cmocka_unit_test(test_fim_checker_scheduled_configuration_directory_error),
        cmocka_unit_test(test_fim_checker_not_scheduled_configuration_directory_error),
        cmocka_unit_test(test_fim_checker_invalid_fim_mode),
        cmocka_unit_test(test_fim_checker_over_max_recursion_level),
        cmocka_unit_test(test_fim_checker_deleted_file),
        cmocka_unit_test_setup(test_fim_checker_deleted_file_enoent, setup_fim_entry),
#ifndef TEST_WINAGENT
        cmocka_unit_test(test_fim_checker_no_file_system),
#endif
        cmocka_unit_test(test_fim_checker_fim_regular),
        cmocka_unit_test(test_fim_checker_fim_regular_warning),
        cmocka_unit_test(test_fim_checker_fim_regular_ignore),
        cmocka_unit_test(test_fim_checker_fim_regular_restrict),
        cmocka_unit_test_setup_teardown(test_fim_checker_fim_directory, setup_struct_dirent, teardown_struct_dirent),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_fim_checker_fim_directory_on_max_recursion_level, setup_struct_dirent, teardown_struct_dirent),
#endif

        /* fim_directory */
        cmocka_unit_test_setup_teardown(test_fim_directory, setup_struct_dirent, teardown_struct_dirent),
        cmocka_unit_test_setup_teardown(test_fim_directory_ignore, setup_struct_dirent, teardown_struct_dirent),
        cmocka_unit_test(test_fim_directory_nodir),
        cmocka_unit_test(test_fim_directory_opendir_error),

        /* fim_get_data */
        cmocka_unit_test_teardown(test_fim_get_data, teardown_local_data),
        cmocka_unit_test_teardown(test_fim_get_data_no_hashes, teardown_local_data),
        cmocka_unit_test(test_fim_get_data_hash_error),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_fim_get_data_fail_to_get_file_premissions),
#endif

        /* check_deleted_files */
        cmocka_unit_test(test_check_deleted_files),
        cmocka_unit_test(test_check_deleted_files_error),

        /* free_inode */
        cmocka_unit_test(test_free_inode_data),
        cmocka_unit_test(test_free_inode_data_null),

        /* fim_realtime_event */
        cmocka_unit_test_setup_teardown(test_fim_realtime_event_file_exists, setup_fim_entry, teardown_fim_entry),
        cmocka_unit_test(test_fim_realtime_event_file_missing),

        /* fim_whodata_event */
        cmocka_unit_test(test_fim_whodata_event_file_exists),
        cmocka_unit_test(test_fim_whodata_event_file_missing),

        /* fim_process_missing_entry */
        cmocka_unit_test(test_fim_process_missing_entry_no_data),
        cmocka_unit_test(test_fim_process_missing_entry_failure),
        cmocka_unit_test_setup(test_fim_process_missing_entry_data_exists, setup_fim_entry),

        /* fim_diff_folder_size */
        cmocka_unit_test(test_fim_diff_folder_size),

#ifdef TEST_WINAGENT
        /* fim_registry_event */
        cmocka_unit_test(test_fim_registry_event_null_data),
        cmocka_unit_test_setup_teardown(test_fim_registry_event_invalid_add, setup_fim_entry, teardown_fim_entry),
        cmocka_unit_test_setup(test_fim_registry_event_invalid_modification, setup_fim_entry),
        cmocka_unit_test_setup(test_fim_registry_event_valid_add, setup_fim_entry),
        cmocka_unit_test_setup(test_fim_registry_event_valid_modification, setup_fim_entry),
        cmocka_unit_test_setup(test_fim_registry_event_already_scanned, setup_fim_entry),
#endif
    };
    const struct CMUnitTest root_monitor_tests[] = {
        cmocka_unit_test(test_fim_checker_root_ignore_file_under_recursion_level),
        cmocka_unit_test(test_fim_checker_root_file_within_recursion_level),
    };
    int retval;

    retval = cmocka_run_group_tests(tests, setup_group, teardown_group);
    retval += cmocka_run_group_tests(root_monitor_tests, setup_root_group, teardown_group);

    return retval;
}
