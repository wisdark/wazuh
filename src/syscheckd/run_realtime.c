/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "string_op.h"
#include "shared.h"
#include "syscheck.h"

volatile int audit_thread_active;
volatile int whodata_alerts;
volatile int audit_db_consistency_flag;

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>
#endif

#include "fs_op.h"
#include "hash_op.h"
#include "debug_op.h"
#include "syscheck.h"
#include "syscheck_op.h"

static pthread_mutex_t adddir_mutex;

/* Checksum of the realtime file being monitored */
int realtime_checksumfile(const char *file_name, whodata_evt *evt)
{
    char *buf;
    char *path;
    syscheck_node *s_node;
    int pos;
    char file_link[PATH_MAX + 1] = {'\0'};

    // To obtain path without symbolic links

#ifndef WIN32
    os_calloc(PATH_MAX + 1, sizeof(char), path);

    if (realpath(file_name, path) == NULL) {
        snprintf(path, PATH_MAX, "%s", file_name);
    }
#else
    os_strdup(file_name, path);
#endif

    /* New file */
#ifdef WIN_WHODATA
    if (evt) {
        pos = evt->dir_position;
    } else {
#endif
        if (pos = find_dir_pos(path, 1, 0, evt ? CHECK_WHODATA : CHECK_REALTIME), pos < 0) {
            goto end;
        }
#ifdef WIN_WHODATA
    }
#endif

    if (syscheck.converted_links[pos]) {
        replace_linked_path(file_name, pos, file_link);
    }

    if (s_node = (syscheck_node *) OSHash_Get_ex(syscheck.fp, path), s_node) {
        char c_sum[OS_SIZE_4096 + 1];
        size_t c_sum_size;

        buf = s_node->checksum;
        c_sum[0] = '\0';
        c_sum[OS_SIZE_4096] = '\0';

        // If it returns < 0, we've already alerted the deleted file
        if (c_read_file(path, *file_link ? file_link : NULL, buf, c_sum, pos, evt) < 0) {
            os_free(path);
            return (0);
        }

        c_sum_size = strlen(buf + SK_DB_NATTR);
        if (strncmp(c_sum, buf + SK_DB_NATTR, c_sum_size)) {
            char alert_msg[OS_MAXSTR + 1];
            char wd_sum[OS_SIZE_6144 + 1];

            // Extract the whodata sum here to not include it in the hash table
            if (extract_whodata_sum(evt, wd_sum, OS_SIZE_6144)) {
                merror(FIM_ERROR_WHODATA_SUM_MAX, path);
            }

            // Update database
            snprintf(alert_msg, sizeof(alert_msg), "%.*s%.*s", SK_DB_NATTR, buf, (int)strcspn_escaped(c_sum, ' '), c_sum);
            s_node->checksum = strdup(alert_msg);

            alert_msg[OS_MAXSTR] = '\0';
            char *fullalert = NULL;

            if (buf[SK_DB_REPORT_CHANG] == '+') {
                fullalert = seechanges_addfile(path);
                if (fullalert) {
                    snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s:%s: %s\n%s", c_sum, wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", *file_link ? file_link : "", file_name, fullalert);
                    free(fullalert);
                    fullalert = NULL;
                } else {
                    snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s:%s: %s", c_sum, wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", *file_link ? file_link : "", file_name);
                }
            } else {
                snprintf(alert_msg, OS_MAXSTR, "%s!%s:%s:%s: %s", c_sum, wd_sum, syscheck.tag[pos] ? syscheck.tag[pos] : "", *file_link ? file_link : "", file_name);
            }

            send_syscheck_msg(alert_msg);
            struct timeval timeout = {0, syscheck.rt_delay * 1000};
            select(0, NULL, NULL, NULL, &timeout);

            os_free(buf);
            os_free(path);

            return (1);
        } else {
            mdebug2(FIM_REALTIME_DISCARD_EVENT, path);
        }

        os_free(path);

        return (0);
    } else {
        if (pos >= 0) {
            if(IsFile(path) == 0){
                mdebug1(FIM_REALTIME_NEWPATH, path, syscheck.dir[pos]);
            }
            char *cparent = get_converted_link_path(pos);
            int diff = fim_find_child_depth(cparent ? cparent : syscheck.dir[pos], path);
            int depth = syscheck.recursion_level[pos] - diff + 1;

            free(cparent);
            if(check_path_type(path) == 2){
                depth = depth - 1;
            }
#ifndef WIN32
            struct stat statbuf;

            if (lstat(path, &statbuf) < 0) {
                mdebug2(FIM_STAT_FAILED, path);
            } else {
                if (S_ISLNK(statbuf.st_mode) && (syscheck.opts[pos] & CHECK_FOLLOW)) {
                    read_dir(path, NULL, pos, evt, depth, 1, '-');
                    os_free(path);
                    return 0;
                } else if (S_ISLNK(statbuf.st_mode) && !(syscheck.opts[pos] & CHECK_FOLLOW)) {
                    os_free(path);
                    return 0;
                }
            }
#endif
            read_dir(path, *file_link ? file_link : NULL, pos, evt, depth, 0, '-');
        }

    }

end:
    os_free(path);
    return (0);
}

/* Find container directory */
int find_dir_pos(const char *filename, char full_compare, char check_recursion, int check_find) {
    char buf[PATH_MAX + 1];
    int i;
    char *c;
    int retval = -1;
    char path_end = 0;
    int level = -1;
    char *cdir = NULL;

    if (full_compare) {
        snprintf(buf, PATH_MAX, "%s%c", filename, PATH_SEP);
    } else {
        snprintf(buf, PATH_MAX, "%s", filename);
    }

    if (check_recursion && check_path_type(buf) == 2) {
        level = 0;
    }

    while (c = strrchr(buf, PATH_SEP), c && c != buf && !path_end) {
        *c = '\0';
#ifdef WIN32
        // Convert C: to C:\ .
        if (c > buf && *(c - 1) == ':') {
            path_end = 1;
            *c = '\\';
            *(c + 1) = '\0';
        }
#endif

        for (i = 0; syscheck.dir[i]; i++) {
            free(cdir);
            cdir = get_converted_link_path(i);
            char *dir = cdir ? cdir : syscheck.dir[i];

            if (!strcmp(dir, buf)) {
                if (syscheck.recursion_level[i] < level) {
                    continue;
                }

                if (check_find && !(syscheck.opts[i] & check_find)) {
                    goto end;
                }
                retval = i;
                break;
            }
        }

        if (retval != -1) {
            // The directory has been found
            break;
        }

        level++;
    }

end:
    free(cdir);
    return retval;
}

#ifdef INOTIFY_ENABLED
#include <sys/inotify.h>

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

/* Start real time monitoring using inotify */
int realtime_start()
{
    minfo(FIM_REALTIME_STARTING);

    w_mutex_init(&adddir_mutex, NULL);

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if (syscheck.realtime == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    syscheck.realtime->fd = -1;

#ifdef INOTIFY_ENABLED
    syscheck.realtime->fd = inotify_init();
    if (syscheck.realtime->fd < 0) {
        merror(FIM_ERROR_INOTIFY_INITIALIZE);
        return (-1);
    }
#endif

    return (1);
}

/* Add a directory to real time checking */
int realtime_adddir(const char *dir, __attribute__((unused)) int whodata)
{
    if (whodata && audit_thread_active) {

        // Save dir into saved rules list
        w_mutex_lock(&audit_mutex);

        if(!W_Vector_insert_unique(audit_added_dirs, dir)){
            mdebug1(FIM_WHODATA_NEWDIRECTORY, dir);
        }

        w_mutex_unlock(&audit_mutex);

    } else {

        if (!syscheck.realtime) {
            realtime_start();
        }

        /* Check if it is ready to use */
        if (syscheck.realtime->fd < 0) {
            return (-1);
        } else {
            int wd = 0;

            if(syscheck.skip_nfs) {
                short is_nfs = IsNFS(dir);
                if( is_nfs == 1 ) {
                    merror(FIM_ERROR_NFS_INOTIFY, dir);
                	return(-1);
                }
                else {
                    mdebug2(FIM_SKIP_NFS, syscheck.skip_nfs, dir, is_nfs);
                }
            }

            wd = inotify_add_watch(syscheck.realtime->fd,
                                   dir,
                                   REALTIME_MONITOR_FLAGS);
            if (wd < 0) {
                merror(FIM_ERROR_INOTIFY_ADD_WATCH, dir, wd, errno);
            } else {
                char wdchar[32 + 1];
                wdchar[32] = '\0';
                snprintf(wdchar, 32, "%d", wd);

                /* Entry not present */
                if (!OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
                    char *ndir;

                    ndir = strdup(dir);
                    if (ndir == NULL) {
                        merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
                    }

                    if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, ndir)) {
                        merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
                    }
                    mdebug1(FIM_REALTIME_NEWDIRECTORY, ndir);
                }
            }
        }
    }

    return (1);
}

/* Process events in the real time queue */
int realtime_process()
{
    ssize_t len;
    size_t i = 0;
    char buf[REALTIME_EVENT_BUFFER + 1];
    struct inotify_event *event;

    buf[REALTIME_EVENT_BUFFER] = '\0';

    len = read(syscheck.realtime->fd, buf, REALTIME_EVENT_BUFFER);
    if (len < 0) {
        merror(FIM_ERROR_REALTIME_READ_BUFFER);
    } else if (len > 0) {
        while (i < (size_t) len) {
            event = (struct inotify_event *) (void *) &buf[i];

            if (event->len) {
                char wdchar[32 + 1];
                char final_name[MAX_LINE + 1];

                wdchar[32] = '\0';
                final_name[MAX_LINE] = '\0';

                snprintf(wdchar, 32, "%d", event->wd);

                snprintf(final_name, MAX_LINE, "%s/%s",
                         (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar),
                         event->name);

                /* Need a sleep here to avoid triggering on vim
                * (and finding the file removed)
                */

                struct timeval timeout = {0, syscheck.rt_delay * 1000};
                select(0, NULL, NULL, NULL, &timeout);

                realtime_checksumfile(final_name, NULL);
            }

            i += REALTIME_EVENT_SIZE + event->len;
        }
    }

    return (0);
}

int run_whodata_scan(void) {
    return 0;
}


#elif defined(WIN32)
typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    TCHAR buffer[65536];
} win32rtfim;

int realtime_win32read(win32rtfim *rtlocald);

void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap)
{
    int lcount;
    size_t offset = 0;
    char wdchar[260 + 1];
    char final_path[MAX_LINE + 1];
    win32rtfim *rtlocald;
    PFILE_NOTIFY_INFORMATION pinfo;
    TCHAR finalfile[MAX_PATH];

    if (dwBytes == 0) {
        mwarn(FIM_WARN_REALTIME_OVERFLOW);
    }

    if (dwerror != ERROR_SUCCESS) {
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwerror, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        merror(FIM_ERROR_REALTIME_WINDOWS_CALLBACK, messageBuffer, dwerror);
        LocalFree(messageBuffer);

        return;
    }

    /* Get hash to parse the data */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", (char*)overlap->Pointer);
    rtlocald = OSHash_Get(syscheck.realtime->dirtb, wdchar);
    if (rtlocald == NULL) {
        merror(FIM_ERROR_REALTIME_WINDOWS_CALLBACK_EMPTY);
        return;
    }

    if (dwBytes) {
        do {
            pinfo = (PFILE_NOTIFY_INFORMATION) &rtlocald->buffer[offset];
            offset += pinfo->NextEntryOffset;

            lcount = WideCharToMultiByte(CP_ACP, 0, pinfo->FileName,
                                         pinfo->FileNameLength / sizeof(WCHAR),
                                         finalfile, MAX_PATH - 1, NULL, NULL);
            finalfile[lcount] = TEXT('\0');

            final_path[MAX_LINE] = '\0';
            snprintf(final_path, MAX_LINE, "%s\\%s", rtlocald->dir, finalfile);

            /* Check the change */
            str_lowercase(final_path);
            realtime_checksumfile(final_path, NULL);
        } while (pinfo->NextEntryOffset != 0);
    }

    realtime_win32read(rtlocald);
    return;
}

void free_win32rtfim_data(win32rtfim *data) {
    if (!data) return;
    if (data->h != NULL && data->h != INVALID_HANDLE_VALUE) CloseHandle(data->h);
    if (data->overlap.Pointer) free(data->overlap.Pointer);
    if (data->dir) free(data->dir);
    free(data);
}

int realtime_start()
{
    minfo(FIM_REALTIME_STARTING);

    w_mutex_init(&adddir_mutex, NULL);

    os_calloc(1, sizeof(rtfim), syscheck.realtime);

    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }
    OSHash_SetFreeDataPointer(syscheck.realtime->dirtb, (void (*)(void *))free_win32rtfim_data);

    syscheck.realtime->fd = -1;
    syscheck.realtime->evt = CreateEvent(NULL, TRUE, FALSE, NULL);

    return (0);
}

int realtime_win32read(win32rtfim *rtlocald)
{
    int rc;

    rc = ReadDirectoryChangesW(rtlocald->h,
                               rtlocald->buffer,
                               sizeof(rtlocald->buffer) / sizeof(TCHAR),
                               TRUE,
                               FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE |
                               FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SECURITY,
                               0,
                               &rtlocald->overlap,
                               RTCallBack);
    if (rc == 0) {
        merror(FIM_ERROR_REALTIME_DIRECTORYCHANGES, rtlocald->dir);
        sleep(2);
    }

    return (0);
}

// In Windows the whodata parameter contains the directory position + 1 to be able to reference it
int realtime_adddir(const char *dir, int whodata)
{
    char wdchar[260 + 1];
    win32rtfim *rtlocald;

    if (whodata) {
#ifdef WIN_WHODATA
        int type;

        if (!syscheck.wdata.fd && whodata_audit_start()) {
            merror_exit(FIM_CRITICAL_ERROR_HASH_CREATE, "realtime_adddir()", strerror(errno));
        }

        // This parameter is used to indicate if the file is going to be monitored in Whodata mode,
        // regardless of it was checked in the initial configuration (CHECK_WHODATA in opts)
        syscheck.wdata.dirs_status[whodata - 1].status |= WD_CHECK_WHODATA;
        syscheck.wdata.dirs_status[whodata - 1].status &= ~WD_CHECK_REALTIME;

        // Check if the file or directory exists
        if (type = check_path_type(dir), type == 2) {
            syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_DIR_TYPE;
            syscheck.wdata.dirs_status[whodata - 1].status |= WD_STATUS_EXISTS;
        } else if (type == 1) {
            syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_FILE_TYPE;
            syscheck.wdata.dirs_status[whodata - 1].status |= WD_STATUS_EXISTS;
        } else {
            mwarn(FIM_WARN_REALTIME_OPENFAIL, dir);
            syscheck.wdata.dirs_status[whodata - 1].object_type = WD_STATUS_UNK_TYPE;
            syscheck.wdata.dirs_status[whodata - 1].status &= ~WD_STATUS_EXISTS;
            return 0;
        }

        GetSystemTime(&syscheck.wdata.dirs_status[whodata - 1].last_check);
        if (set_winsacl(dir, whodata - 1)) {
            merror(FIM_ERROR_WHODATA_ADD_DIRECTORY, dir);
            return 0;
        }
        return 1;
#endif
    }

    if (!syscheck.realtime) {
        realtime_start();
    }

    w_mutex_lock(&adddir_mutex);

    /* Maximum limit for realtime on Windows */
    if (syscheck.realtime->fd > syscheck.max_fd_win_rt) {
        merror(FIM_ERROR_REALTIME_MAXNUM_WATCHES, dir);
        w_mutex_unlock(&adddir_mutex);
        return (0);
    }

    /* Set key for hash */
    wdchar[260] = '\0';
    snprintf(wdchar, 260, "%s", dir);
    if(OSHash_Get_ex(syscheck.realtime->dirtb, wdchar)) {
        mdebug2(FIM_REALTIME_HASH_DUP, wdchar);
        w_mutex_unlock(&adddir_mutex);
    }
    else {
        os_calloc(1, sizeof(win32rtfim), rtlocald);

        rtlocald->h = CreateFile(dir,
                                FILE_LIST_DIRECTORY,
                                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                NULL);


        if (rtlocald->h == INVALID_HANDLE_VALUE || rtlocald->h == NULL) {
            free(rtlocald);
            rtlocald = NULL;
            merror(FIM_ERROR_REALTIME_ADD, dir);
            w_mutex_unlock(&adddir_mutex);
            return (0);
        }
        syscheck.realtime->fd++;
        w_mutex_unlock(&adddir_mutex);

        /* Add final elements to the hash */
        os_strdup(dir, rtlocald->dir);
        os_strdup(dir, rtlocald->overlap.Pointer);
        if (!OSHash_Add_ex(syscheck.realtime->dirtb, wdchar, rtlocald)) {
            merror_exit(FIM_CRITICAL_ERROR_OUT_MEM);
        }
        /* Add directory to be monitored */
        realtime_win32read(rtlocald);
    }

    return (1);
}

#else /* !WIN32 */

int run_whodata_scan() {
    return 0;
}

int realtime_start()
{
    merror(FIM_ERROR_REALTIME_INITIALIZE);

    return (0);
}

int realtime_adddir(__attribute__((unused)) const char *dir, __attribute__((unused))int whodata)
{
    return (0);
}

int realtime_process()
{
    return (0);
}

#endif /* WIN32 */
