/*
 * Wazuh Module for System inventory
 * Copyright (C) 2015-2020, Wazuh Inc.
 * March 9, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollector.h"
#include <errno.h>

static wm_sys_t *sys;                           // Pointer to configuration

static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
static void wm_sys_destroy(wm_sys_t *sys);      // Destroy data
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON *wm_sys_dump(const wm_sys_t *sys);

// Syscollector module context definition

const wm_context WM_SYS_CONTEXT = {
    "syscollector",
    (wm_routine)wm_sys_main,
    (wm_routine)(void *)wm_sys_destroy,
    (cJSON * (*)(const void *))wm_sys_dump
};

#ifndef WIN32
int queue_fd;                                   // Output queue file descriptor
#endif

static void wm_sys_setup(wm_sys_t *_sys);       // Setup module
static void wm_sys_check();                     // Check configuration, disable flag
#ifndef WIN32
static void wm_sys_cleanup();                   // Cleanup function, doesn't overwrite wm_cleanup
#endif

// Module main function. It won't return

void* wm_sys_main(wm_sys_t *sys) {

    time_t time_start = 0;
    time_t time_sleep = 0;

    // Check configuration and show debug information

    wm_sys_setup(sys);
    mtinfo(WM_SYS_LOGTAG, "Module started.");

    // First sleeping

    if (!sys->flags.scan_on_start) {
        time_start = time(NULL);

        // On first run, take into account the interval of time specified
        if (sys->state.next_time == 0) {
            sys->state.next_time = time_start + sys->interval;
        }

        if (sys->state.next_time > time_start) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            w_time_delay(1000 * (sys->state.next_time - time_start));
        }
    } else {
        // Wait for Wazuh DB start
        w_time_delay(1000);
    }

    // Main loop

    while (1) {

        mtinfo(WM_SYS_LOGTAG, "Starting evaluation.");

        // Get time and execute
        time_start = time(NULL);

        /* Network inventory */
        if (sys->flags.netinfo){
            #ifdef WIN32
                sys_network_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_network_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                sys_network_bsd(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.netinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Network inventory is not available for this OS version.");
            #endif
        }

        /* Operating System inventory */
        if (sys->flags.osinfo){
            #ifdef WIN32
                sys_os_windows(WM_SYS_LOCATION);
            #else
                sys_os_unix(queue_fd, WM_SYS_LOCATION);
            #endif
        }

        /* Hardware inventory */
        if (sys->flags.hwinfo){
            #if defined(WIN32)
                sys_hw_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_hw_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__MACH__)
                sys_hw_bsd(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.hwinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Hardware inventory is not available for this OS version.");
            #endif
        }

        /* Installed programs inventory */
        if (sys->flags.programinfo){
            #if defined(WIN32)
                sys_programs_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_packages_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__FreeBSD__) || defined(__MACH__)
                sys_packages_bsd(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.programinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Packages inventory is not available for this OS version.");
            #endif
        }

        /* Installed hotfixes inventory */
        if (sys->flags.hotfixinfo) {
            #ifdef WIN32
                sys_hotfixes(WM_SYS_LOCATION);
            #endif
        }
        /* Opened ports inventory */
        if (sys->flags.portsinfo){
            #if defined(WIN32)
                sys_ports_windows(WM_SYS_LOCATION, sys->flags.allports);
            #elif defined(__linux__)
                sys_ports_linux(queue_fd, WM_SYS_LOCATION, sys->flags.allports);
            #elif defined(__MACH__)
                sys_ports_mac(queue_fd, WM_SYS_LOCATION, sys->flags.allports);
            #else
                sys->flags.portsinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Opened ports inventory is not available for this OS version.");
            #endif
        }

        /* Running processes inventory */
        if (sys->flags.procinfo){
            #if defined(__linux__)
                sys_proc_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(WIN32)
                sys_proc_windows(WM_SYS_LOCATION);
            #elif defined(__MACH__)
                sys_proc_mac(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.procinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Running processes inventory is not available for this OS version.");
            #endif
        }

        time_sleep = time(NULL) - time_start;

        mtinfo(WM_SYS_LOGTAG, "Evaluation finished.");

        if ((time_t)sys->interval >= time_sleep) {
            time_sleep = sys->interval - time_sleep;
            sys->state.next_time = sys->interval + time_start;
        } else {
            mterror(WM_SYS_LOGTAG, "Interval overtaken.");
            time_sleep = sys->state.next_time = 0;
        }

        if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_WRITE, &sys->state, sizeof(sys->state)) < 0)
            mterror(WM_SYS_LOGTAG, "Couldn't save running state: %s (%d)", strerror(errno), errno);

        // If time_sleep=0, yield CPU
        w_time_delay(1000 * time_sleep);
    }

    return NULL;
}

// Setup module

static void wm_sys_setup(wm_sys_t *_sys) {

    sys = _sys;
    wm_sys_check();

    // Read running state

    if (wm_state_io(WM_SYS_CONTEXT.name, WM_IO_READ, &sys->state, sizeof(sys->state)) < 0)
        memset(&sys->state, 0, sizeof(sys->state));

    #ifndef WIN32

    // Connect to socket
    queue_fd = StartMQ(DEFAULTQPATH, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting
    atexit(wm_sys_cleanup);

    #endif
}

#ifndef WIN32
void wm_sys_cleanup() {
    close(queue_fd);
    mtinfo(WM_SYS_LOGTAG, "Module finished.");
}
#endif

// Check configuration

void wm_sys_check() {

    // Check if disabled

    if (!sys->flags.enabled) {
        mtinfo(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if evals

    if (!sys->flags.netinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Network scan disabled.");
    }

    if (!sys->flags.osinfo) {
        mtdebug1(WM_SYS_LOGTAG, "OS scan disabled.");
    }

    if (!sys->flags.hwinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Hardware scan disabled.");
    }

    if (!sys->flags.procinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Running processes inventory disabled.");
    }

    if (!sys->flags.programinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Installed programs scan disabled.");
    }

    if (!sys->flags.portsinfo) {
        mtdebug1(WM_SYS_LOGTAG, "Opened ports scan disabled.");
    }

    // Check if interval

    if (!sys->interval)
        sys->interval = WM_SYS_DEF_INTERVAL;
}


// Get read data

cJSON *wm_sys_dump(const wm_sys_t *sys) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_sys = cJSON_CreateObject();

    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sys,"disabled","no"); else cJSON_AddStringToObject(wm_sys,"disabled","yes");
    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sys,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_sys,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_sys,"interval",sys->interval);
    if (sys->flags.netinfo) cJSON_AddStringToObject(wm_sys,"network","yes"); else cJSON_AddStringToObject(wm_sys,"network","no");
    if (sys->flags.osinfo) cJSON_AddStringToObject(wm_sys,"os","yes"); else cJSON_AddStringToObject(wm_sys,"os","no");
    if (sys->flags.hwinfo) cJSON_AddStringToObject(wm_sys,"hardware","yes"); else cJSON_AddStringToObject(wm_sys,"hardware","no");
    if (sys->flags.programinfo) cJSON_AddStringToObject(wm_sys,"packages","yes"); else cJSON_AddStringToObject(wm_sys,"packages","no");
    if (sys->flags.portsinfo) cJSON_AddStringToObject(wm_sys,"ports","yes"); else cJSON_AddStringToObject(wm_sys,"ports","no");
    if (sys->flags.allports) cJSON_AddStringToObject(wm_sys,"ports_all","yes"); else cJSON_AddStringToObject(wm_sys,"ports_all","no");
    if (sys->flags.procinfo) cJSON_AddStringToObject(wm_sys,"processes","yes"); else cJSON_AddStringToObject(wm_sys,"processes","no");
#ifdef WIN32
    if (sys->flags.hotfixinfo) cJSON_AddStringToObject(wm_sys,"hotfixes","yes"); else cJSON_AddStringToObject(wm_sys,"hotfixes","no");
#endif

    cJSON_AddItemToObject(root,"syscollector",wm_sys);

    return root;
}

// Initialize hw_info structure

void init_hw_info(hw_info *info) {
    if(info != NULL) {
        info->cpu_name = NULL;
        info->cpu_cores = 0;
        info->cpu_MHz = 0.0;
        info->ram_total = 0;
        info->ram_free = 0;
        info->ram_usage = 0;
    }
}

void wm_sys_destroy(wm_sys_t *sys) {
    free(sys);
}

int wm_sys_get_random_id() {
    int ID;
    char random_id[SERIAL_LENGTH];

    snprintf(random_id, SERIAL_LENGTH - 1, "%u%u", os_random(), os_random());
    ID = atoi(random_id);

    if (ID < 0) {
        ID = -ID;
    }

    return ID;
}
