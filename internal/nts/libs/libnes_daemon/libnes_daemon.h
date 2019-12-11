/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_daemon.h
 * @brief Header file for libnes_daemon
 */

#ifndef _LIBNES_DAEMON_H_
#define _LIBNES_DAEMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#define DAEMON_WORKING_DIR "/usr/bin"
#define DAEMON_NAME "nes-daemon"
#define PID_FILE_PATH "/var/run/nes.pid"

/**
 * Daemonize application
 *
 * @return
 *   0 on success or -1 on error
*/
extern int daemonize(void);

/**
 * Daemon cleanup, close log and pidfile
 *
*/
extern void daemon_cleanup(void);

/**
 * Log to system log
 *
 * @param msg
 *   log message
 *
*/
extern void daemon_log(const char* msg);

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif // _LIBNES_DAEMON_H_
