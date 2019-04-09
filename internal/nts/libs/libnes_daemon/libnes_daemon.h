/*******************************************************************************
* Copyright 2019 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/


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
