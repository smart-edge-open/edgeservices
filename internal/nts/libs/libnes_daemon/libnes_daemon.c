/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_daemon.c
 * @brief Implementation of nes library for application daemonization
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>

#include "libnes_daemon.h"

static int pid_file;

#define PID_STR_LEN 10

static int
open_pid_file(void)
{
	char pid_str[PID_STR_LEN];
	pid_file = open(PID_FILE_PATH, O_RDWR|O_CREAT, 0600);
	if (pid_file == -1) {
		daemon_log("Unable to open PID file");
		return -1;
	}

	if (lockf(pid_file, F_TLOCK, 0) == -1) {
		daemon_log("Unable to lock PID file");
		return -1;
	}

	snprintf(pid_str,PID_STR_LEN, "%d\n", getpid());
	if (0 > write(pid_file, pid_str, strlen(pid_str))) {
		daemon_log("Failed writing to PID file");
		return -1;
	}
	return 0;
}

int
daemonize(void)
{
	pid_t fpid;
	int dev_null_file;

	openlog(DAEMON_NAME, LOG_PID, LOG_DAEMON);
	fpid = fork();
	if (fpid < 0) {
		daemon_log("Unable to fork first process");
		return -1;
	}
	if (fpid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0) {
		daemon_log("Unable to set session id");
		return -1;
	}

	fpid = fork();
	if (fpid < 0) {
		daemon_log("Unable to fork second process");
		return -1;
	}

	if (fpid > 0)
		exit(EXIT_SUCCESS);

	umask(0);
	if (chdir(DAEMON_WORKING_DIR) < 0) {
		daemon_log("Unable to change directory to "DAEMON_WORKING_DIR);
		return -1;
	}

	dev_null_file = open("/dev/null", O_RDWR);
	if (dev_null_file == -1)  {
		daemon_log("Unable to open /dev/null for stream redirection");
		return -1;
	}

	dup2(dev_null_file, STDIN_FILENO);
	dup2(dev_null_file, STDOUT_FILENO);
	dup2(dev_null_file, STDERR_FILENO);
	close(dev_null_file);

	return open_pid_file();
}

void
daemon_log(const char* msg)
{
	syslog(LOG_INFO, "%s", msg);
}

void
daemon_cleanup(void)
{
	close(pid_file);
	closelog();
}
