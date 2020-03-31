#!/usr/bin/python3
# coding: utf-8

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

import docker
import argparse
import logging
import subprocess
import os
import configparser
import ctypes
import signal
import sys
import time
import traceback
import re

NES_SUCCESS=0
NES_FAIL=1
KNI_NAMESIZE=32
_HOST_NS = "/var/run/docker/netns/default"
_HOST_NS_MNT = "/var/host_ns/mnt"

_LOG = None

def signal_handler(sig, frame):
    _LOG.info("Quiting")
    sys.exit(0)

class NesContext(object):
    def __init__(self, lib, cfg_path):
        self.lib = lib
        self.cfg_path = cfg_path
        self.conn = None
        self.conn_ptr = None

class nes_remote_t(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("socket_fd", ctypes.c_int),
                ("state", ctypes.c_int),
                ("ip_address", ctypes.c_char_p),
                ("port_nr", ctypes.c_ushort),
                ("on_connection_closed", ctypes.c_void_p),
                ("on_error", ctypes.c_void_p)]

def make_parser():
    log_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    levels_str = "{0:s} or {1:s}".format(", ".join(log_levels[:-1]), log_levels[-1])

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-v", "--verbosity", action="store", metavar="LEVEL", dest="verbosity", default="INFO",
        choices=log_levels,
        help="Application diagnostic output verbosity ({0:s})".format(levels_str))
    parser.add_argument(
        "-c", "--config", action="store", metavar="CONFIG_PATH", dest="nes_cfg_path",
        default="nes.cfg",
        help="NEV SDK config file path")
    parser.add_argument(
        "-f", "--filter", action="store", metavar="NAME_FILTER", dest="name_filter",
        default="mec-app",
        help="Only add KNI interfaces to a POD which name starts with name_filter")
    parser.add_argument(
        "-l", "--library", action="store", metavar="LIB_PATH", dest="nes_api_lib_path",
        default="../build/libnes_api_shared.so",
        help="nes_api shared library file path")
    parser.add_argument(
        "-p", "--log-path", action="store", metavar="LOG_PATH", dest="log_path",
        default="/var/log/nes_kni.log",
        help="Log file path")

    return parser

def setup_logger(options):
    log_fmt = "KNI DAEMON: [%(levelname)s] %(module)s(%(lineno)d): %(message)s"
    ts_fmt = "%Y-%m-%dT%H:%M:%S"

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(log_fmt, ts_fmt))
    root_logger = logging.getLogger('')
    root_logger.addHandler(handler)
    root_logger.setLevel(options.verbosity)
    return root_logger

def nes_disconnect(nes_context):
    try:
        return NES_SUCCESS == nes_context.lib.nes_conn_close(nes_context.conn_ptr)
    except Exception as e:
        _LOG.critical("nes_api library error\n {}".format(e))
        return False
    return True

def nes_lib_load(nes_api_lib_path, nes_cfg_path):
    if not os.path.isfile(nes_api_lib_path):
        _LOG.critical("nes_api shared library file {} does not exist".format(nes_api_lib_path))
        return None

    if not os.path.isfile(nes_cfg_path):
        _LOG.critical("NES config file {} does not exist".format(nes_cfg_path))
        return None

    try:
        nes_context = NesContext(ctypes.CDLL(nes_api_lib_path), nes_cfg_path)
    except Exception as e:
        _LOG.critical("nes_api library error\n {}".format(e))
        return None
    return nes_context


def nes_connect(nes_context):
    unix_sock_path = ctypes.c_char_p()

    if not os.path.isfile(nes_context.cfg_path):
        _LOG.critical("NES config file {} does not exist".format(nes_context.cfg_path))
        return False

    # Use ConfigParser with `strict` disabled as nes config file
    # might contain duplicated keys(route) that are not used here
    config = configparser.ConfigParser(strict = False)
    config.read(nes_context.cfg_path)
    try:
        unix_sock_path.value = config['NES_SERVER']['ctrl_socket'].encode('utf-8')
        _LOG.debug("nes_api unix socket path: {}".format(unix_sock_path.value))
    except KeyError as e:
        _LOG.critical("Failed to get unix socket path\n {}".format(e))
        return False

    nes_context.conn = nes_remote_t()
    nes_context.conn_ptr = ctypes.pointer(nes_context.conn)
    try:
        return NES_SUCCESS == nes_context.lib.nes_conn_start(nes_context.conn_ptr, unix_sock_path)
    except Exception as e:
        _LOG.critical("nes_api library error\n {}".format(e))
        return False
    return True

def docker_connect():
    docker_cli = docker.from_env()
    try:
        docker_cli.ping()
    except docker.errors.APIError as e:
        _LOG.critical("Failed to connect to docker server\n {}".format(e))
        return None
    return docker_cli

def modify_kni_interface(nes_context, dev_id, delete_if):
    ret = NES_FAIL

    if not nes_connect(nes_context):
        _LOG.info("Failed to connect do nes server")
        return (ret, "")

    try:
        created_if_name = ctypes.create_string_buffer(KNI_NAMESIZE)
        dev_id_name = ctypes.create_string_buffer(dev_id.encode('utf-8'))
    except TypeError as e:
        _LOG.critical("ctypes create_string_buffer error\n {}".format(e))
        return (ret, "")

    try:
        if (delete_if):
            ret = nes_context.lib.nes_kni_del(nes_context.conn_ptr, dev_id_name, created_if_name)
        else:
            ret = nes_context.lib.nes_kni_add(nes_context.conn_ptr, dev_id_name, created_if_name)
    except Exception as e:
        _LOG.critical("nes_api library error\n {}".format(e))

    if not nes_disconnect(nes_context):
        _LOG.info("Failed to disconnect from nes server")

    return (ret, created_if_name.value.decode("utf-8") )

def add_kni_interface(nes_context, dev_id):
    ret, if_name = modify_kni_interface(nes_context, dev_id, False)
    if NES_SUCCESS != ret:
        _LOG.error("Failed to create the KNI inteface for {}".format(dev_id))

    _LOG.debug("Created KNI inteface {} for {}".format(if_name, dev_id))
    return if_name

def del_kni_interface(nes_context, dev_id):
    ret, if_name = modify_kni_interface(nes_context, dev_id, True)
    if NES_SUCCESS != ret:
        _LOG.error("Failed to remove the KNI inteface for {}".format(dev_id))
    else:
        _LOG.debug("Removed KNI inteface {} for {}".format(if_name, dev_id))

    return if_name

def run_command(command, expected_output):
    try:
        ret = subprocess.check_output(command).decode("utf-8")
    except subprocess.CalledProcessError as e:
        _LOG.error("\"{}\" failed[{}]: {}".format(' '.join(e.cmd), e.returncode, e.output))
        return False
    return expected_output in ret

def move_if(dst_ip_ns_path, if_name):
    command_prefix = ["ip",
                      "link",
                      "set",
                      if_name,
                      "netns"]

    move_to_host = command_prefix + [_HOST_NS]

    move_to_dst =  ["nsenter",
                    "--mount=" + _HOST_NS_MNT,
                    "--net=" + _HOST_NS] + \
                    command_prefix + \
                    [dst_ip_ns_path]

    if not run_command(move_to_host, ""):
        _LOG.error("Failed to move {} to the default namespace".format(if_name))
        return False
    if not run_command(move_to_dst, ""):
        _LOG.error("Failed to move {} to {} namespace".format(if_name, dst_ip_ns_path))
        return False
    return True

def docker_create_if(nes_context, docker_cli, pod_id, ip_ns_path):
    created_if = add_kni_interface(nes_context, pod_id)
    if not created_if:
        _LOG.error("Failed to create an interface from {}, namespace[{}]".format(pod_id, ip_ns_path))
        return False
    if not move_if(ip_ns_path, created_if):
        _LOG.error("Failed to move {} to {} namespace".format(created_if, ip_ns_path))
        return False
    _LOG.info("{} attached to {}, namespace[{}]".format(created_if, pod_id, ip_ns_path))
    return True

def docker_delete_if(nes_context, docker_cli, pod_id, ip_ns_path):
    removed_if = del_kni_interface(nes_context, pod_id)
    if not removed_if:
        _LOG.error("Failed to remove an interface for {}, namespace[{}]".format(pod_id, ip_ns_path))
        return False
    _LOG.info("{} removed from {}, namespace[{}]".format(removed_if, pod_id, ip_ns_path))
    return True

def filter_name(pod_name, name_filter):
    ret = pod_name.startswith(name_filter)
    if not ret:
        _LOG.debug("{} name doesn't start with {}, not processing.".format(pod_name, name_filter))
    return ret

def check_if_uuid(uuid_string):
    regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    return bool(regex.match(uuid_string))

def docker_poll(nes_context, docker_cli, name_filter):
    events = docker_cli.events(decode=True)

    for event in events:
        try:
            if event['Type'] == 'container':

                if 'io.kubernetes.docker.type' in event['Actor']['Attributes']:
                    if event['Actor']['Attributes']['io.kubernetes.docker.type'] != 'container':
                        continue
                    sandbox_id = event['Actor']['Attributes']['io.kubernetes.sandbox.id']
                    pod_name = event['Actor']['Attributes']['io.kubernetes.pod.name']
                    if not filter_name(pod_name, "app"):
                        continue
                else:
                    sandbox_id = event['Actor']['ID']
                    pod_name = event['Actor']['Attributes']['name']
                    if not filter_name(pod_name, name_filter) and not check_if_uuid(pod_name):
                        continue

                sandbox = docker_cli.containers.get(sandbox_id)
                ip_ns_path = sandbox.attrs['NetworkSettings']['SandboxKey']

                if event['Action'] == 'start':
                    _LOG.debug("New container started {}".format(pod_name))
                    del_kni_interface(nes_context, sandbox_id) # clear if already exists
                    if not docker_create_if(nes_context, docker_cli, sandbox_id, ip_ns_path):
                        _LOG.error("Failed to attach the interface to {}".format(pod_name))

                elif event['Action'] == 'kill' and int(event['Actor']['Attributes']['signal']) == signal.SIGTERM:
                    _LOG.debug("{} container stopped".format(pod_name))
                    if not docker_delete_if(nes_context, docker_cli, sandbox_id, ip_ns_path):
                        _LOG.error("Failed to remove the interface from {}".format(pod_name))

        except Exception as e:
            _LOG.critical("Docker events error {}".format(e))
            _LOG.critical(traceback.format_exc())


def main(options):
    docker_cli = docker_connect()
    if not docker_cli:
        _LOG.info("Failed to connect do docker server")
        return 1

    signal.signal(signal.SIGINT, signal_handler)

    nes_context = nes_lib_load(options.nes_api_lib_path, options.nes_cfg_path)
    if not nes_context:
        _LOG.info("Failed to load nes_api library")
        return 2

    _LOG.info("[Started]")
    _LOG.info("Waiting for containers events")
    docker_poll(nes_context, docker_cli, options.name_filter)

if __name__ == '__main__':
    options = make_parser().parse_args()
    _LOG = setup_logger(options)
    sys.exit(main(options))
