#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

set -euo pipefail

_SCRIPT_NAME=$(basename "${0}")

SAVE_FILE="/tmp/openness-biosfw-saved-settings.ini"
RESTORE_FILE="/biosfw-config/bios_to_restore.ini"
FILE_START="-------------- BIOSFW START --------------"
FILE_END="-------------- BIOSFW END --------------"
SYSCFG_ARGS_FILE="/biosfw-secret/syscfg-args"
ADMIN_PASS_FILE="/biosfw-secret/admin"

error() {
    >&2 echo -e "[ERROR] ${*}"
}

log() {
    echo -e "${*}"
}

usage() {
    local -r exit_code=${1}

    echo "Executes syscfg with given arguments."
    echo "Script is intended to be run in OpenNESS' BIOSFW pod."
    echo
    echo "Restore action depends on volume provided by Kubernetes' ConfigMap which is used to pass the file"
    echo "BIOS Admin Password depends on volume provided by Kubernetes' Secret which is used to pass the password"
    echo
    echo "Usage:"
    echo "    ${_SCRIPT_NAME} save"
    echo "    ${_SCRIPT_NAME} restore"
    echo "    ${_SCRIPT_NAME} direct"
    echo "    ${_SCRIPT_NAME} help"
    echo
    echo "Actions:"
    echo "    save                     Saves current settings to ${SAVE_FILE}"
    echo "    restore                  Restores setting from ${RESTORE_FILE}"
    echo "    direct                   Executes syscfg with arguments from ${SYSCFG_ARGS_FILE}"
    echo "    help                     Prints this message"
    echo

    exit "${exit_code}"
}

redact_passwords() {
    local remove_quotes='s/\"//g'
    local change_bap='s,bap [^/ ]* [^/ ]*,bap *** *** ,g'            # BIOS Admin Pass change
    local change_bup='s,bup [^/ ]* [^/ ]* [^/ ]*,bup *** *** *** ,g' # BIOS User Pass change
    local provide_bap='s,bap [^/ ]*,bap ***,g'                       # BIOS Admin Pass provide to run command

    local to_redact="${*}"
    echo "${to_redact}" | sed \
        -e "${remove_quotes}" \
        -e "${change_bap}" \
        -e "${change_bup}" \
        -e "${provide_bap}"
}

execute_command() {
    local output
    output=$(eval "$@" 2>&1)
    local result=$?
    if [ "${result}" -ne 0 ]; then
        error "Exiting - command failed: '${*}' because:\n\n${output}\n"
        exit 1
    fi
}

save() {
    log "Saving settings"
    rm -rf "${SAVE_FILE}"

    execute_command "syscfg /s \"${SAVE_FILE}\" /b /f /q"

    echo "${FILE_START}"
    cat "${SAVE_FILE}"
    echo "${FILE_END}"

    exit 0
}

restore() {
    if [[ ! -f "${ADMIN_PASS_FILE}" ]]; then
        error "File ('${ADMIN_PASS_FILE}') with arguments is missing"
        exit 1
    fi

    local admin_password
    admin_password=$(cat "${ADMIN_PASS_FILE}")

    log "Restoring settings"

    log "Config to restore:"
    cat "${RESTORE_FILE}"
    echo -e "\n\n"

    local cmd="syscfg /r \"${RESTORE_FILE}\" /b /f"
    if [ -n "${admin_password}" ]; then
        cmd="${cmd} /bap ${admin_password}"
    fi

    echo "Command to be executed: $(redact_passwords "${cmd}")"
    eval "${cmd}"
}

direct() {
    if [[ ! -f "${SYSCFG_ARGS_FILE}" ]]; then
        error "File ('${SYSCFG_ARGS_FILE}') with arguments is missing"
        exit 1
    fi

    local syscfg_args
    syscfg_args=$(cat "${SYSCFG_ARGS_FILE}")

    log "Executing syscfg with arguments: $(redact_passwords "${syscfg_args}")"
    eval syscfg "${syscfg_args}"
}

# Check preconditions
if ! command -v syscfg >/dev/null; then
    error "syscfg is missing"
    exit 1
fi

action=${1:-}
if [[ -z "${action}" ]]; then
    echo "Command is required: { save | restore | direct | help }"
    exit 1
fi

if [ "${action}" == "save" ]; then
    save
elif [ "${action}" == "restore" ]; then 
    restore
elif [ "${action}" == "direct" ]; then 
    direct
elif [ "${action}" == "help" ]; then 
    usage 0
else
    error "Unrecognized action: ${action}"
    usage 1
fi
