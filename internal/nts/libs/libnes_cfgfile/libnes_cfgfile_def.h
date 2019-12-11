/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef LIBNES_CFGFILE_DEF_H
#define LIBNES_CFGFILE_DEF_H

#include <rte_cfgfile.h>

struct rte_cfgfile_section {
        char name[CFG_NAME_LEN];
        int num_entries;
        int allocated_entries;
        struct rte_cfgfile_entry *entries;
};

struct rte_cfgfile {
        int flags;
        int num_sections;
        int allocated_sections;
        struct rte_cfgfile_section *sections;
};

#endif /* LIBNES_CFGFILE_DEF_H */

