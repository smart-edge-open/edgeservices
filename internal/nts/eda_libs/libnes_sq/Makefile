# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

CC = gcc

SRCS = libnes_sq.c

LIB = libedanes_sq.a
OBJ = libnes_sq.o

INC = -I../libnes_api
DIR = ../build

CFLAGS += -O3 -Wall -c
SEC_CFLAGS = -fstack-protector-strong -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
CFLAGS += $(SEC_CFLAGS)

$(LIB): $(DIR)/$(OBJ)
	ar -r -o $(DIR)/$@ $^

$(DIR)/%.o: %.c dirmake
	$(CC) -c $(INC) $(CFLAGS) -o $@ $<

dirmake:
	@mkdir -p $(DIR)

clean:
	rm -f $(DIR)/$(LIB) $(DIR)/$(OBJ)

LDLIBS += -L$(DIR) -ledanes_sq


