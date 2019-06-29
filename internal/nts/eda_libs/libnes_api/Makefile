############################################################################
# Copyright 2019 Intel Corporation. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

CC = gcc

SRCS = libnes_api.c 

LIB = libedanes_api.a
OBJ = libnes_api.o

INC = -I../libnes_sq 
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


LDLIBS += -L$(DIR) -ledanes_api
