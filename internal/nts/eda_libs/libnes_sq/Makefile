#########################################################
# <COPYRIGHT_TAG>
#########################################################

include $(RTE_SDK)/mk/rte.vars.mk

RTE_OUTPUT = ../build

# binary name
LIB = libnes_sq.a

# all source are stored in SRCS-y
SRCS-y := libnes_sq.c

CFLAGS += -O3
#CFLAGS += -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)
CFLAGS += -I../libnes_api




CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extlib.mk
