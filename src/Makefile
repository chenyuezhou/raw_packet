# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

OPT=-O2
WARN=-Wall -W -Wno-missing-field-initializers -Wno-format-truncation
CFLAGS=-I./lib
CC=cc $(OPT) $(WARN) $(CFLAGS)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

OBJ=raw_socket
COMMON_OBJ=\
		   raw_socket.o \
		   ip_packet.o \
		   tcp_packet.o \
		   lib/checksum.o \
		   #
#
.PHONY: all
all: $(OBJ)

%.o: %.c
	$(call msg,CC,$@)
	$(Q)$(CC) -c -o $@ $<

$(OBJ): $(COMMON_OBJ)
	$(call msg,TARGET,$@)
	$(Q)$(CC) $^ -o $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(COMMON_OBJ) $(OBJ)
