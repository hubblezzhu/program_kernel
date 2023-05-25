
RM ?= rm

CLANG ?= clang
LLC ?= llc
CC ?= gcc

LIBBPF_INCLUDE = /usr/include/bpf/


CLANG_FLAGS += -O2 -emit-llvm -c
LLC_FLAGS += -march=bpf -filetype=obj -o

CFLAGS += -Wall -O2
CFLAGS += -I$(LIBBPF_INCLUDE)

USER_SRC_FILE=ebpf_sysctl_user.c

KERN_SRC_FILE=ebpf_sysctl.c

.PHONY
user_prog:


.PHONY
kern_prog:


all: kern_prog user_prog


clean:
	$(RM) -f $(SRC_FILE)