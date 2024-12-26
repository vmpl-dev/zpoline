PROGS = libzpoline.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g -rdynamic
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -shared -fPIC
CFLAGS += -Wno-error=address-of-packed-member
# CFLAGS += -DSUPPLEMENTAL__REWRITTEN_ADDR_CHECK

LD_VERSION = $(shell ld --version | head -1 | grep -oP '[\d\.]+' | sed 's/\.//' | sed 's/\..*//' | head -1 )
# differentiate the code according to the library version
ifeq ($(shell test $(LD_VERSION) -ge 239; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_239
else ifeq ($(shell test $(LD_VERSION) -ge 238; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_238
else ifeq ($(shell test $(LD_VERSION) -ge 229; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_229
endif

LDFLAGS += -lopcodes -ldl

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install:
	install -d $(DESTDIR)/usr/lib
	install -m 0755 $(PROGS) $(DESTDIR)/usr/lib

uninstall:
	rm -f $(DESTDIR)/usr/lib/$(PROGS)

clean:
	-@rm -rf $(CLEANFILES)
