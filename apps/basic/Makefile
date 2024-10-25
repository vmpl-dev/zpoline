PROGS = libzphook_basic.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wno-error=address-of-packed-member
CFLAGS += -Wextra
CFLAGS += -shared -fPIC

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
