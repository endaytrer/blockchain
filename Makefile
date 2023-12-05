CC := gcc
CCLD := gcc
DEPS := openssl
LIBS := $(shell pkg-config --libs $(DEPS))
CFLAGS := -std=gnu11 -Wall -Wextra -pedantic -fPIC -g -O0
CFLAGS += $(shell pkg-config --cflags $(DEPS))

C_SRCS := $(wildcard *.c)
C_HDRS := $(wildcard *.h)
C_OBJS := $(patsubst %.c, %.o, $(C_SRCS)) 

DYLIB := libblockchain.so

.PHONY: all clean

all: $(DYLIB)

$(DYLIB): $(C_OBJS)
	$(CCLD) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

%.o: %.c $(C_HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(DYLIB)