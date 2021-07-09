OBJS =
OBJS += main.o

DEF =
DEF += -O3
DEF += --std=c99
DEF += -D_LARGEFILE64_SOURCE
DEF += -D_GNU_SOURCE
DEF += -g

LIBS =

%.o: %.c
	gcc $(DEF) -c -o $@ -g $<

all: $(OBJS)
	gcc -g -o pcap2erf $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) pcap2erf
