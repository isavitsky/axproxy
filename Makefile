CC=cc
LD=cc

CFLAGS=
LDFLAGS=-lax25

OBJ=axproxy.o

all: axproxy

%.o: %.c
		$(CC) $(CFLAGS) -c -o $@ $<

axproxy: axproxy.o $(OBJ)
	$(LD) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o axproxy

