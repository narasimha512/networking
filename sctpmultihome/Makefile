 #
### Makefile for server
 #

STRIP = strip

SHELL= /bin/sh
#LIBS = -L /root/dia_ssl/dia_openssl-1.0.2c/lib -lssl -lcrypto
LIBS = -lssl -lcrypto /lib64/libsctp.so.1

# Use this when you want DEBUG info
CFLAGS = -D_REENTRANT -pipe -g -O2 -Wall -Dlint -funroll-loops -fomit-frame-pointer

all: sctpserver sctpclient

sctpserver.o: sctpserver.c
	$(CC) $(CFLAGS) -c sctpserver.c
sctpclient.o: sctpclient.c
	$(CC) $(CFLAGS) -c sctpclient.c

sctpserver: sctpserver.o
	$(CC) -o sctpserver $(LIBS) sctpserver.o
sctpclient: sctpclient.o
	$(CC) -o sctpclient $(LIBS) sctpclient.o

        #$(STRIP) sctpserver
	$(RM) -f *.o

install: all

clean:
	$(RM) -f *.o sctpserver sctpclient
