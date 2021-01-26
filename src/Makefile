LIBS=
CPP=g++
CC=gcc

COFLAGS=-O2
CWFLAGS=-Wall
CIFLAGS=-I. -I../common
#Uncomment this if you want more debug messages
#CMFLAGS=-DDEBUG 
CMFLAGS= -std=c++11 
LIBS=-lssl -lcrypto -lpthread

CFLAGS= $(CWFLAGS) $(COFLAGS) $(CIFLAGS) $(CMFLAGS) -fPIC

all: SSL-Client SSL-Server

SSL-Client.o: SSL-Client.c
	$(CC) $(CFLAGS) -c SSL-Client.c

SSL-Server.o: SSL-Server.c
	$(CC) $(CFLAGS) -c SSL-Server.c

SSL-Client: SSL-Client.o
	$(CPP) -o SSL-Client SSL-Client.o $(LIBS)
	$(RM) *.o

SSL-Server: SSL-Server.o 
	$(CPP) -o SSL-Server SSL-Server.o $(LIBS)
	$(RM) *.o

install: compile

clean:
	$(RM) -f *.o SSL-Client SSL-Server
		
distclean: clean
