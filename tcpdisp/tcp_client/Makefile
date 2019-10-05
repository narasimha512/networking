LIBS=
CPP=g++
CC=gcc

COFLAGS=-O2
CWFLAGS=-Wall
CIFLAGS=-I. -I../common
#Uncomment this if you want more debug messages
#CMFLAGS=-DDEBUG 
CMFLAGS= -std=c++11 
#LIBS=-lssl -lcrypto
LIBS= -lpthread

CFLAGS= $(CWFLAGS) $(COFLAGS) $(CIFLAGS) $(CMFLAGS)

all: tcp_client

tcp_client.o: tcp_client.cpp
	$(CC) $(CFLAGS) -c tcp_client.cpp
utils.o: ../common/utils.h ../common/utils.cpp
	$(CPP) $(CFLAGS) -c ../common/utils.cpp
stats.o: ../common/stats.h ../common/stats.cpp
	$(CPP) $(CFLAGS) -c ../common/stats.cpp
	
tcp_client: tcp_client.o utils.o stats.o
	$(CPP) -o tcp_client tcp_client.o utils.o stats.o $(LIBS)
	$(RM) *.o

install: compile

clean:
	$(RM) -f *.o tcp_client
		
distclean: clean
