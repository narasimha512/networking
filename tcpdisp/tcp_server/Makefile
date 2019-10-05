### Makefile for server
LIBS=
CPP=g++
CC=gcc

COFLAGS=-O2
CWFLAGS=-Wall
CIFLAGS=-I. -I../common
#Uncomment this if you want more debug messages
#CMFLAGS=-DDEBUG
CMFLAGS= -std=c++11

CPPFLAGS= $(CWFLAGS) $(COFLAGS) $(CIFLAGS) $(CMFLAGS)

STRIP = strip

SHELL= /bin/sh
#LIBS = -lssl -lcrypto
LIBS = -lpthread

# Use this when you want DEBUG info
#CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Dlint -funroll-loops -fomit-frame-pointer -I../common -DDEBUG
CFLAGS = -DLINUX -D_REENTRANT -pipe -g -O2 -Wall -Dlint -funroll-loops -fomit-frame-pointer 

all: tcp_server

tcp_server.o: tcp_server.cpp
	$(CPP) $(CFLAGS)  $(CPPFLAGS) -c tcp_server.cpp
utils.o: ../common/utils.cpp ../common/utils.h
	$(CPP) $(CFLAGS) $(CPPFLAGS) -c ../common/utils.cpp

tcp_server: tcp_server.o utils.o
	
	$(CPP) -o tcp_server $(LIBS) tcp_server.o utils.o 
	
	#$(STRIP) tcp_server	
	$(RM) -f *.o

install: all

clean:
	$(RM) -f *.o tcp_server

