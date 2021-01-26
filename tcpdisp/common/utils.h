#include <iostream>
#include <sstream>
//#include <chrono>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <uuid/uuid.h>
#include <assert.h>
#include <fstream>
#include <map>
#include <string>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <netdb.h>

using namespace std;

#ifndef __UTILS_H__
#define __UTILS_H__

typedef long long hrtime_t;
typedef unsigned int uint_32;

const hrtime_t SECOND_TO_NANOSECONDS = 1000000000LL;

extern uint_32 curr_time_in_seconds;

void initStaticConfig(const std::string& fileName);
const std::string getStaticConfig(const std::string& key);
hrtime_t getCurrentTimeInNanoSec();
void waitForNextInterval(hrtime_t timeTakenToComplete);
void printCompletedTime();


#endif