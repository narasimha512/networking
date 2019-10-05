#include <iostream>
#include <sstream>
#include <chrono>
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
int readnbytes(int sock_fd,  void* buffer, int bytes);
int sendnbytes(int sock_fd,  void* buffer, int bytes);
int pollOnFd(int sock_fd, int poll_time_out, short int events);

#endif