#include "utils.h"

void initSockUtils();

void setSocketOptions(int sockfd);

int readnbytes(int sock_fd,  void* buffer, int bytes);
int sendnbytes(int sock_fd,  void* buffer, int bytes);
int pollOnFd(int sock_fd, int poll_time_out, short int events);

void threadExitOnError(int ret, int sock);

void closeOnError(int ret, int sock);

