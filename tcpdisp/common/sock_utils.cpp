#include "sock_utils.h"

uint_32 read_time_out_ms;
uint_32 send_time_out_ms;

void initSockUtils()
{
    read_time_out_ms = atoi(getStaticConfig("poll_read_timeout").c_str());
    send_time_out_ms = atoi(getStaticConfig("poll_write_timeout").c_str());    
}

void setSocketOptions(int sock_fd)
{

  int sendBufferSize = atoi(getStaticConfig("send_buf_size").c_str()); //1 MB
  int recvBufferSize = atoi(getStaticConfig("recv_buf_size").c_str()); //2 MB

  if (sendBufferSize)
  {
   if( -1 >= setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &sendBufferSize, sizeof(sendBufferSize)))
  {
    cout << "setsockopt(SO_SNDBUF) failed: " << errno << endl << flush;
  }
  else
  {
    cout << "setsockopt(SO_SNDBUF) success: " << errno << endl << flush;
      
  }
  
  }
  if (recvBufferSize) 
  {
  if( -1 >= setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &recvBufferSize, sizeof(recvBufferSize)))
  {
    cout << "setsockopt(SO_RCVBUF) failed: " << errno << endl << flush;
  }
  else
  {
    cout << "setsockopt(SO_RCVBUF) success: " << errno << endl << flush;      
  }
  
  }
}

void threadExitOnError(int ret, int sock)
{
    if(ret < 0)
    {
        cout << "threadExitOnError: err " << errno << endl << flush;      
    close(sock);
    pthread_exit(0);
    }
}

void closeOnError(int ret, int sock)
{
    if(ret < 0)
    {
        cout << "closeOnError: err " << errno << endl << flush;      

    close(sock);
    }
}

int readnbytes(int sock_fd, void* buffer, int bytes)
{
    int remainingBytes = bytes;
    do 
    {
    int valread = read( sock_fd , buffer, remainingBytes);
    if(valread > 0)
    {
        remainingBytes -= valread;
        buffer += valread;
    }
    else if (valread == 0)
    {
                        cout << "polling for read: " << read_time_out_ms << endl << flush;      
        int ret = pollOnFd(sock_fd, read_time_out_ms, POLLIN);
        if(ret == -1)
        {
        cout << "readnbytes pollOnFd: err " << errno << endl << flush;      

          return -1;
        }
    }
    else
    {
        cout << "readnbytes: err " << errno << " while reading : " << remainingBytes << endl << flush;      
        cout << "readnbytes: remainingBytes " << remainingBytes << " total bytes : " << bytes << endl << flush;      

        return -1;
    }
    }
    while(remainingBytes > 0);
    return bytes;
}

int pollOnFd(int sock_fd, int poll_time_out, short int events)
{
    struct pollfd fds;

fds.fd = sock_fd;//open("/dev/dev0", ...);
fds.events = events;

int ret = poll(&fds, 1, poll_time_out);

	if (ret == -1) {
        cout << "pollOnFd: err " << errno << endl << flush;      
		return -1;
	}

	if (!ret) {
                cout << "elapsed: " << poll_time_out << endl << flush;      
		return 0;
	}

if (ret > 0) {
    /* An event on the fds has occurred. */
    if (fds.revents & events) {
    /* Priority data may be written on device number i. */
        return 1;
    }
}
}

int sendnbytes(int sock_fd, void* buffer, int bytes)
{
    int remainingBytes = bytes;
    do 
    {
    int sentBytes = send( sock_fd , buffer, remainingBytes, 0);
    if(sentBytes > 0)
    {
        remainingBytes -= sentBytes;
        buffer += sentBytes;
    }
    else if (sentBytes == 0)
    {
        cout << "polling for write: " << send_time_out_ms << endl << flush;      
        int ret = pollOnFd(sock_fd, send_time_out_ms, POLLOUT);
        if(ret == -1)
        {
        cout << "sendnbytes pollOnFd: err " << errno << " while sending : " << remainingBytes <<  endl << flush;

          return -1;

        }
    }
    else
    {
        cout << "sendnbytes: err " << errno << endl << flush;      
        cout << "sendnbytes: remainingBytes " << remainingBytes << " total bytes : " << bytes << endl << flush;      

        return -1;
    }
    }
    while(remainingBytes > 0);
    return bytes;
}