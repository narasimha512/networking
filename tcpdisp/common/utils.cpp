#include "utils.h"

std::map<std::string, std::string> staticConfig;
uint_32 curr_time_in_seconds;
uint_32 read_time_out_ms;
uint_32 send_time_out_ms;

void initStaticConfig(const std::string& fileName)
{
    std::string line;
    std::ifstream file(fileName);
    if (file.is_open())
    {
        while (getline(file, line))
        {
            //cout << "File is  [" << line << "] found... " << endl;
            std::istringstream is_line(line);
            std::string key, value;
            if (std::getline(is_line, key, '=') && std::getline(is_line, value))
            {
                if ('#' == key.at(0))
                {
                    continue;
                }
                cout << key << " " << value << std::endl;
                staticConfig[key] = value;
            }
        }
        file.close();
    }
    else
    {
        cout << "Unable to open [" << fileName << "] for static configuration init";
    }

    read_time_out_ms = atoi(getStaticConfig("poll_read_timeout").c_str());
    send_time_out_ms = atoi(getStaticConfig("poll_write_timeout").c_str());
}

const std::string getStaticConfig(const std::string& key)
{
    std::string value;
    std::map<std::string, std::string>::const_iterator itr = staticConfig.find(key);
    if (staticConfig.end() != itr)
    {
        value = itr->second;
        cout << "Static Config found for " << key << " " << value << endl;
    }
    else
    {
        cout << "No key with [" << key << "] found... " << endl;
    }
    return value;
}

hrtime_t getCurrentTimeInNanoSec()
{
    struct timespec sp;
    hrtime_t nsec;
    if (clock_gettime(CLOCK_REALTIME, &sp))
    {
        return 0;
    }

    nsec = 1000000000LL;
    nsec *= sp.tv_sec;
    curr_time_in_seconds = sp.tv_sec;
    nsec += sp.tv_nsec;
    return nsec;
}

void waitForNextInterval(hrtime_t timeTakenToComplete)
{
            struct timespec tim;
            tim.tv_sec = 0;

            // Sleep for the rest of the second
            tim.tv_nsec = (SECOND_TO_NANOSECONDS  - timeTakenToComplete);    

            while (1)
            {
                int ret = nanosleep(&tim, &tim);
                if ((ret && (errno !=  EINTR)) || (!ret))
                {
                    break;
                }

            }   
}

int readnbytes(int sock_fd, void* buffer, int bytes)
{
    int readBytes = 0;
    int remainingBytes = bytes;
    do 
    {
    int valread = read( sock_fd , buffer, remainingBytes);
    if(valread > 0)
    {
        remainingBytes -= valread;
        readBytes += valread;
    }
    else if (valread == 0)
    {
        int ret = pollOnFd(sock_fd, read_time_out_ms, POLLIN);
        if(ret == -1)
        {
          return -1;
        }
    }
    else
    {
        return -1;
    }
    }
    while(readBytes < bytes);
    return bytes;
}

int pollOnFd(int sock_fd, int poll_time_out, short int events)
{
    struct pollfd fds;

fds.fd = sock_fd;//open("/dev/dev0", ...);
fds.events = events;

int ret = poll(&fds, 1, poll_time_out);

	if (ret == -1) {
		perror ("poll");
		return -1;
	}

	if (!ret) {
		printf ("%d seconds elapsed.\n", poll_time_out);
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
    int sendBytes = 0;
    int remainingBytes = bytes;
    do 
    {
    int sentBytes = send( sock_fd , buffer, remainingBytes, 0);
    if(sentBytes > 0)
    {
        remainingBytes -= sentBytes;
        sendBytes += sentBytes;
    }
    else if (sentBytes == 0)
    {
        int ret = pollOnFd(sock_fd, send_time_out_ms, POLLOUT);
        if(ret == -1)
        {
          return -1;
        }
    }
    else
    {
        return -1;
    }
    }
    while(sendBytes < bytes);
    return bytes;
}