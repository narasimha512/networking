// Server side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include "utils.h"

void closeOnError(int ret, int sock)
{
    if(ret < 0)
    close(sock);
}

void* receive(void* ptr)
{
    char request_buffer[4096] = {0};
    char response_buffer[4096] = {0};

    string hello;
        hello.assign('h',4096);
    memcpy(response_buffer, hello.c_str(), 4095 );

    int sock_fd = *(static_cast<int*>(ptr));
    int resp_msg_size = atoi(getStaticConfig("resp_msg_size").c_str());

    while(true)
    {
    unsigned int req_msg_size = 0;
    int valread = readnbytes( sock_fd , &req_msg_size, sizeof(req_msg_size));
        //cout << "read " << valread << " bytes" << endl;
    closeOnError(valread, sock_fd);
    valread = readnbytes( sock_fd , request_buffer, req_msg_size - sizeof(req_msg_size));   
        //cout << "read " << valread << " bytes" << endl;

    closeOnError(valread, sock_fd);

    hrtime_t request_time = 0;
    memcpy(&request_time, request_buffer , sizeof(hrtime_t) );    
    //usleep(100000);
    memcpy(response_buffer, &resp_msg_size, sizeof(resp_msg_size) );
    hrtime_t current_time = getCurrentTimeInNanoSec();
    memcpy(response_buffer + sizeof(req_msg_size), &request_time, sizeof(hrtime_t) );
    memcpy(response_buffer + sizeof(hrtime_t) + sizeof(req_msg_size), &current_time, sizeof(hrtime_t) );
    int bytesCount = send(sock_fd , response_buffer ,  resp_msg_size, 0 );
        //cout << "written " << bytesCount << " bytes" << endl;

    }
}

int main(int argc, char const *argv[])
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);


    char response_buffer[4096] = {0};
    initStaticConfig("server.config");
    int tps_count = atoi(getStaticConfig("tps_count").c_str());

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
     
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(getStaticConfig("listen_ip").c_str());;
    address.sin_port = htons( atoi(getStaticConfig("listen_port").c_str()));
     
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

do    {
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    int *ptr = new int;
    *ptr = new_socket;
    pthread_t posix_thread_id;
    int return_code = pthread_create(&posix_thread_id, NULL, receive, ptr);


    }while(1);
    return 0;
}

