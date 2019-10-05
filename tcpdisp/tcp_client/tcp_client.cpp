// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include "utils.h"
#include "stats.h"

int sock = 0;
void* receive(void* ptr)
{
    char response_buffer[4096] = {0};
    unsigned int req_msg_size = 0;
    hrtime_t current_time = 0;
    hrtime_t request_time = 0;
    hrtime_t response_time = 0;
    uint_32 prev_time = curr_time_in_seconds;
    reset_stats();

    while(1)
    {
        //usleep(100000);
    int valread = readnbytes( sock , &req_msg_size, sizeof(req_msg_size));
    //cout << "read " << valread << " bytes" << endl;
    valread = readnbytes( sock , response_buffer, req_msg_size - sizeof(req_msg_size));
    //cout << "read " << valread << " bytes" << endl;
    memcpy(&request_time, response_buffer, sizeof(hrtime_t) );
    memcpy(&response_time, response_buffer + sizeof(hrtime_t), sizeof(hrtime_t) );
    //cout << "request_time time " << request_time << endl;
    //cout << "response_time time " << response_time << endl;
    current_time = getCurrentTimeInNanoSec();   

    uint_32 resp_time = (current_time - request_time) / 1000000;
    update_stats(resp_time);
    //cout << "time: " << curr_time_in_seconds << " response time:" << resp_time << " usec" << endl;
    if(prev_time != curr_time_in_seconds)
    {
        print_stats();
        reset_stats();
        prev_time = curr_time_in_seconds;
    }
    }
}


int main(int argc, char const *argv[])
{
    struct sockaddr_in address;
    int valread;
    struct sockaddr_in serv_addr;
    unsigned int tps = 0;
    string hello;
    hello.assign('h',4096);
    char request_buffer[4096] = {0};
    memcpy(request_buffer, hello.c_str(), 4095 );

    initStaticConfig("client.config");
    int tps_count = atoi(getStaticConfig("tps_count").c_str());
    int req_msg_size = atoi(getStaticConfig("req_msg_size").c_str());

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    memset(&serv_addr, '0', sizeof(serv_addr));

    if(strcmp(getStaticConfig("src_routing").c_str(), "true"))
    {
    struct sockaddr_in localaddr;
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr(getStaticConfig("local_ip").c_str());
    localaddr.sin_port = 0;  // Any local port will do
    bind(sock, (struct sockaddr *)&localaddr, sizeof(localaddr));

    }
	serv_addr.sin_family = AF_INET;
     
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, getStaticConfig("server_ip").c_str(), &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    serv_addr.sin_port = htons(atoi(getStaticConfig("server_port").c_str()));
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    pthread_t posix_thread_id;
    int return_code = pthread_create(&posix_thread_id, NULL, receive, NULL);

    hrtime_t loadStartTime;

    do
    {
    if(tps == 0)
    {
        loadStartTime = getCurrentTimeInNanoSec();
    }
    tps++;

    memcpy(request_buffer, &req_msg_size, sizeof(req_msg_size) );
    hrtime_t current_time = getCurrentTimeInNanoSec();
    memcpy(request_buffer + sizeof(req_msg_size), &current_time, sizeof(hrtime_t) );
    int bytesCount = send(sock , request_buffer ,  req_msg_size, 0 );
    
    if(tps_count <= tps )
    {
        hrtime_t iterationEndTime = getCurrentTimeInNanoSec();
        hrtime_t timeTakenToComplete = iterationEndTime - loadStartTime;

        tps=0;
        waitForNextInterval(timeTakenToComplete);             
    }
    }
    while(tps_count > 0);
    return 0;
}

