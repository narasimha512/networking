// Server side C/C++ program to demonstrate Socket programming
#include "stats.h"
#include "sock_utils.h"
#include "shared_queue.h"
int running_clients = 0;

void* receive(void* ptr)
{
    char request_buffer[4096] = {0};
    /*char response_buffer[4096] = {0};

    string hello;
    hello.assign('h',4096);
    memcpy(response_buffer, hello.c_str(), 4095 );*/

    SharedQueue<queueData>* queuePtr = (static_cast<SharedQueue<queueData>*>(ptr));
    //int sock_fd = *(static_cast<int*>(ptr));
    int sock_fd = queuePtr->sock_fd;
    int resp_msg_size = atoi(getStaticConfig("resp_msg_size").c_str());

    //stats
    uint_32 prev_time = curr_time_in_seconds;
    reset_stats();
    int tps = 0;
    uint_32 last_second = curr_time_in_seconds;

    while (true)
    {
        queueData l_queue_data;

        unsigned int req_msg_size = 0;
        int valread = readnbytes(sock_fd , &req_msg_size, sizeof(req_msg_size));
        //cout << "read " << valread << " bytes" << endl;
        threadExitOnError(valread, sock_fd, running_clients);
        valread = readnbytes(sock_fd , request_buffer, req_msg_size - sizeof(req_msg_size));
        //cout << "read " << valread << " bytes" << endl;

        threadExitOnError(valread, sock_fd, running_clients);


        hrtime_t request_time = 0;
        memcpy(&request_time, request_buffer , sizeof(hrtime_t));
        //usleep(100000);
        char* response_buffer = new char[resp_msg_size + 1];

        memcpy(response_buffer, &resp_msg_size, sizeof(resp_msg_size));
        hrtime_t current_time = getCurrentTimeInNanoSec();
        memcpy(response_buffer + sizeof(req_msg_size), &request_time, sizeof(hrtime_t));
        memcpy(response_buffer + sizeof(hrtime_t) + sizeof(req_msg_size), &current_time, sizeof(hrtime_t));

        l_queue_data.buffer = response_buffer;
        l_queue_data.size = resp_msg_size;

        queuePtr->push_back(l_queue_data);

        update_tps("receive", sock_fd, last_second, tps, queuePtr->size());

#if 0
        uint_32 resp_time = (current_time - request_time) / 1000000;

        update_stats(resp_time);
        //cout << "time: " << curr_time_in_seconds << " response time:" << resp_time << " usec" << endl;
        if (prev_time != curr_time_in_seconds)
        {
            print_stats();
            reset_stats();
            prev_time = curr_time_in_seconds;
        }
#endif
    }
}

void* send(void* ptr)
{
    SharedQueue<queueData>* queuePtr = (static_cast<SharedQueue<queueData>*>(ptr));
    //int sock_fd = *(static_cast<int*>(ptr));
    int sock_fd = queuePtr->sock_fd;
    //int resp_msg_size = atoi(getStaticConfig("resp_msg_size").c_str());

    //stats
    reset_stats();
    int tps = 0;
    uint_32 last_second = curr_time_in_seconds;

    while (true)
    {
        queueData& l_queue_data = queuePtr->front();

        int bytesCount = sendnbytes(sock_fd , l_queue_data.buffer ,  l_queue_data.size);
        hrtime_t current_time = getCurrentTimeInNanoSec();
        //cout << "written " << bytesCount << " bytes" << endl;
        threadExitOnError(bytesCount, sock_fd, running_clients);
        delete[] l_queue_data.buffer;
        queuePtr->pop_front();

        update_tps("sent", sock_fd, last_second, tps, queuePtr->size());

#if 0
        uint_32 resp_time = (current_time - request_time) / 1000000;

        update_stats(resp_time);
        //cout << "time: " << curr_time_in_seconds << " response time:" << resp_time << " usec" << endl;
        if (last_second != curr_time_in_seconds)
        {
            print_stats();
            reset_stats();
            last_second = curr_time_in_seconds;
        }
#endif

    }
}


int main(int argc, char const* argv[])
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);


    char response_buffer[4096] = {0};
    initStaticConfig("server.config");
    int tps_count = atoi(getStaticConfig("tps_count").c_str());

    initSockUtils();

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
    address.sin_port = htons(atoi(getStaticConfig("listen_port").c_str()));

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    do
    {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
                                 (socklen_t*)&addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        setSocketOptions(new_socket);

        SharedQueue<queueData>* queuePtr = new SharedQueue<queueData>;
        //int *ptr = new int;
        //*ptr = new_socket;
        queuePtr->sock_fd = new_socket;
        pthread_t posix_thread_recv_id;
        int return_code;
        return_code = pthread_create(&posix_thread_recv_id, NULL, receive, queuePtr);
        pthread_t posix_thread_send_id;
        return_code = pthread_create(&posix_thread_send_id, NULL, send, queuePtr);


    }
    while (1);
    return 0;
}

