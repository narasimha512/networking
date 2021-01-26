#include "stats.h"

const int STATS_SIZE = 10;

int response_times[STATS_SIZE];
int total_response_times[STATS_SIZE];
int latency_counter=0;

void update_tps(string type, int sockfd, uint_32& last_second, int& tps, size_t size)
{
    if (last_second != curr_time_in_seconds)
    {
        cout << "time: " << curr_time_in_seconds << " " << type << " sockfd: " << sockfd << " tps: " << tps  << " pending: " <<
             size << endl << std::flush;;
        tps = 1;
        last_second = curr_time_in_seconds;
    }
    else
    {
        tps++;
    }


}
void reset_stats()
{
    static bool reset_done = false;
    if (!reset_done)
    {
        for (int i = 0; i < STATS_SIZE; i++)
        {
            total_response_times[i] = 0;
        }

    }
    for (int i = 0; i < STATS_SIZE; i++)
    {
        if (reset_done)
        {
            total_response_times[i] += response_times[i];

        }
        response_times[i] = 0;

    }
}

void update_stats(uint_32 resp_time)
{
    if (resp_time < 1)
    {
        response_times[0]++;
    }
    else if (resp_time < 10)
    {
        response_times[1]++;
    }
    else if (resp_time < 50)
    {
        response_times[2]++;
    }
    else if (resp_time < 100)
    {
        response_times[3]++;
    }
    else if (resp_time < 500)
    {
        response_times[4]++;
    }
    else if (resp_time < 1000)
    {
        response_times[5]++;
    }
    else if (resp_time < 2000)
    {
        response_times[6]++;
    }
    else  if (resp_time < 5000)
    {
        response_times[7]++;
    }
    else  if (resp_time < 10000)
    {
        response_times[8]++;
    }
    else
    {
        response_times[9]++;
    }
}


bool print_stats()
{

    if (response_times[0])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 1ms " << response_times[0] << endl;
    }
    if (response_times[1])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 10ms " << response_times[1] << endl;
    }

    if (response_times[2])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 50ms " << response_times[2] << endl;
    }

    if (response_times[3])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 100ms " << response_times[3] << endl;
    }

    if (response_times[4])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 500ms " << response_times[4] << endl;
    }

    if (response_times[5])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 1sec " << response_times[5] << endl;
    }

    if (response_times[6])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 2sec " << response_times[6] << endl;
    }

    if (response_times[7])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 5sec " << response_times[7] << endl;
    }
    if (response_times[8])
    {
        cout << "time: " << curr_time_in_seconds << " response time less than 10sec " << response_times[8] << endl;
    }
    if (response_times[9])
    {
        cout << "time: " << curr_time_in_seconds << " response time greater than 10sec " << response_times[9] << endl;
    }
    if(response_times[7] || response_times[8] || response_times[9])
    {
        latency_counter++;
    }
    else
    {
        latency_counter=0;
    }
    if(latency_counter)
    {
        printCompletedTime();
    }

    if(latency_counter > 5)
    {
        printCompletedTime();
        cout << "exiting as latency counter reached max limit: " << latency_counter << " time: " << curr_time_in_seconds <<  endl << flush;
        return false;
    }
    return true;
}