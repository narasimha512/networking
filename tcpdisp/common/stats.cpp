#include "stats.h"

const int STATS_SIZE = 10;

int response_times[STATS_SIZE];
int total_response_times[STATS_SIZE];

void update_tps(int sockfd, hrtime_t current_time, hrtime_t& prev_time, int& tps)
{
    if(((current_time - prev_time) / (1000 * 1000 * 1000)) >= 1)
    {
        cout << "sockfd: " << sockfd << " tps: " << tps << " current_time: " << curr_time_in_seconds << endl << std::flush;;
        tps = 0;
        prev_time = current_time;
    }
        else
        {
            tps++;
        }
        
    
}
void reset_stats()
{
    static bool reset_done=false;
    if(!reset_done)
    {
    for(int i=0; i< STATS_SIZE; i++)
    {
        total_response_times[i] = 0;
    }

    }
    for(int i=0; i< STATS_SIZE; i++)
    {
        if(reset_done)
        {
           total_response_times[i] += response_times[i];

        }
        response_times[i] = 0;

    }
}

void update_stats(uint_32 resp_time)
{
    if(resp_time < 1)
    {
        response_times[0]++;
    }
    else if(resp_time < 10)
    {
        response_times[1]++;
    }
    else if(resp_time < 50)
    {
        response_times[2]++;
    }
    else if(resp_time < 100)
    {
        response_times[3]++;
    }    
    else if(resp_time < 500)
    {
        response_times[4]++;
    }    
    else if(resp_time < 1000)
    {
        response_times[5]++;
    }
    else if(resp_time < 2000)
    {
        response_times[6]++;
    }
    else  if(resp_time < 5000)
    {
        response_times[7]++;
    }
    else  if(resp_time < 10000)
    {
        response_times[8]++;
    }
    else  
    {
        response_times[9]++;
    }    
}


void print_stats()
{

        if(response_times[0])
        cout << "time: " << curr_time_in_seconds << " response time less than 1ms " << response_times[0] << endl;

        if(response_times[1])
        cout << "time: " << curr_time_in_seconds << " response time less than 10ms " << response_times[1] << endl;

        if(response_times[2])
        cout << "time: " << curr_time_in_seconds << " response time less than 50ms " << response_times[2] << endl;

        if(response_times[3])
        cout << "time: " << curr_time_in_seconds << " response time less than 100ms " << response_times[3] << endl;

        if(response_times[4])
        cout << "time: " << curr_time_in_seconds << " response time less than 500ms " << response_times[4] << endl;

        if(response_times[5])
        cout << "time: " << curr_time_in_seconds << " response time less than 1sec " << response_times[5] << endl;

        if(response_times[6])
        cout << "time: " << curr_time_in_seconds << " response time less than 2sec " << response_times[6] << endl;

        if(response_times[7])
        cout << "time: " << curr_time_in_seconds << " response time less than 5sec " << response_times[7] << endl;

        if(response_times[8])
        cout << "time: " << curr_time_in_seconds << " response time less than 10sec " << response_times[8] << endl;

        if(response_times[9])
        cout << "time: " << curr_time_in_seconds << " response time greater than 10sec " << response_times[9] << endl;

}