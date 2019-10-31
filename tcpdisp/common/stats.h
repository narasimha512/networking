#include "utils.h"

void update_stats(uint_32 resp_time);
void print_stats();
void reset_stats();

void update_tps(int sockfd, hrtime_t current_time, hrtime_t& prev_time, int& tps);

