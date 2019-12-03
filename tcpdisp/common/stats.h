#include "utils.h"

void update_stats(uint_32 resp_time);
bool print_stats();
void reset_stats();

void update_tps(string type, int sockfd, uint_32& last_second, int& tps, size_t size);

