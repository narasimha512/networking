#include "utils.h"

std::map<std::string, std::string> staticConfig;
uint_32 curr_time_in_seconds;

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

