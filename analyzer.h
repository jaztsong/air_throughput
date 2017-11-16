#include <stdint.h>
#include <cstdlib>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <map>
#include <iomanip>
#include <assert.h>     
#include <math.h> 
#include <algorithm>
#include <bitset>
#include <tuple>
#include <queue>
#include <set>
#include <future>
#include "float.h"
#include <zmq.hpp>
#include <mutex>

/* #define MULTI_THREAD */
/* #define PROBE_REQUEST_BASED */
/* #define OVERLAP_WINDOW true */

#define ADD_LEN 17
#define BITMAP_LEN 64
//
#define MTU 1350

/* The percentile parameter to compute transmission rate */
#define X_PERCENTILE_5 0.5
#define X_PERCENTILE_24 0.25

class Line_cont;
class BlkACK_stat;
class Analyzer
{
        public:
                Analyzer(uint16_t);
                /* virtual ~Analyzer (); */
                uint16_t getWindowSize();
                double getTime();
                void addPacket(std::string);
                void start_report(uint16_t);
                void stop_report();

        private:
                std::atomic<bool> _execute;
                std::thread mReport_thd;
                zmq::socket_t* mZMQ_publisher;
                zmq::context_t mZMQ_context;
                std::mutex mPackets_mutex;

                void init_zmq();

                //All in millisecond
                std::string mName;
                double mAirtime;
                uint16_t mLoss;
                uint16_t mWindow;
                bool clean_Packets();
                std::deque<Line_cont*> mPackets;
                std::map<std::string,BlkACK_stat*> mBlkACKs;
                bool populate_BlkACK();
                void do_analyze();
                void clean_mem();
                void report();
                void dump_report();
                float estimate_throughput();
                bool is_blockACK(Line_cont*);
                /* std::queue<Line_cont*> m_queue_blockACKreq; */
                /* data */

};

class Line_cont
{
        public:
                enum Fields{
                        F_TIME = 0,
                        F_TIME_DELTA = 1,
                        F_LEN = 2,
                        F_TA = 3,
                        F_RA = 4,
                        F_TYPE_SUBTYPE = 5,
                        F_DS = 6,
                        F_RETRY = 7,
                        F_RSSI = 8,
                        F_FREQ = 9,
                        F_RATE = 10,
                        F_NAV = 11,
                        F_BLKACK_SSN = 12,
                        F_BLKACK_BM = 13
                };

                Line_cont (std::string);
                void read_field(std::string,uint8_t);
                std::string get_field(Fields);
                void print_fields();
                double getTime();
                Line_cont* next_line;
                void clean_mem_line();

        private:
                double mTime;
                std::map<Fields, std::string> mData;
                /* data */

};


class BlkACK {
        public:
                BlkACK(Line_cont*);
                std::string addr;
                bool addr_rev;
                Line_cont* line;
                uint16_t SSN;
                int RSSI;
                std::vector<uint16_t> Miss;
};
class BlkACK_stat
{
        public:
                BlkACK_stat (std::string);
                std::string getAddr();
                void addACK(BlkACK*);
                void add_ACK_airtime(float);
                void addRTS_airtime(float);
                std::vector<std::tuple<uint16_t,uint16_t,int,float,bool> > mAMPDU_tuple;
                bool parse_AMPDU();
                float getAMPDU_mean();
                uint16_t getN_MPDU_flow();
                float getAirTime_flow();
                float getGap_mean_flow();
                float getLoss_flow();



                void setPktSize(uint16_t);
                uint16_t getPktSize();
                void calc_stats();
                void calc_rate();
                void report_flow();
                float getRate_flow();
                int getRSSI_flow();
                float getAMPDU_mean_flow();
                void report_pkt();
                void clean_mem_flow();


        private:
                std::string mAddr;
                std::vector<BlkACK*> mACKs;
                std::vector<uint16_t> mvector_Loss;
                std::vector<float> mACK_airtime;
                int set_diff(std::vector<uint16_t>&,std::vector<uint16_t>&);
                float mAirtime;
                int mRSSI_mean;
                float mAMPDU_mean;
                float mLoss;
                float mRate;
                float mTime_delta;
                uint16_t mMPDU_num;
                uint16_t mPkt_Size;
                uint16_t mFREQ;
                /* data */



};
