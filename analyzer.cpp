#include "analyzer.h"
#include <iostream>
#include <cmath>

using namespace std;
void calc_mean_std(vector<float> v, float* mean, float* std)
{
        float mean_ = 0.0;
        float std_ = 0.0;
        for (auto v_ : v){
            mean_ += v_;
        }
        mean_ = mean_/v.size();
        for (auto v_ : v){
           std_ += pow(v_-mean_,2);
        }
        *mean = mean_;
        *std = sqrt(std_/v.size());
}
Analyzer::Analyzer(uint16_t w, uint16_t c)
        : mZMQ_context(1)
{
        mWindow = w;
        mAirtime = 0.0;
        mChunk_Window = c;
        mScale = 1.0;
        mLoss = 0.0;
        mPackets.clear();
        mChunks.clear();
        mBlkACKs.clear();
        init_zmq();
        srand(time(NULL));
}
void Analyzer::stop_report()
{
        _execute.store(false, std::memory_order_release);
        if( mReport_thd.joinable() )
                mReport_thd.join();
}

void Analyzer::start_report(uint16_t interval)
{
        if( _execute.load(std::memory_order_acquire) ) {
                stop_report();
        };
        _execute.store(true, std::memory_order_release);
        mReport_thd = std::thread(
                        [this, interval]()
                        {
                        while (_execute.load(std::memory_order_acquire)) {
                        std::this_thread::sleep_for(
                                std::chrono::milliseconds(interval));
                        do_analyze();                   
                        }
                        });
}
void Analyzer::init_zmq()
{
        /* mZMQ_context = new zmq::context_t(1); */
        /* mZMQ_publisher = new zmq::socket_t(*mZMQ_context, ZMQ_PUB); */
        mZMQ_publisher = new zmq::socket_t(mZMQ_context, ZMQ_PUB);
        mZMQ_publisher->bind("tcp://*:5556");
}
void Analyzer::addPacket(string line)
{

        string line_value;
        istringstream ss(line);
        Line_cont* line_c = NULL;
        uint8_t count = 0;
        while(getline(ss, line_value, '|'))
        {
                if(count == 0 ){
                        line_c = new Line_cont(line_value);
                }
                if (line_c != NULL)
                        line_c->read_field(line_value,count);
                count++;
        }


        if (line_c != NULL){
                std::lock_guard<std::mutex> guard(mPackets_mutex);
                mPackets.push_back(line_c);
        }

}

bool Analyzer::clean_Packets()
{
        std::lock_guard<std::mutex> guard(mPackets_mutex);
        if(mPackets.size() == 0){
                return false;
        }
        while(( mPackets.back() )->getTime() - ( mPackets.front() )->getTime() > mWindow/1000.0){
                ( mPackets.front() )->clean_mem_line();
                delete mPackets.front();
                mPackets.pop_front();
        }
        return true;

}
bool Analyzer::make_chunks()
{
        std::lock_guard<std::mutex> guard(mPackets_mutex);
        vector<Line_cont*> temp_pkts;
        double st_time = mPackets.front()->getTime();
        for(auto it:mPackets){
                if(it->getTime() > st_time + (double) mChunk_Window/1000.0){
                        mChunks.push_back(temp_pkts);
                        temp_pkts.clear();
                        st_time += (double) mChunk_Window/1000.0;
                }
                temp_pkts.push_back(it);
        }
        if(temp_pkts.size() > 0)
                mChunks.push_back(temp_pkts);
        if(mChunks.size() > 0){
                return true;
        }
        else{
                return false;
        }

}

map<std::string,BlkACK_stat*> Analyzer::populate_BlkACK(vector<Line_cont*> tPackets)
{
        map<std::string,BlkACK_stat*> tBlkACKs;
        for(auto it = tPackets.begin(); it != tPackets.end();++it){
                //Populate BlkACK stats
                if(is_blockACK(*it)){
                        BlkACK* t_b =  new BlkACK(*it);
                        if(tBlkACKs.find(t_b->addr) == tBlkACKs.end()){
                                        BlkACK_stat* t_blkack_stat = new BlkACK_stat(t_b->addr);
                                        tBlkACKs[t_b->addr]=t_blkack_stat;
                        }
                        tBlkACKs[t_b->addr]->addACK(t_b);
                        tBlkACKs[t_b->addr]->parse_AMPDU();

                }

        }
        return tBlkACKs;
}
bool Analyzer::is_blockACK(Line_cont* l)
{
        if(l->get_field(Line_cont::F_RA).length() + l->get_field(Line_cont::F_TA).length() > 2*17 - 1)
                return ( l->get_field(Line_cont::F_TYPE_SUBTYPE) == "25" ) || ( l->get_field(Line_cont::F_TYPE_SUBTYPE) == "0x19" ); 
        else
                return false;

}

void Analyzer::do_analyze()
{
        vector<float> t_res;
        if(clean_Packets() == false){
                goto output;
        }
        if(make_chunks() == false){
                goto output;
        }
        mAirtime = 0.0;
        mLoss = 0.0;
        mRate_switch_guide = 0.0;
        for(auto ck:mChunks){
               float re[2];
               estimate_throughput(populate_BlkACK(ck),re);
               if(re[0] > -1)
                       t_res.push_back(re[0]);
        }
        if(t_res.size() == 0){
                goto output;
        }
        calc_mean_std(t_res,&mThroughput_mean,&mThroughput_std);
output:
        report();
        dump_report();
        clean_mem();
}
void Analyzer::estimate_throughput(map<std::string,BlkACK_stat*> BlkACKs,float* res)
{
        //TODO: This is a crude way to compute air throughput for video streaming purpose,
        //we may come back and make it more elegent to maybe detect/input adapter mac_addr as an input
        //For Lixing Wed 15 Nov 2017 09:39:42 AM EST.
        string my_addr = "80:1f:02:f5:b1:de";
        uint16_t my_MPDU_num = 0;
        uint16_t my_AMPDU_num = 0;
        float my_AMPDU_mean = 0;
        float my_AMPDU_gap = 0;
        uint16_t my_loss = 0;
        double my_airtime = 0.0;
        float throughput = 0;
        float my_rate = 0.0;
        float all_airtime = 0.0;
        float c_Scale = 1.0;
        map<string,tuple<float,float,uint16_t,float,float>> client_stats; //airtime,AMPDU_mean,Loss,AMPDU_gap,AMPDU_N
        for(auto blk_stat:BlkACKs){
                blk_stat.second->calc_stats();
                mAirtime += blk_stat.second->getAirTime_flow();
                all_airtime += blk_stat.second->getAirTime_flow();
                mLoss += blk_stat.second->getLoss_flow();
                if (blk_stat.first.substr(0,17) == my_addr){
                        my_airtime += blk_stat.second->getAirTime_flow();
                        my_loss = blk_stat.second->getLoss_flow();
                        my_MPDU_num = blk_stat.second->getN_MPDU_flow();
                        my_AMPDU_mean = blk_stat.second->getAMPDU_mean_flow();
                        my_AMPDU_gap = blk_stat.second->getGap_mean_flow()*blk_stat.second->getAMPDU_mean_flow(); 
                        my_AMPDU_num = blk_stat.second->getN_MPDU_flow()/blk_stat.second->getAMPDU_mean_flow();
                        /* throughput = 1000*blk_stat.second->getGap_mean_flow(); */
                }else if(blk_stat.first.substr(17,17) == my_addr){
                        my_airtime += blk_stat.second->getAirTime_flow();
                }
                client_stats[blk_stat.first] = make_tuple(
                                blk_stat.second->getAirTime_flow(),
                                blk_stat.second->getAMPDU_mean_flow(),
                                blk_stat.second->getAMPDU_max_flow(),
                                blk_stat.second->getGap_mean_flow()*blk_stat.second->getAMPDU_mean_flow(),
                                blk_stat.second->getN_MPDU_flow()/blk_stat.second->getAMPDU_mean_flow()
                                );

        }
        if(all_airtime/mChunk_Window>0.8)
                c_Scale = mChunk_Window/all_airtime;
        float tGap_sum = 0.0;
        for(auto c:client_stats){
                if(get<2>(c.second) > 0)
                        printf("%s airtime %5.3f AMPDU %3.1f Gap %3.1f N %d\n",
                                        c.first.c_str(),
                                        c_Scale*get<0>(c.second)/mChunk_Window,
                                        get<1>(c.second),
                                        get<3>(c.second),
                                        (uint16_t)get<4>(c.second)
                                        /* (get<1>(c.second) - 0*get<2>(c.second))*MTU*8/(1000*mAirtime*mScale) */
                              );
                tGap_sum += get<3>(c.second);
        }
        uint16_t light_link = 0, total_link = 0;
        mRate_switch_guide = 0.0;
        float give_up_factor = 1.5;
        for(auto c:client_stats){
                /* printf("compare AMPDU_Gap %5.3f>%5.3f?%d AMPDU_N %d>%d?%d\n", */
                /*                 get<3>(c.second),my_AMPDU_gap,get<3>(c.second) > my_AMPDU_gap, */
                /*                 (uint16_t)get<4>(c.second),my_AMPDU_num,(uint16_t)get<4>(c.second) > my_AMPDU_num); */
                if(( get<3>(c.second) > give_up_factor*my_AMPDU_gap ) && ( (uint16_t) get<4>(c.second) > give_up_factor*my_AMPDU_num )){
                        mRate_switch_guide = 1.0; //don't use this bitrate for going up;
                        break;
                }
                else if(get<3>(c.second) > 1.0){
                        if(( get<3>(c.second) <= my_AMPDU_gap ) || ( (uint16_t)get<4>(c.second) <= my_AMPDU_num ))   
                                light_link++;
                        total_link++;
                        printf("lsong2: haha %d/%d\n",light_link,total_link);
                }
        }
        if( total_link > 1 && mRate_switch_guide == 0.0){
                light_link--;
                total_link--;
                if(light_link == total_link)
                        mRate_switch_guide = 2.0; //don't use this bitrate for going down;
        }

        float E_AMPDU_num = all_airtime*c_Scale/tGap_sum;
        float E_throughput = 0;
        
        if(my_airtime > 0 && my_MPDU_num > 0){
                my_rate = (my_MPDU_num - 0*my_loss )*MTU*8/(1000*my_airtime);
                throughput = my_rate*( my_airtime )/( all_airtime*c_Scale );
                E_throughput = throughput*(E_AMPDU_num/my_AMPDU_num);
                /* E_throughput = throughput < E_throughput ? throughput + throughput*(E_AMPDU_num/my_AMPDU_num - 1)*my_airtime/all_airtime : E_throughput; */
                printf("My flow airtime %5.3f total %5.3f AMPDU %3.1f N %d(%5.2f) c_TH %4.2f e_TH %4.2f\n",
                                c_Scale*my_airtime/mChunk_Window,
                                all_airtime/mChunk_Window,
                                my_AMPDU_gap,
                                my_AMPDU_num,
                                E_AMPDU_num,
                                throughput,
                                E_throughput
                      );
        }
        /* if(all_airtime > 0){ */
        /*         uint32_t poll =  rand() %  (uint32_t) all_airtime*1000; */
        /*         if(  poll  < (uint32_t) my_airtime*1000 ) */
        /*                 printf("poll==================================================================\t"),throughput = E_throughput; */
        /*         printf("poll %d out of %d | %d\n",poll,(uint32_t) all_airtime*1000,(uint32_t)my_airtime*1000); */
        /* } */
        printf("\n");
        /* throughput = throughput + throughput*(E_AMPDU_num/my_AMPDU_num - 1)*my_airtime/mAirtime; */
        /* return E_throughput; */
        if (all_airtime > 0.5 || my_airtime > 0)
                *res = throughput;
        else
                *res = -2;
        *( res+1 ) = all_airtime;
}
void Analyzer::clean_mem()
{
        for(auto it:mBlkACKs){
                it.second->clean_mem_flow();
                delete it.second;
        }
        mBlkACKs.clear();
        mChunks.clear();
}
double Analyzer::getTime()
{
        if(mPackets.size()>0)
                return (mPackets.back() )->getTime();
        else
                return 0.0;
}

void Analyzer::report()
{
        zmq::message_t message(20);
        snprintf ((char *) message.data(), 20 ,
                        "%f %f", mThroughput_mean,mRate_switch_guide);
        mZMQ_publisher->send(message);
}

void Analyzer::dump_report()
{
        printf("%10.6f Airtime:%5.2f Air_Thrpt:%4.1f STD: %4.1f Rate_switch_guide %2.1f\n",
                        getTime(), //time
                        mAirtime,  //Airtime
                        mThroughput_mean,
                        mThroughput_std,
                        mRate_switch_guide
                        );
}

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////Line_cont (Line Container)/////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

Line_cont::Line_cont(string t)
{
        mTime=atof(t.c_str());
        next_line = NULL;
}

void Line_cont::read_field(string s, uint8_t index)
{
        mData[( (Fields) index )]=s;
}
string Line_cont::get_field(Fields f)
{
        return mData[f];
}
void Line_cont::print_fields()
{
         for (map<Fields,string>::iterator it=mData.begin(); it!=mData.end(); ++it)
                     std::cout << it->first << "=>" << it->second <<'\t' ;
         std::cout<<endl;
}

double Line_cont::getTime()
{
        return mTime;

}
void Line_cont::clean_mem_line(){
        mTime = 0.0;
        mData.clear();
}


////////////////////////////////////////////////////////////////////////////////////
////////////////////////////BlkACK//////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
BlkACK::BlkACK(Line_cont* l)
{
        string t_addr1 = l->get_field(Line_cont::F_TA);
        string t_addr2 = l->get_field(Line_cont::F_RA);
        string t_addr = t_addr1 + t_addr2;
        /* double t_time = atof( ( l->get_field(Line_cont::F_TIME) ).c_str() ); */
        uint16_t t_ssn = atoi( ( l->get_field(Line_cont::F_BLKACK_SSN) ).c_str() );
        int t_rssi = atoi( ( l->get_field(Line_cont::F_RSSI) ).c_str() );
        istringstream ss(l->get_field(Line_cont::F_BLKACK_BM));
        string byte;
        uint8_t index=0;
        
        this->addr = t_addr;
        this->addr_rev = t_addr1.compare(t_addr2) < 0;
        this->line = l;
        this->SSN = t_ssn;
        this->RSSI = t_rssi;
        this->Miss.clear();
        while(getline(ss, byte, ':'))
        {
                unsigned long tt=strtoul(byte.c_str(),NULL,16);
                for( int j=0;j<8;j++ ){
                    if(!( (unsigned char)( tt >> j )  & ( 0x1 ) ))
                            this->Miss.push_back(this->SSN + index*8 + j );
                    /* cout<<j+index*8<<" "<<( (tt>>j)&(0x1 ) )<<" "; */
                }
                index++;
        }

}

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////BlkACK_stat /////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
BlkACK_stat::BlkACK_stat(string s)
{
        mAddr = s;
        mACKs.clear();
        mvector_Loss.clear();
        mACK_airtime.clear();
        mAMPDU_mean = 0.0;
        mLoss = 0.0;
        mMPDU_num = 0;
        mAirtime = 0.0;
        mPkt_Size = 0;
        mFREQ = 0;
        mRSSI_mean = -100;
        mTime_delta = 0.0;
        mAMPDU_tuple.clear();
        mRate = 0.0;
}
void BlkACK_stat::addACK(BlkACK* b)
{
        mACKs.push_back(b);
}
string BlkACK_stat::getAddr()
{
       return mAddr; 
}
                
bool BlkACK_stat::parse_AMPDU()
{
        uint16_t t_len=0;
        uint16_t t_len_miss=0;
        if(mACKs.size()>1){
                //The Blk ACK vector has more than 1 acks, 
                //then we need consider the relationship between the current one and previous one
                if(mACKs.back()->Miss.size()>0){
                        t_len_miss = set_diff(mACKs.back()->Miss,mACKs[mACKs.size()-2]->Miss);
                        /* //Current blk ack indicates loss */
                        /* vector<uint16_t> t_diff; */
                        /* t_diff = set_diff(mACKs[mACKs.size()-2]->Miss,mACKs.back()->Miss); */
                        /* t_len_miss = t_diff.size(); */  
                        /* Debug */
                        /* cout<<" t_len under loss "<<t_len_miss<<" "<<endl; */

                        if(mACKs[mACKs.size()-2]->Miss.size() < 1){
                                mvector_Loss.push_back(t_len_miss);
                        }

                }

                /* Compute the SSN distance. */
                if(mACKs.back()->SSN < mACKs[mACKs.size()-2]->SSN){
                        t_len = mACKs.back()->SSN + 4096 - mACKs[mACKs.size()-2]->SSN;
                }else{
                        t_len = mACKs.back()->SSN - mACKs[mACKs.size()-2]->SSN;
                }
                t_len += set_diff(mACKs[mACKs.size()-2]->Miss,mACKs.back()->Miss);

                /* Abnormal case hard filter */
                if(t_len > 64){
                        /* cout<<" error t_len > 64 "<<t_len<<endl; */
                        t_len = 1;
                }

                t_len_miss = min(t_len, t_len_miss);
                
                /* mACKs.back()->line->print_fields(); */
                /* cout<<t_len<<" "<<t_len_miss<<endl; */

        }
        else{
                return false;
        }

        /* As we set the display filter to only show the non-data packets, we can use the time_delta_displayed metric to measure */
        /* the time gap of the ACK distancing from previous non-data packet. The gap might help infer the data rate. */
        float time_delta = 0.0;
        float t_ack_gap = 1000*atof(mACKs.back()->line->get_field(Line_cont::F_TIME_DELTA).c_str());
        float pre_own_ack = 1000*( mACKs.back()->line->getTime() - mACKs[mACKs.size()-2]->line->getTime());
        bool if_continue = abs(t_ack_gap-pre_own_ack) < 0.001;
        //TODO: The threshold need to be double checked.
        //For Lixing Fri 03 Feb 2017 02:02:51 PM EST.
        
        /* t_ack_gap = max(t_ack_gap,(float)0.048); */
        if(t_len  > 0)
                time_delta = t_ack_gap/float(t_len) ; // convert into millisecond.
        /* time_delta = max(time_delta,(float)0.016); */

        /* The variable name mBAMPDU means AMPDU based on BlkACK. */
        mAMPDU_tuple.push_back(make_tuple(t_len,t_len_miss,mACKs.back()->RSSI,time_delta,if_continue));

        /* report_pkt(); */

        return true;

}
void BlkACK_stat::report_pkt()
{
        if(mAMPDU_tuple.size() > 0){
                printf("%-5s %10.6f  %-16s %4d %4d %3d %6.3f\n",
                                "PKT", //level
                                mACKs.back()->line->getTime(),//pkt time
                                mAddr.c_str(),  //addr
                                get<0>( mAMPDU_tuple.back() ),  //AI:A-MPDU Intensity
                                get<1>( mAMPDU_tuple.back() ),  //loss
                                get<2>( mAMPDU_tuple.back() ),  //RSSI
                                get<3>( mAMPDU_tuple.back() )  //blockACK gap
                      );
        } 
}

void BlkACK_stat::calc_stats()
{
        int sum = 0, n = 0, RSSI_sum = 0, loss_sum = 0 ;
        float sum_time_delat = 0.0;
        mAMPDU_max = 0;
        if(mAMPDU_tuple.size()>0){
                for(vector<tuple<uint16_t,uint16_t,int,float,bool> >::iterator it = mAMPDU_tuple.begin();it!=mAMPDU_tuple.end();++it){
                        sum += get<0>(*it);
                        loss_sum += get<1>(*it);
                        RSSI_sum += get<2>(*it);
                        mAMPDU_max = max(mAMPDU_max,get<0>(*it));
                        if( get<0>(*it) > 0 ) sum_time_delat += get<3>(*it)*get<0>(*it);
                        n++;
                        
                }
                if(n > 0){
                        mAMPDU_mean = sum/float(n);
                        mRSSI_mean =(int) RSSI_sum/float(n);
                        mTime_delta = sum_time_delat/float(sum);
                }
                mMPDU_num = sum;
                /* Deal with loss */
                mLoss = loss_sum;
                /* Didn't use this metric so far */
                mAirtime = sum_time_delat;
                /* Get the frequency. */
                mFREQ = atoi(mACKs[0]->line->get_field(Line_cont::F_FREQ ).c_str());

        }
}

void BlkACK_stat::addRTS_airtime(float f)
{
        mAirtime += f;
}
void BlkACK_stat::add_ACK_airtime(float f)
{
        mACK_airtime.push_back(f);
}
void BlkACK_stat::calc_rate()
{
        if(mTime_delta > 0.001 && mMPDU_num > 10){
                /* mAMPDU_max = min((int)max((float)mAMPDU_max,MAX_TRANS_TIME/mTime_delta_median),BITMAP_LEN); */
                mRate =  MTU*8/float(mTime_delta*1000);
        }
        else
                mRate = 0;
}
float BlkACK_stat::getLoss_flow()
{
        return mLoss;
}
float BlkACK_stat::getGap_mean_flow()
{
        return mTime_delta;
}

float BlkACK_stat::getAMPDU_mean()
{
        return mAMPDU_mean;
}

uint16_t BlkACK_stat::getAMPDU_max_flow()
{
        return mAMPDU_max;
}

uint16_t BlkACK_stat::getN_MPDU_flow()
{
        return mMPDU_num;
}

float BlkACK_stat::getAirTime_flow()
{
        
        return mAirtime;
}
void BlkACK_stat::report_flow()
{
        
        printf("%-5s %-16s %4d %6.3f %6.3f %6.3f %6.3f %6.3f %4d\n",
                        "FLOW", //level
                        mAddr.c_str(),  //addr
                        mMPDU_num,  //number of MPDUs
                        mAMPDU_mean, //mean of AI
                        mLoss,  //mean of loss per A-MPDU
                        mTime_delta,  //mean blockACK gap
                        mAirtime,  //minimum blockACK gap
                        getRate_flow(),  //Transmission
                        mRSSI_mean //RSSI
              );
        /* this->clean_mem_flow(); */
}

void BlkACK_stat::clean_mem_flow()
{
        
        for(auto it:mACKs)
                delete it;
        mAMPDU_tuple.clear();
        mvector_Loss.clear();
        mACK_airtime.clear();
}
int BlkACK_stat::getRSSI_flow()
{
        return mRSSI_mean;     
}
float BlkACK_stat::getAMPDU_mean_flow()
{
        return mAMPDU_mean;
}
float BlkACK_stat::getRate_flow()
{
        calc_rate();
        return mRate;
}

int BlkACK_stat::set_diff(vector<uint16_t>& a,vector<uint16_t>& b)
{
        
        /* The new method of calculating set difference. */
        vector<uint16_t> diff;
        set_difference(a.begin(),a.end(),b.begin(),b.end(),inserter(diff,diff.begin()));
        /* cout<<"claculate set_diff result "<<diff.size()<<endl; */

        return diff.size();
}
        








