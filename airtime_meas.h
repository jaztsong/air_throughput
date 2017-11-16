#include <iostream>
#include <stdlib.h>
#include <iomanip>
#include "./wifipcap/wifipcap.h"
#include "analyzer.h"
/* Translate Ethernet address, as seen in struct ether_header, to type MAC. */
static inline MAC ether2MAC(const uint8_t * ether)
{
        return MAC(ether);

}
class Airtime_Meas : public WifipcapCallbacks
{
        private:
                Analyzer* mAnalyzer;
                double pre_time;
                int mRSSI = -100;
                uint16_t mFREQ = 0;
                uint16_t mRate = 0;
        public:
                Airtime_Meas(){
                        pre_time = 0.0;
                        mRSSI = -100;
                        mFREQ = 0;
                        mRate = 0;
                }
                void setAnalyzer(Analyzer* p){
                        mAnalyzer = p;
                }
                void startAnalyze(uint16_t interval){
                        printf("Start Analyze.\n");
                        mAnalyzer->start_report(interval);
                }

                bool Check80211FCS() { return true; }
                /* void Handle80211CtrlBLKAck(const struct timeval& t, const ctrl_blk_ack_t* hdr) */
                /* { */
                        


                /* } */
                void HandleRadiotap(const struct timeval& t, radiotap_hdr *hdr, const u_char *rest, int len) {
                        /* std::cout<<"radiotap channel "<<hdr->channel<<std::endl; */
                        mRSSI = hdr->signal_dbm;
                        mRate = hdr->rate;
                        mFREQ = hdr->channel;
                }

                void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta, const u_char* ptr, int len, bool fcs_ok) {
                        std::ostringstream line_buffer;
                        char bitmap[100];

                        /* printf("Handle80211 %d\n",len); */
                        double time = t.tv_sec + t.tv_usec/1000000.0;
                        double delta_time = pre_time > 0.0?time - pre_time:0.0;
                        u_int16_t type_subtype = FC_TYPE(fc)*16+FC_SUBTYPE(fc);
                        if (type_subtype == 25){
                                int j=0;
                                for(int i=0;i<8;i++){
                                        if(i==7)
                                                j += sprintf(bitmap+j,"%02x",*(ptr+20+i));
                                        else
                                                j += sprintf(bitmap+j,"%02x:",*(ptr+20+i));

                                }
                        }
                        line_buffer<<std::fixed<<std::setprecision(6)<<time<<"|"<<delta_time<<"|"<<len<<"|"<<ether2MAC(ptr+10)<<"|"<<ether2MAC(ptr+4)<<"|"<<type_subtype<<"|"<<FC_TO_DS(fc)<<"|0|"<<mRSSI<<"|"<<mFREQ<<"|"<<mRate<< "|"<<EXTRACT_LE_16BITS(ptr+2)<<"|"<<( type_subtype != 25 ? "":std::to_string(  16*( *( ptr+19  )  ) + ( ( *(ptr+18)  )>>4  )  )  )<<"|"<<( type_subtype == 25?bitmap:"")  ;
                        /* printf("%s\n",line_buffer.str().c_str()); */
                        mAnalyzer->addPacket(line_buffer.str());
                        if(FC_TYPE(fc) != 2)
                                pre_time = time;
                }

};

