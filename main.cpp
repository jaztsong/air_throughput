#include <iostream>
#include <stdlib.h>
#include "airtime_meas.h"

using namespace std;

/**
 * usage: airtime_meas <dev> <window_size#ms> <update_time#ms>
 */
int main(int argc, char **argv) {
        if (argc != 5){
                cerr<<" Error input. Usage: airtime_meas <dev> <window_size#ms> <chunk_window#ms> <update_time#ms>"<<endl;
                return 1;
        }

        Wifipcap *wcap = new Wifipcap(argv[1], true);
        Airtime_Meas* t_measuer = new Airtime_Meas();
        t_measuer->setAnalyzer(new Analyzer(atoi(argv[2]),atoi(argv[3])));
        t_measuer->startAnalyze(atoi(argv[4]));
        wcap->Run(t_measuer);
        return 0;
}
