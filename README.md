## Purpose
The code is built to compute real-time airtime as well as the air throughput from a WiFi adapter in the monitor mode.

## Description
It compute the real-time stats and broadcast on a zmq tcp socket (5556).

## Note
The code utilizes the wifipcap packet ([https://github.com/simsong/tcpflow/tree/master/src/wifipcap]) for online packet decoding.


## Update
