# file:   wifi_parser.c
# date:   Wed Jun 21 11:40:00 EST 2006
# Author: Doug Madory, Jihwang Yeo

ALL = airtime_meas
# SRCS = parser.cpp TimeVal.cpp util.cpp crc32.cpp cpack.cpp
# OBJS = $(patsubst %.cpp,%.o,$(SRCS))

# Compiler and flags
CXX = g++
CXXFLAGS = -g -Wall
LFLAGS = -lzmq -lpcap -std=gnu++11 -pthread 

all: $(ALL)

# wifipcap.a: $(OBJS)
# 	ar rc $@ $(OBJS)

airtime_meas: main.cpp analyzer.cpp airtime_meas.h analyzer.h
	$(CXX) $(CXXFLAGS)  -o $@ main.cpp analyzer.cpp ./wifipcap/wifipcap.a $(LFLAGS) 

# parser.o: parser.cpp parser.h
# 	$(CXX) $(CXXFLAGS)  -c parser.cpp
clean:
	rm -f $(ALL) *.o
