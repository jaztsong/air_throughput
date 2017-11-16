# file:   wifi_parser.c
# date:   Wed Jun 21 11:40:00 EST 2006
# Author: Doug Madory, Jihwang Yeo

ALL = wifipcap.a sample
SRCS = parser.cpp TimeVal.cpp util.cpp crc32.cpp cpack.cpp
OBJS = $(patsubst %.cpp,%.o,$(SRCS))

# Compiler and flags
CXX = g++
CXXFLAGS = -g
LFLAGS = -lpcap

LIBS = -lpcap

all: $(ALL)

wifipcap.a: $(OBJS)
	ar rc $@ $(OBJS)

sample: sample.cpp wifipcap.a
	$(CXX) $(CXXFLAGS)  -o $@ sample.cpp wifipcap.a $(LFLAGS) 

clean:
	rm -f $(ALL) *.o
