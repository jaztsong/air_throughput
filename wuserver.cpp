//
//  Weather update server in C++
//  Binds PUB socket to tcp://*:5556
//  Publishes random weather updates
//
//  Olivier Chamoux <olivier.chamoux@fr.thalesgroup.com>
//
#include <zmq.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#if (defined (WIN32))
#include <zhelpers.hpp>
#endif

#define within(num) (float) ((float) num * random () / (RAND_MAX + 1.0))

int main () {

    //  Prepare our context and publisher
    zmq::context_t* context =  new zmq::context_t (1);
    zmq::socket_t* publisher = new zmq::socket_t(*context, ZMQ_PUB);
    /* publisher.bind("tcp://*:5556"); */
    publisher->bind("tcp://*:5556");				// Not usable on Windows.

    //  Initialize random number generator
    srandom ((unsigned) time (NULL));
    while (1) {

        float throughput;
        //  Get values that will fool the boss
        throughput = within (150) ;

        //  Send message to all subscribers
        zmq::message_t message(20);
        snprintf ((char *) message.data(), 20 ,
        	"%f", throughput);
        publisher->send(message);
        usleep(20000);

    }
    return 0;
}
