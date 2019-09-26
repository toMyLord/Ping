#include "src/ping.h"

int main(int argc, char * argv[]) {
    Ping ping(argv[1], 1);
    ping.CreateSocket();
    while(1)
    {
        ping.SendPacket();
        ping.RecvPacket();
        sleep(1);
    }

}