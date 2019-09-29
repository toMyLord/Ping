//
// Created by mylord on 2019/9/26.
//

#ifndef MYPING_PING_H
#define MYPING_PING_H

#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define PACK_SIZE 32                //最小的ICMP数据包大小，8字节的ICMP包头，16字节的DATA，其中DATA是timeval结构体

class Ping {
private:
    std::string input_domain;       //用来存储通过main函数的参数传入的域名或者ip
    std::string backup_ip;          //通过输入的域名或者ip转化成为的ip备份

    int sock_fd;

    int max_wait_time;              //最大等待时间

    int send_pack_num;              //发送的数据包数量
    int recv_pack_num;              //收到的数据包数量
    int lost_pack_num;              //丢失的数据包数量

    struct sockaddr_in send_addr;   //发送到目标的套接字结构体
    struct sockaddr_in recv_addr;   //接受来自目标的套接字结构体

    char send_pack[PACK_SIZE];      //用于保存发送的ICMP包
    char recv_pack[PACK_SIZE + 20];      //用于保存接收的ICMP包

    struct timeval first_send_time; //第一次发送ICMP数据包时的UNIX时间戳
    struct timeval recv_time;       //接收ICMP数据包时的UNIX时间戳

    double min_time;
    double max_time;
    double sum_time;


    int GeneratePacket();
    int ResolvePakcet(int pack_szie);

    unsigned short CalculateCksum(unsigned short * send_pack, int pack_size);

public:
    Ping(const char * ip, int max_wait_time);
    ~Ping();

    void CreateSocket();

    void SendPacket();
    void RecvPacket();

    void statistic();
};


#endif //MYPING_PING_H
