//
// Created by mylord on 2019/9/26.
//

#include <unistd.h>
#include "ping.h"
Ping::Ping(const char * ip, int max_wait_time){
    this->input_domain = ip;

    this->max_wait_time = max_wait_time < 3 ? max_wait_time : 3;

    this->send_pack_num = 0;
    this->recv_pack_num = 0;
    this->lost_pack_num = 0;
}

Ping::~Ping() {
    if(close(sock_fd) == -1) {
        fprintf(stderr, "Close socket error:%s \n\a", strerror(errno));
        exit(1);
    }
}

void Ping::CreateSocket(){
    struct protoent * protocol;             //获取协议用
    unsigned long in_addr;                  //用来保存网络字节序的二进制地址
    struct hostent host_info, * host_pointer; //用于gethostbyname_r存放IP信息
    char buff[2048];                         //gethostbyname_r函数临时的缓冲区，用来存储过程中的各种信息
    int errnop = 0;                         //gethostbyname_r函数存储错误码

    //通过协议名称获取协议编号
    if((protocol = getprotobyname("icmp")) == NULL){
        fprintf(stderr, "Get protocol error:%s \n\a", strerror(errno));
        exit(1);
    }

    //创建原始套接字，这里需要root权限，申请完成之后应该降权处理
    if((sock_fd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) == -1){
        fprintf(stderr, "Greate RAW socket error:%s \n\a", strerror(errno));
        exit(1);
    }

    //降权处理，使该进程的EUID，SUID的值变成RUID的值
    setuid(getuid());

    //判断用户输入的点分十进制的ip地址还是域名，如果是域名则将其转化为ip地址，并备份
    //inet_addr()将一个点分十进制的IP转换成一个长整数型数
    if((in_addr = inet_addr(input_domain.c_str())) == INADDR_NONE){
        //输入的不是点分十进制的ip地址
        if(gethostbyname_r(input_domain.c_str(), &host_info, buff, sizeof(buff), &host_pointer, &errnop)){
            //非法域名
            fprintf(stderr, "Get host by name error:%s \n\a", strerror(errno));
            exit(1);
        } else{
            //输入的是域名
            this->send_addr.sin_addr = *((struct in_addr *)host_pointer->h_addr);
        }
    } else{
        //输入的是点分十进制的地址
        this->send_addr.sin_addr.s_addr = in_addr;
    }

    //将ip地址备份下来
    this->backup_ip = inet_ntoa(send_addr.sin_addr);
}