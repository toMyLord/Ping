//
// Created by mylord on 2019/9/26.
//

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

    printf("PING %s (%s) %d(%d) bytes of data.\n", input_domain.c_str(),
            backup_ip.c_str(), PACK_SIZE - 8, PACK_SIZE + 24);
}

unsigned short Ping::CalculateCksum(char * send_pack, int pack_size){

}

int Ping::GeneratePacket()
{
    int pack_size;
    struct icmp * icmp_pointer;
    struct timeval * time_pointer;

    //将发送的char[]类型的send_pack直接强制转化为icmp结构体类型，方便修改数据
    icmp_pointer = (struct icmp *)send_pack;

    //type为echo类型且code为0代表回显应答（ping应答）
    icmp_pointer->icmp_type = ICMP_ECHO;
    icmp_pointer->icmp_code = 0;
    icmp_pointer->icmp_cksum = 0;           //计算校验和之前先要将校验位置0
    icmp_pointer->icmp_seq = send_pack_num; //用send_pack_num作为ICMP包序列号
    icmp_pointer->icmp_id = getpid();       //用进程号作为ICMP包标志

    pack_size = PACK_SIZE;

    //将icmp结构体中的数据字段直接强制类型转化为timeval类型，方便将Unix时间戳赋值给icmp_data
    time_pointer = (struct timeval *)icmp_pointer->icmp_data;

    gettimeofday(time_pointer, NULL);

    icmp_pointer->icmp_cksum = CalculateCksum(send_pack, pack_size);

    return pack_size;
}

void Ping::SendPacket() {
    int pack_size = GeneratePacket();

    if((sendto(sock_fd, send_pack, pack_size, 0, (const struct sockaddr *)&send_pack, sizeof(send_pack))) < 0){
        fprintf(stderr, "Sendto error:%s \n\a", strerror(errno));
        exit(1);
    }

    this->send_pack_num++;
}