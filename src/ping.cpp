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

    this->min_time = 0;
    this->max_time = 0;
    this->sum_time = 0;
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

    //设置send_addr结构体
    send_addr.sin_family = AF_INET;

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
            backup_ip.c_str(), PACK_SIZE - 8, PACK_SIZE + 20);

    gettimeofday(&first_send_time, NULL);
}

unsigned short Ping::CalculateCksum(unsigned short * send_pack, int pack_size){
    int check_sum = 0;              //校验和
    int nleft = pack_size;          //还未计算校验和的数据长度
    unsigned short * p = send_pack; //用来做临时指针
    unsigned short temp;            //用来处理字节长度为奇数的情况

    while(nleft > 1){
        check_sum += *p++;          //check_sum先加以后，p的指针才向后移
        nleft -= 2;
    }

    //奇数个长度
    if(nleft == 1){
        //利用char类型是8个字节，将剩下的一个字节压入unsigned short（16字节）的高八位
        *(unsigned char *)&temp = *(unsigned char *)p;
        check_sum += temp;
    }

    check_sum = (check_sum >> 16) + (check_sum & 0xffff);   //将之前计算结果的高16位和低16位相加
    check_sum += (check_sum >> 16);                         //防止上一步也出现溢出
    temp = ~check_sum;              //temp是最后的校验和

    return temp;
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
    icmp_pointer->icmp_seq = send_pack_num + 1; //用send_pack_num作为ICMP包序列号
    icmp_pointer->icmp_id = getpid();       //用进程号作为ICMP包标志

    pack_size = PACK_SIZE;

    //将icmp结构体中的数据字段直接强制类型转化为timeval类型，方便将Unix时间戳赋值给icmp_data
    time_pointer = (struct timeval *)icmp_pointer->icmp_data;

    gettimeofday(time_pointer, NULL);

    icmp_pointer->icmp_cksum = CalculateCksum((unsigned short *)send_pack, pack_size);

    return pack_size;
}

void Ping::SendPacket() {
    int pack_size = GeneratePacket();

    if((sendto(sock_fd, send_pack, pack_size, 0, (const struct sockaddr *)&send_addr, sizeof(send_addr))) < 0){
        fprintf(stderr, "Sendto error:%s \n\a", strerror(errno));
        exit(1);
    }

    this->send_pack_num++;
}

//要对收到的IP数据包去IP报头操作，校验ICMP，提取时间戳
int Ping::ResolvePakcet(int pack_size) {
    int icmp_len, ip_header_len;
    struct icmp * icmp_pointer;
    struct ip * ip_pointer = (struct ip *)recv_pack;
    double rtt;
    struct timeval * time_send;

    ip_header_len = ip_pointer->ip_hl << 2;                     //ip报头长度=ip报头的长度标志乘4
    icmp_pointer = (struct icmp *)(recv_pack + ip_header_len);  //pIcmp指向的是ICMP头部，因此要跳过IP头部数据
    icmp_len = pack_size - ip_header_len;                       //ICMP报头及ICMP数据报的总长度

    //收到的ICMP包长度小于报头
    if(icmp_len < 8) {
        printf("received ICMP pack lenth:%d(%d) is error!\n", pack_size, icmp_len);
        lost_pack_num++;
        return -1;
    }
    if((icmp_pointer->icmp_type == ICMP_ECHOREPLY) &&
        (backup_ip == inet_ntoa(recv_addr.sin_addr)) &&
        (icmp_pointer->icmp_id == getpid())){

        time_send = (struct timeval *)icmp_pointer->icmp_data;

        if((recv_time.tv_usec -= time_send->tv_usec) < 0) {
            --recv_time.tv_sec;
            recv_time.tv_usec += 10000000;
        }

        rtt = (recv_time.tv_sec - time_send->tv_sec) * 1000 + (double)recv_time.tv_usec / 1000.0;

        if(rtt > (double)max_wait_time * 1000)
            rtt = max_time;

        if(min_time == 0 | rtt < min_time)
            min_time = rtt;
        if(rtt > max_time)
            max_time = rtt;

        sum_time += rtt;

        printf("%d byte from %s : icmp_seq=%u ttl=%d time=%.1fms\n",
               icmp_len,
               inet_ntoa(recv_addr.sin_addr),
               icmp_pointer->icmp_seq,
               ip_pointer->ip_ttl,
               rtt);

        recv_pack_num++;
    } else{
        printf("throw away the old package %d\tbyte from %s\ticmp_seq=%u\ticmp_id=%u\tpid=%d\n",
               icmp_len, inet_ntoa(recv_addr.sin_addr), icmp_pointer->icmp_seq,
               icmp_pointer->icmp_id, getpid());

        return -1;
    }

}

void Ping::RecvPacket() {
    int recv_size, fromlen;
    fromlen = sizeof(struct sockaddr);

    while(recv_pack_num + lost_pack_num < send_pack_num) {
        fd_set fds;
        FD_ZERO(&fds);              //每次循环都必须清空FD_Set
        FD_SET(sock_fd, &fds);      //将sock_fd加入集合

        int maxfd = sock_fd + 1;
        struct timeval timeout;
        timeout.tv_sec = this->max_wait_time;
        timeout.tv_usec = 0;

        //使用select实现非阻塞IO
        int n = select(maxfd, NULL, &fds, NULL, &timeout);

        switch(n) {
            case -1:
                fprintf(stderr, "Select error:%s \n\a", strerror(errno));
                exit(1);
            case 0:
                printf("select time out, lost packet!\n");
                lost_pack_num++;
                break;
            default:
                //判断sock_fd是否还在集合中
                if(FD_ISSET(sock_fd, &fds)) {
                    //还在集合中则说明收到了回显的数据包
                    if((recv_size = recvfrom(sock_fd, recv_pack, sizeof(recv_pack),
                            0, (struct sockaddr *)&recv_addr, (socklen_t *)&fromlen)) < 0) {
                        fprintf(stderr, "packet error(size:%d):%s \n\a", recv_size, strerror(errno));
                        lost_pack_num++;
                    } else{
                        //收到了可能合适的数据包
                        gettimeofday(&recv_time, NULL);

                        ResolvePakcet(recv_size);
                    }
                }
                break;
        }
    }
}

void Ping::statistic() {
    double total_time;
    struct timeval final_time;
    gettimeofday(&final_time, NULL);

    if((final_time.tv_usec -= first_send_time.tv_usec) < 0) {
        --final_time.tv_sec;
        final_time.tv_usec += 10000000;
    }
    total_time = (final_time.tv_sec - first_send_time.tv_sec) * 1000 + (double)final_time.tv_usec / 1000.0;

    printf("\n--- %s ping statistics ---\n",input_domain.c_str());
    printf("%d packets transmitted, %d received, %.0f%% packet loss, time %.0f ms\n",
            send_pack_num, recv_pack_num, (double)(send_pack_num - recv_pack_num) / (double)send_pack_num,
            total_time);
    printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", min_time, (double)sum_time / recv_pack_num, max_time);


}