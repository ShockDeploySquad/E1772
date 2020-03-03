//
//  main.cpp
//  Network
//
//  Created by shan on 2020/2/28.
//  Copyright © 2020 Terwal. All rights reserved.
//

#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include "TowerSerial.h"
#include <string.h>
#include <fstream>
#include <time.h>
#include <thread>



void* text_output(void* args)
{
    int fd = *(int*)args;
    long rlen;
    time_t now_time=time(NULL);
    char buffer[1000];
    memset(buffer, 0x0, 100 * sizeof(char));
    int lenbuffer[5];
    while(1)
    {
        while(1)
        {
           rlen = read(fd, buffer, 1000);
           
           if(rlen > 0)break;
        }
        
        if(buffer[0]=='\0')continue;
        
       
       
        now_time=time(NULL);

        tm*  t_tm = localtime(&now_time);
           
        std::cout << "[RECV " << t_tm->tm_year+1900 << "-" << t_tm->tm_mon+1 << "-" << t_tm->tm_mday << " " << t_tm->tm_hour << ":" << t_tm->tm_min << ":" << t_tm->tm_sec << "]";
        
        printf(" [SENT %c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c] ",buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5],buffer[6],buffer[7],buffer[8],buffer[9],buffer[10],buffer[11],buffer[12],buffer[13]);
        
        
        
        for(int i=14;;i++)
        {
            if(buffer[i]=='\0')break;
            printf("%c",buffer[i]);
 
        }
        std::cout  << std::endl;
               
        memset(buffer, 0, 100 * sizeof(char));
        memset(lenbuffer, 0x0, 3 * sizeof(int));
           
    }
    
    
    
    
    
    return 0;
}

void* text_input(void* tran)
{
    char Inputbuffer[800];
    char buffer[1000];
    int fd = *(int*)tran;
    std::stringstream ss;
    long wlen = 1;
    std::cin.sync();
    std::cin.getline(Inputbuffer,800);
    memset(Inputbuffer,0,800*sizeof(char));
    std::cout << "连接完成！\n";
    std::cout << "\n";
    while(1)
    {
        
        std::cin.getline(Inputbuffer,800);
        
        
        time_t now_time=time(NULL);

        tm*  t_tm = localtime(&now_time);
 
        std::cout << "[SENT " << t_tm->tm_year+1900 << "-" << t_tm->tm_mon+1 << "-" << t_tm->tm_mday << " " << t_tm->tm_hour << ":" << t_tm->tm_min << ":" << t_tm->tm_sec << "] " << Inputbuffer << std::endl;
        
        
        
        
        
        //Define package
        buffer[0]=((t_tm->tm_year+1900)/1000+48);
        buffer[1]=(((t_tm->tm_year+1900)/100)%10+48);
        buffer[2]=(((t_tm->tm_year+1900)/10)%10+48);
        buffer[3]=((t_tm->tm_year+1900)%10+48);
        buffer[4]=(((t_tm->tm_mon+1)/10)%10+48);
        buffer[5]=((t_tm->tm_mon+1)%10+48);
        buffer[6]=(((t_tm->tm_mday)/10)%10+48);
        buffer[7]=((t_tm->tm_mday)%10+48);
        buffer[8]=(((t_tm->tm_hour)/10)%10+48);
        buffer[9]=((t_tm->tm_hour)%10+48);
        buffer[10]=(((t_tm->tm_min)/10)%10+48);
        buffer[11]=((t_tm->tm_min)%10+48);
        buffer[12]=(((t_tm->tm_sec)/10)%10+48);
        buffer[13]=((t_tm->tm_sec)%10+48);
        
        for(int i=0;;i++)
        {
            if(Inputbuffer[i]=='\0')
                break;
            buffer[i+14]=Inputbuffer[i];
        }
        
        
        wlen = write(fd,buffer,strlen(buffer));
        
        if (wlen == 0)
        {
            printf("写入错误：%ld, %d\n", wlen, errno);
        }
        
        memset(buffer,0,1000*sizeof(char));
        memset(Inputbuffer,0,800*sizeof(char));
        tcdrain(fd);
        
        
        
    }

    
    return 0;
}

int main()
{
    printf("Salutations.请输入虚拟串口或实际串口的路径。\n应该像是 /dev/ptyXX or /dev/ttyXX\n");
    char portname[20];
    int fd;
    
    std::cin >> portname;
    std::cout << "等待连接中......\n" ;
    std::cout << "\n" ;
    fd = open(portname, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        printf("未能打开%s: %s\n", portname, strerror(errno));
        return -1;
    }
    int *tran = &fd;
    

    set_interface_attribs(fd, B115200);   //配置串口。
    
    
    
    pthread_t tids[2];
    
    int ret = pthread_create(&tids[0], NULL, text_output, tran);
    if (ret != 0)
        
    {
        std::cout << "输出线程错误：" << ret << std::endl;
    }
    
    
    ret = pthread_create(&tids[1], NULL, text_input, tran);
    if (ret != 0)
        
    {
        std::cout << "读取线程错误：" << ret << std::endl;
    }
    pthread_exit(NULL);
    
}
