//
//  main.cpp
//  FuriousPcap
//
//  Created by shan on 2020/3/22.
//  Copyright © 2020 Terwal. All rights reserved.
//

#include <iostream>
#include <pcap/pcap.h>
#include <time.h>
#include <pthread.h>
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
#include <string.h>
#include <fstream>
#include <time.h>
#include <thread>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#define WARNING_TRI 4096


char Error_Buffer_For_PCAP[PCAP_ERRBUF_SIZE];
int Return_Catcher;
char *Device_Name;

pcap_t *PCAP_Handle;
bpf_u_int32 mask; /* 执行嗅探的设备的网络掩码 */
bpf_u_int32 net; /* 执行嗅探的设备的IP地址 */
struct pcap_pkthdr PCAP_Header;
const u_char *PCAP_Packet;

FILE *CSV_File;

using namespace std;
fstream String_Stream;


typedef struct Flow_Indicator_IP
{
    unsigned int Ip1;
    unsigned int Ip2;
    unsigned int Ip3;
    unsigned int Ip4;
    int Flow = 0;
    Flow_Indicator_IP *Next;
}Flow_Indicator_IP;

typedef struct Flow_Indicator_MAC
{
    unsigned int MAC1;
    unsigned int MAC2;
    unsigned int MAC3;
    unsigned int MAC4;
    unsigned int MAC5;
    unsigned int MAC6;
    int Flow = 0;
    Flow_Indicator_MAC *Next;
}Flow_Indicator_MAC;

clock_t First_Time,Second_Time;

void Achieve_IP(Flow_Indicator_IP *ChainStart,unsigned int Ip1,unsigned int Ip2,unsigned int Ip3,unsigned int Ip4,int Flow)
{
    Flow_Indicator_IP *Pointer = ChainStart;
    while(1)
    {
        if(Pointer->Next == NULL)
        {
            Flow_Indicator_IP *NewNode = new Flow_Indicator_IP;
            Pointer->Next = NewNode;
            Pointer->Next->Ip1 = Ip1;
            Pointer->Next->Ip2 = Ip2;
            Pointer->Next->Ip3 = Ip3;
            Pointer->Next->Ip4 = Ip4;
            Pointer->Next->Flow = Flow;
            Pointer->Next->Next = NULL;
            
            break;
        }
        else if(Pointer->Next->Ip1 == Ip1 && Pointer->Next->Ip2 == Ip2 && Pointer->Next->Ip3 == Ip3 && Pointer->Next->Ip4 == Ip4 )
        {
            Pointer->Next->Flow += Flow;
            break;
        }
        else
        {
            Pointer = Pointer->Next;
            
        }
    }
}

void Achieve_MAC(Flow_Indicator_MAC *ChainStart,unsigned int MAC1,unsigned int MAC2,unsigned int MAC3,unsigned int MAC4,unsigned int MAC5,unsigned int MAC6,int Flow)
{
    Flow_Indicator_MAC *Pointer = ChainStart;
    while(1)
    {
        
        if(Pointer->Next == NULL)
        {
            Flow_Indicator_MAC *NewNode = new Flow_Indicator_MAC ;
            Pointer->Next = NewNode;
            Pointer->Next->MAC1 = MAC1;
            Pointer->Next->MAC2 = MAC2;
            Pointer->Next->MAC3 = MAC3;
            Pointer->Next->MAC4 = MAC4;
            Pointer->Next->MAC5 = MAC6;
            Pointer->Next->MAC5 = MAC6;
            Pointer->Next->Flow = Flow;
            Pointer->Next->Next = NULL;
            
            break;
        }
        
        else if(Pointer->Next->MAC1 == MAC1 && Pointer->Next->MAC2 == MAC2 && Pointer->Next->MAC3 == MAC3 && Pointer->Next->MAC4 == MAC4 && Pointer->Next->MAC5 == MAC5 && Pointer->Next->MAC6 == MAC6)
        {
            Pointer->Next->Flow += Flow;
            
            break;
        }
        
        else
        {
            Pointer = Pointer->Next;
        }
        
    }
}


void IP_Collect(Flow_Indicator_IP *ChainStart)
{
    Flow_Indicator_IP *Pointer = ChainStart->Next;
    while(Pointer != NULL)
    {
        cout << dec << Pointer->Ip1 << "." << Pointer->Ip2 << "." << Pointer->Ip3 << "." << Pointer->Ip4 << " :" << Pointer->Flow <<endl;
        Pointer -> Flow = 0;
        Pointer = Pointer->Next;
    }
}

void MAC_Collect(Flow_Indicator_MAC *ChainStart)
{
    Flow_Indicator_MAC *Pointer = ChainStart->Next;
    while(Pointer != NULL)
    {
        cout << hex << Pointer->MAC1 << "-" << Pointer->MAC2 << "-" << Pointer->MAC3 << "-" << Pointer->MAC4 << "-" << Pointer->MAC5  << "-" << Pointer->MAC6 << " :" << dec << Pointer->Flow <<endl;
        Pointer -> Flow = 0;
        Pointer = Pointer->Next;
    }
}




Flow_Indicator_IP *ChainStart_IP_Source = new Flow_Indicator_IP;
Flow_Indicator_IP *ChainStart_IP_Destination = new Flow_Indicator_IP;
Flow_Indicator_MAC *ChainStart_MAC_Source = new Flow_Indicator_MAC;
Flow_Indicator_MAC *ChainStart_MAC_Destination = new Flow_Indicator_MAC;


void PCAP_Callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int i;
    int length = 0 ;
    
    //26-29 源ip 30-33目标ip
    time_t Packet_Time = header->ts.tv_sec;
    char Packet_Time_String[64];
    strftime(Packet_Time_String, sizeof(Packet_Time_String), "%Y-%m-%d %H:%M:%S",localtime(&Packet_Time) );
    
    
    
    cout << Packet_Time_String << ",";
    String_Stream << Packet_Time_String << ",";
    
    
    i = 6;
    printf("%X",(unsigned int)packet[i]);
    String_Stream << hex << (unsigned int)packet[i];
    
    
    for( i = 7 ; i <= 11 ; i++ )
    {
        printf("-%X",(unsigned int)packet[i]);
        String_Stream << "-" << hex << (unsigned int)packet[i];
    }
    
    cout << ",";
    String_Stream << ",";
    
    i = 26;
    cout << dec << (unsigned int)packet[i];
    String_Stream << dec << (unsigned int)packet[i];
    
    for( i = 27 ; i <= 29 ; i++ )
    {
        cout << "." << (unsigned int)packet[i];
        String_Stream << "." << dec << (unsigned int)packet[i];
    }
    
    cout << ",";
    String_Stream << ",";
    
    i = 0;
    printf("%X",(unsigned int)packet[i]);
    String_Stream << hex << (unsigned int)packet[i];
    
    for( i = 1 ; i <= 5 ; i++ )
    {
        printf("-%X",(unsigned int)packet[i]);
        String_Stream << "-" << hex << (unsigned int)packet[i];
    }
    
    cout << ",";
    String_Stream << ",";
    
    i = 30;
    cout << dec <<(unsigned int)packet[i];
    String_Stream << dec << (unsigned int)packet[i];
    
    for( i = 31 ; i <= 33 ; i++ )
    {
        cout << "." << dec << (unsigned int)packet[i];
        String_Stream << "." << dec <<(unsigned int)packet[i];
        
    }
    
    cout << ",";
    String_Stream << ",";
    
    length = (unsigned int)packet[17] + ( 256 * (unsigned int)packet[16] );
    
    if(length >= WARNING_TRI)
    {
        cout << "Large Flow Detected!" << endl;
    }
    
    
    cout << length << endl;
    String_Stream << dec << length << endl;
    
    Achieve_MAC(ChainStart_MAC_Source,(unsigned int)packet[6],(unsigned int)packet[7],(unsigned int)packet[8],(unsigned int)packet[9],(unsigned int)packet[10],(unsigned int)packet[11],length);
    
    Achieve_IP(ChainStart_IP_Source, (unsigned int)packet[26], (unsigned int)packet[27], (unsigned int)packet[28], (unsigned int)packet[29], length);
    
    Achieve_MAC(ChainStart_MAC_Destination,(unsigned int)packet[0],(unsigned int)packet[1],(unsigned int)packet[2],(unsigned int)packet[3],(unsigned int)packet[4],(unsigned int)packet[5],length);
    
    Achieve_IP(ChainStart_IP_Destination, (unsigned int)packet[30], (unsigned int)packet[31], (unsigned int)packet[32], (unsigned int)packet[33], length);
    
    
    Second_Time = clock();
    if( Second_Time - 60000 >= First_Time)
    {
        First_Time = clock();
        cout << "By Source IP:" << endl;
        IP_Collect(ChainStart_IP_Source);
        
        cout << "By Source MAC:" << endl;
        MAC_Collect(ChainStart_MAC_Source);
        
        cout << "By Destination IP:" << endl;
        IP_Collect(ChainStart_IP_Destination);
        
        cout << "By Destination MAC:" << endl;
        MAC_Collect(ChainStart_MAC_Destination);
        
    }
    
    
}



















int main(int argc, const char * argv[]) {

    cout << "Furious P.C.A.P. Lauching!\n";
    cout << "Please wait warmly while we capturing packets" << endl;
    
    ChainStart_IP_Source->Next = NULL;
    ChainStart_MAC_Source->Next = NULL;
    ChainStart_IP_Destination->Next = NULL;
    ChainStart_MAC_Destination->Next = NULL;
    
    String_Stream.open("Log.csv",ios::app);
    
    Device_Name = pcap_lookupdev(Error_Buffer_For_PCAP);
    pcap_lookupnet(Device_Name, &net, &mask, Error_Buffer_For_PCAP);
    PCAP_Handle = pcap_open_live(Device_Name, 65535, true, 0, Error_Buffer_For_PCAP);
    
    
    First_Time = clock();
    
    pcap_loop(PCAP_Handle, -1, PCAP_Callback, NULL);
    
    pcap_close(PCAP_Handle);
    
    
    
    
    
    
    return 0;
}




