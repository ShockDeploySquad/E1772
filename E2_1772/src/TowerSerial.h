//
//  TowerSerial.h
//  Network
//
//  Created by shan on 2020/3/3.
//  Copyright © 2020 Terwal. All rights reserved.
//

#ifndef TowerSerial_h
#define TowerSerial_h

int set_interface_attribs(int fd, int BaudRate)
{
    struct termios tty;
    
    cfsetospeed(&tty, (speed_t)BaudRate);
    cfsetispeed(&tty, (speed_t)BaudRate);

    //串口配置。两边一样就能通。除了阻塞模式似乎比较重要。
    
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;

    
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty.c_oflag &= ~OPOST;

    //取数据的时间间隔和数据触发量。
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 1;
    tcsetattr(fd, TCSANOW, &tty);
        tcflush(fd, TCIOFLUSH); //这东西干嘛用的我还不知道。
    return 0;
}

#endif /* TowerSerial_h */
