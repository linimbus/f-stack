#define _GNU_SOURCE  

#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

/* See feature_test_macros(7) */
#include <pthread.h>
#include <sched.h> 

#include "ss_api.h"


#define MAX_EVENTS     512

#define BUFF_MAX_LEN   4096

int g_sockfd = -1;

struct ss_buff * g_buff_m;

int g_stat_send_times    = 0;
size_t g_stat_send_size  = 0;
int g_stat_recv_times    = 0;
size_t g_stat_recv_size  = 0;

void * stat_display(void * arg) 
{
    int send_times = 0;
    int recv_times = 0;
    size_t send_size = 0;
    size_t recv_size = 0;

    send_times = g_stat_send_times;
    recv_times = g_stat_recv_times;
    send_size  = g_stat_send_size;
    recv_size  = g_stat_recv_size;
    
    for (;;)
    {
        sleep(5);

        if (( g_stat_send_times - send_times) != 0 )
        {
            printf(" stat send times %d \n", (g_stat_send_times - send_times)/5 );
            printf(" stat send size  %lu \n", (g_stat_send_size  - send_size )/5 );
        }

        if (( g_stat_recv_times - recv_times ) != 0 )
        {
            printf(" stat recv times %d \n", (g_stat_recv_times - recv_times)/5 );
            printf(" stat recv size  %lu \n", (g_stat_recv_size  - recv_size )/5 );
        }

        send_times = g_stat_send_times;
        recv_times = g_stat_recv_times;
        send_size  = g_stat_send_size;
        recv_size  = g_stat_recv_size;
    }
}

void * server_socket_process(void * arg)
{
    int ret;
    struct epoll_event ev;
    struct epoll_event events[MAX_EVENTS];
    int epfd;

    epfd = ss_epoll_create(0);
    if ( epfd < 0 )
    {
        printf("epoll create failed\n");
        exit(1);
    }

    ev.data.fd = g_sockfd;
    ev.events  = EPOLLIN;
    ret = ss_epoll_ctl(epfd, EPOLL_CTL_ADD, g_sockfd, &ev);
    if (ret < 0) 
    {
        printf("ss_epoll_ctl failed\n");
        exit(1);
    }

    for (;;)
    {
        /* Wait for events to happen */
        int nevents = ss_epoll_wait(epfd,  events, MAX_EVENTS, -1);
        int i;

        for ( i = 0; i < nevents ; ++i ) 
        {
            /* Handle new connect */
            if (events[i].data.fd == g_sockfd) 
            {
                while (1) 
                {
                    int nclientfd = ss_accept(g_sockfd, NULL, NULL);
                    if (nclientfd < 0) 
                    {
                        break;
                    }
        
                    printf("accept client fd %d.\n", nclientfd);
        
                    /* Add to event list */
                    ev.data.fd = nclientfd;
                    ev.events  = EPOLLIN | EPOLLOUT | EPOLLERR;
                    if (ss_epoll_ctl(epfd, EPOLL_CTL_ADD, nclientfd, &ev) != 0) 
                    {
                        printf("epoll_ctl failed:%d, %s\n", errno, strerror(errno));
                        break;
                    }
                }
            } 
            else
            { 
                char buf[BUFF_MAX_LEN];
                size_t writelen = 0;
                size_t readlen  = 0;

                if (events[i].events & EPOLLERR ) 
                {
                    /* Simply close socket */
                    ss_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ss_close(events[i].data.fd);
        
                    printf("connect %d close.\n", events[i].data.fd);
                } 

                if (events[i].events & EPOLLIN )
                {
                    readlen = ss_read( events[i].data.fd, buf, sizeof(buf));
                    if ( readlen > 0 )
                    {
                        g_stat_recv_times++;
                        g_stat_recv_size += readlen;
                        ss_buff_write(g_buff_m, buf, readlen);
                    }
                    if ( readlen == 0 ) 
                    {
                        ss_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                        ss_close( events[i].data.fd);
                        printf("connect %d close.\n", events[i].data.fd);
                    }
                }

                if (events[i].events & EPOLLOUT )
                {
                    readlen = ss_buff_read(g_buff_m, buf, sizeof(buf));
                    if ( readlen > 0 )
                    {
                        writelen = ss_write( events[i].data.fd, buf, readlen);
                        g_stat_send_times++;
                        g_stat_send_size += writelen;

                        if ( writelen == 0 ) 
                        {
                            ss_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                            ss_close( events[i].data.fd);
                            printf("connect %d close.\n", events[i].data.fd);
                        }
                    }
                }
            }
        }
    }
}

void * client_socket_process(void * arg)
{
    int ret;
    struct epoll_event ev;
    struct epoll_event events[MAX_EVENTS];
    int epfd;

    epfd = ss_epoll_create(0);
    if ( epfd < 0 )
    {
        printf("epoll create failed\n");
        exit(1);
    }

    ev.data.fd = g_sockfd;
    ev.events  = EPOLLIN | EPOLLOUT | EPOLLERR;
    ret = ss_epoll_ctl(epfd, EPOLL_CTL_ADD, g_sockfd, &ev);
    if (ret < 0) 
    {
        printf("ss_epoll_ctl failed\n");
        exit(1);
    }

    for (;;)
    {
        /* Wait for events to happen */
        int nevents = ss_epoll_wait(epfd,  events, MAX_EVENTS, -1);
        int i;

        for ( i = 0; i < nevents ; ++i ) 
        {
            char buf[BUFF_MAX_LEN];
            ssize_t writelen = 0;
            ssize_t readlen  = 0;

            if (events[i].events & EPOLLERR ) 
            {
                /* Simply close socket */
                ss_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                ss_close(events[i].data.fd);
                printf("connect %d close.\n", events[i].data.fd);
            } 

            if (events[i].events & EPOLLIN )
            {
                readlen = ss_read( events[i].data.fd, buf, sizeof(buf));
                if ( readlen > 0 )
                {
                    g_stat_recv_times++;
                    g_stat_recv_size += readlen;
                }

                if ( readlen == 0 ) 
                {
                    ss_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ss_close( events[i].data.fd);
                    printf("connect %d close.\n", events[i].data.fd);
                }
            }

            if (events[i].events & EPOLLOUT )
            {
                //readlen = sizeof(buf);
                //memset(buf, 'a', readlen);
                
                readlen = sprintf(buf, "helloworld! (client %d)\n", g_stat_send_times );

                writelen = ss_write( events[i].data.fd, buf, readlen);
                if ( writelen == 0 ) 
                {
                    ss_epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    ss_close( events[i].data.fd);
                    printf("connect %d close.\n", events[i].data.fd);
                }

                if ( writelen > 0 )
                {
                    g_stat_send_times++;
                    g_stat_send_size += writelen;
                }
            }
        }
    }
}


int server_init(int argc, char * argv[])
{
    int ret;
    int i;
    short port;
    struct epoll_event ev;

    pthread_t tid;

    g_buff_m = ss_buff_alloc();
    
    g_sockfd = ss_socket(AF_INET, SOCK_STREAM, 0);
    if (g_sockfd < 0)
    {
        printf("socket failed\n");
        exit(1);
    }

    printf("sockfd:%d\n", g_sockfd);
    for ( i = 0 ; i < argc ; i++ )
    {
        if ( 0 == strcmp(argv[i],"port") )
        {
            port = (short)atoi(argv[i+1]);
        }
    }

    printf("port  :%d\n", port);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = ss_bind(g_sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) 
    {
        printf("bind failed\n");
        exit(1);
    }

    ret = ss_listen(g_sockfd, MAX_EVENTS);
    if (ret < 0) 
    {
        printf("listen failed! ret=%d\n", ret);
        exit(1);
    }
    
    server_socket_process(NULL);

    return 0;
}


int client_init(int argc, char * argv[])
{
    int ret;
    int i;
    
    short port;
    char * addr;

    pthread_t tid;

    g_buff_m = (struct ss_buff *)malloc(sizeof(struct ss_buff));
    
    g_sockfd = ss_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_sockfd < 0)
    {
        printf("socket failed\n");
        exit(1);
    }
        
    printf("sockfd:%d\n", g_sockfd);
    
    for ( i = 0 ; i < argc ; i++ )
    {
        if ( 0 == strcmp(argv[i],"port") )
        {
            port = (short)atoi(argv[i+1]);
        }

        if ( 0 == strcmp(argv[i],"addr") )
        {
            addr = argv[i+1];
        }
    }

    printf("connect -> %s:%d\n", addr, port);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);

    ret = inet_aton(addr, &my_addr.sin_addr);
    if (ret == 0)
    {
        printf("inet_aton failed! \n");
        ss_close(g_sockfd);
        exit(1);
    }

    while(1)
    {
        sleep(1);
        
        ret = ss_connect(g_sockfd, (const struct sockaddr *)&my_addr, sizeof(my_addr));
        if ( ret == 0 )
        {
            break;
        }

        if (errno == EISCONN)
        {
            break;
        }
        
        if (errno == EINTR)
        {
            continue;
        }

        if (errno != EINPROGRESS) 
        {
            printf("connect failed, errno: %d.\n", errno);
            ss_close(g_sockfd);
            exit(1);
        }
    }
    
    client_socket_process(NULL);

    return 0;
}

int g_argc = 0;
char ** g_argv;

void * main_cs(void * arg)
{
    int i;
    int flag = 0;
    pthread_t tid;
    int argc = g_argc;
    char ** argv = g_argv;
    cpu_set_t mask;

    sleep(2);

    CPU_ZERO(&mask);  
    for (i = 0; i < 16; i++) 
    {
        CPU_SET(i, &mask);  
    }

    pthread_setaffinity_np( pthread_self(), sizeof(mask), &mask );

    pthread_create(&tid, NULL, stat_display, NULL);

    for ( i = 0 ; i < argc ; i++ )
    {
        if ( 0 == strcmp(argv[i],"server") )
        {
            flag = 1;
        }

        if ( 0 == strcmp(argv[i],"client") )
        {
            flag = 0;
        }
    }

    if ( flag )
    {
        server_init(argc, argv);
    }
    else
    {
        client_init(argc, argv);
    }
}

int main(int argc, char * argv[])
{
    pthread_t tid;

    g_argc = argc;
    g_argv = argv;

    ss_init(argc, argv);

    pthread_create(&tid, NULL, main_cs, NULL);

    ss_run();
    
    return 0;
}

