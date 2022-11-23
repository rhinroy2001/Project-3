/*
** talker.c -- a datagram "client" demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>

#define MAXBUFLEN 1000


int main(int argc, char *argv[])
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    socklen_t addr_len;
    int rv;
    int numbytes;
    char ip[50];
    char port[50];
    char* ipToken;
    char* temp;
    char* portToken;
    char* portNumber;
    char* ipAddress;
    char buf[MAXBUFLEN];
    int n = 0;
    char username[20];
    char numEmails[20];
    char request[100];
    struct hostent *hostname;
    struct in_addr addr;
    FILE *fp;
    char path[40];
    char confirmation[10];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;

    FILE* file = fopen(argv[1], "r");
    if(file == NULL){
    	perror("Cannot open the file");
	    exit(1);
    }
    fscanf(file, "%s %s", ip, port);
    portToken = strtok(port, "=");
    while(portToken != NULL){
        temp = portToken;
        portToken = strtok(NULL, "=");
        if(portToken == NULL){
            portNumber = temp;
        }
    }
    ipToken = strtok(ip, "=");
    while(ipToken != NULL){
        temp = ipToken;
        ipToken = strtok(NULL, "=");
        if(ipToken == NULL){
            ipAddress = temp;
        }
    }

    if ((rv = getaddrinfo(ipAddress, portNumber, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        return 2;
    }
        for(;;){
            bzero(buf, sizeof(buf));
            printf("Enter your username: ");
            n = 0;
            while((buf[n++] = getchar()) != '\n');
            char* ptr = strchr(buf, '\n');
            if(ptr){
                *ptr = '\0';
            }
            strcpy(username, buf);       
        
            bzero(buf, sizeof(buf));
            printf("Enter the number of emails to download: ");
            n = 0;
            while((buf[n++] = getchar()) != '\n');
            strcpy(numEmails, buf);


            inet_aton(ipAddress, &addr);
            hostname = gethostbyaddr(&addr, sizeof(addr), AF_INET);

            sprintf(request, "GET/db/%s/HTTP/1.1\nServer: <%s>\nCount: %s", username, hostname->h_name, numEmails);
            printf("%s\n", request);
            printf("Confirm the request is correct: y/n ");

            bzero(buf, sizeof(buf));
            n = 0;
            while((buf[n++] = getchar()) != '\n');
            if(strncmp("y", buf, 1) == 0){
                rv = mkdir(username, 0755);
                if ((numbytes = sendto(sockfd, request, sizeof(request), 0, p->ai_addr, p->ai_addrlen)) == -1) {
                    perror("talker: sendto");
                    exit(1);
                }

                bzero(buf, sizeof(buf));
                addr_len = sizeof(ipAddress);
                if((numbytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) ipAddress, &addr_len) == -1)){
                    perror("recvfrom");
                    exit(1);
                }

                printf("%s\n", buf);

                sprintf(path, "%s/request.txt", username);
                fp = fopen(path, "w");
                if(fp != NULL){
                    for(int i = 0; i < MAXBUFLEN; i++){
                        fputc(buf[i], fp);
                    }
                }else{
                    printf("Error creating file");
                }
                fclose(fp);  
                break;
            }else{
                // repeat process
            }
        }


    freeaddrinfo(servinfo);
    
    close(sockfd);

    return 0;
}