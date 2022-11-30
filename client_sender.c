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
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>


#define MAXDATASIZE 1000

 char *Base64Encode(const unsigned char* input, int length) {
    int predictedLength = 4 * ((length + 2) / 3);
    char* output = (char *)(calloc(predictedLength + 1, 1));
    int outputLength = EVP_EncodeBlock((unsigned char *)(output), input, length);
    assert(predictedLength == outputLength);
    return output;
}

char *Base64Decode(char* input, int length){ //Decodes a base64 encoded string
    int predictedLength = 3 * length / 4;
    char* output = (unsigned char *)(calloc(predictedLength + 1, 1));
    int outputLength = EVP_DecodeBlock(output, (unsigned char *)(input), length);
    assert(predictedLength == outputLength);
    return output;
}


int main(int argc, char *argv[])
{
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in their_addr;
    int sockfd;
    int rv;
    int numbytes;
    char buf[MAXDATASIZE];
    char ip[50];
    char port[50];
    char* ipToken;
    char* temp;
    char* portToken;
    char* portNumber;
    char* ipAddress;
    int n;
    int j;
    int k;
    socklen_t addr_len;
    char password[20];
    char* base64DecodeOutput;
    bool firstTimeUser = false;
    size_t decodeLength;
    int newfd;
    char* base64EncodeOutput;
    char pbuf[MAXDATASIZE];
    int passwordSize = 5;

    // read in port number and IP address from file
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

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;

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

    while((buf[n++] = getchar()) != '\n');

    if ((numbytes = sendto(sockfd, buf, sizeof(buf), 0, p->ai_addr, p->ai_addrlen)) == -1) {
        perror("talker: sendto");
        exit(1);
    }
    bzero(buf, sizeof(buf));
    addr_len = sizeof(their_addr);
    if((numbytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, &addr_len) == -1)){
        perror("recvfrom");
        exit(1);
    }
    printf("%s\n", buf);

    


    for(;;){
        n = 0;
        j = 0;
        k = 0;

        if(strncmp(buf, "354 OK", 6) == 0){
            while(1){
                buf[n] = getchar();
                if(n > 0){
                    j = n - 1;
                }
                if(n > 1){
                    k = j - 1;
                }
                if((buf[n] == '\n') && (buf[j] == '.') && (buf[k] == '\n')){
                    break;
                }
                n++;
            }
            if ((numbytes = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
                perror("talker: sendto");
                exit(1);
            }
        }else if(strncmp(buf, "334 cGFzc3dvcmQ6", 16) == 0){
            bzero(buf, sizeof(buf));
            while((buf[n++] = getchar()) != '\n');
            buf[strcspn(buf, "\n")] = '\0';
            base64EncodeOutput = Base64Encode(buf, passwordSize);
            if ((numbytes = sendto(sockfd, base64EncodeOutput, strlen(base64EncodeOutput), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
            perror("talker: sendto");
            exit(1);
            }
            
        }else{
            bzero(buf, sizeof(buf));
            while((buf[n++] = getchar()) != '\n');
            if ((numbytes = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
                perror("talker: sendto");
                exit(1);
            }
        }
        
        bzero(buf, sizeof(buf));
        if((numbytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, &addr_len) == -1)){
            perror("recvfrom");
            exit(1);
        }
        printf("%s\n", buf);
        if(strncmp(buf, "221 BYE", 7) == 0){
            break;
        }
        if(strncmp(buf, "330", 3) == 0){
            firstTimeUser = true;
            bzero(pbuf, sizeof pbuf);
            if((numbytes = recvfrom(sockfd, pbuf, sizeof(pbuf), 0, (struct sockaddr*) &their_addr, &addr_len) == -1)){
                perror("recvfrom");
                exit(1);
            }
            strcpy(password, pbuf);
            printf("encrypted password: %s", password);
            base64DecodeOutput = Base64Decode(password, strlen(password));
            printf("This is your password %s\n", base64DecodeOutput);
            printf("Connection will reset in 5 seconds\n");
            for(int i = 5; i > 0; i--){
                sleep(1);
                printf("%d\n", i);
            }
            break;
        }
    }
    freeaddrinfo(servinfo);
    close(sockfd);

    if(firstTimeUser){
        n = 0;
        if ((rv = getaddrinfo(ipAddress, portNumber, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            return 1;
        }

        // loop through all the results and make a socket
        for(p = servinfo; p != NULL; p = p->ai_next) {
            if ((newfd = socket(p->ai_family, p->ai_socktype,
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

        while((buf[n++] = getchar()) != '\n');

        if ((numbytes = sendto(newfd, buf, sizeof(buf), 0, p->ai_addr, p->ai_addrlen)) == -1) {
            perror("talker: sendto");
            exit(1);
        }
        bzero(buf, sizeof(buf));
        addr_len = sizeof(their_addr);
        if((numbytes = recvfrom(newfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, &addr_len) == -1)){
            perror("recvfrom");
            exit(1);
        }
        printf("%s\n", buf);

        


        for(;;){
            n = 0;
            j = 0;
            k = 0;

            if(strncmp(buf, "354 OK", 6) == 0){
                while(1){
                    buf[n] = getchar();
                    if(n > 0){
                        j = n - 1;
                    }
                    if(n > 1){
                        k = j - 1;
                    }
                    if((buf[n] == '\n') && (buf[j] == '.') && (buf[k] == '\n')){
                        break;
                    }
                    n++;
                }
                if ((numbytes = sendto(newfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
                    perror("talker: sendto");
                    exit(1);
                }
            }else if(strncmp(buf, "334 cGFzc3dvcmQ6", 16) == 0){
                bzero(buf, sizeof(buf));
                while((buf[n++] = getchar()) != '\n');
                buf[strcspn(buf, "\n")] = '\0';
                base64EncodeOutput = Base64Encode(buf, 7);
                printf("base64EncodeOutput: %s\n", base64EncodeOutput);
                if ((numbytes = sendto(sockfd, base64EncodeOutput, strlen(base64EncodeOutput), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
                    perror("talker: sendto");
                    exit(1);
                }  
            }else{
                bzero(buf, sizeof(buf));
                while((buf[n++] = getchar()) != '\n');
                if ((numbytes = sendto(newfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
                    perror("talker: sendto");
                    exit(1);
                }
            }
            bzero(buf, sizeof(buf));
            if((numbytes = recvfrom(newfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, &addr_len) == -1)){
                perror("recvfrom");
                exit(1);
            }
            printf("%s\n", buf);
            if(strncmp(buf, "221 BYE", 7) == 0){
                break;
            }
        }
    }else{
        freeaddrinfo(servinfo);
        close(sockfd);
    }

    

    return 0;
}
