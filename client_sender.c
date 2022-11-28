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

int calcDecodeLength(const char* input){
    int len = strlen(input);
    int padding = 0;
    if(input[len-1] == '=' && input[len-2] == '='){
        padding = 2;
    }else if(input[len-1] == '='){
        padding = 1;
    }
    return (len * 3) / 4 - padding;
}

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a string to base64
    BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;

	return (0); //success
}

int Base64Decode(char* b64message, char** buffer, size_t* length){ //Decodes a base64 encoded string
    BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
    printf("length: %d | decodeLen: %d", length, decodeLen);
	// assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	return (0); //success
}


int main(int argc, char *argv[])
{
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in their_addr;
    int sockfd;
    int newfd;
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
        }else{
            bzero(buf, sizeof(buf));
            while((buf[n++] = getchar()) != '\n');
        }
        if ((numbytes = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
            perror("talker: sendto");
            exit(1);
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
            bzero(buf, sizeof buf);
            if((numbytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, &addr_len) == -1)){
                perror("recvfrom");
                exit(1);
            }
            strcpy(password, buf);
            printf("This is your password %s\n", password);
            printf("Connection will reset in 5 seconds\n");
            for(int i = 5; i > 0; i--){
                printf("%d\n", i);
                sleep(1);
            }
            break;
        }
    }

    if(firstTimeUser){
        freeaddrinfo(servinfo);
        close(sockfd);

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
            }else{
                bzero(buf, sizeof(buf));
                while((buf[n++] = getchar()) != '\n');
            }
            if ((numbytes = sendto(newfd, buf, sizeof(buf), 0, (struct sockaddr*) &their_addr, addr_len) == -1)) {
                perror("talker: sendto");
                exit(1);
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
