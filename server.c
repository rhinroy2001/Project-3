/*
** listener.c -- a datagram sockets "server" demo
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
#include <pthread.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>

#define MAXBUFLEN 1000

struct client_info{
    char host[INET_ADDRSTRLEN];
    int port;
};

struct client_info get_client_info(struct sockaddr_in *sa){
    struct client_info info = {};
    info.port = ntohs(sa->sin_port);
    inet_ntop(sa->sin_family, &(sa->sin_addr), info.host, INET_ADDRSTRLEN);

    return info;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

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


void* communicateWithSender(char* smtpPortNumber){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in their_addr;
    socklen_t addr_len;
    char buf[MAXBUFLEN];
    int rv;
    int numbytes;
    char* clientMessage;
    char* replyCode;
    char* helo;
    char* mailFrom;
    char* rcptTo;
    char* data;
    char* parse;
    char* parseToken;
    char* temp;
    FILE *fp;
    int num = 1;
    char path[40];
    char recipient[40];
    char dateTime[40];
    char from[40];
    char to[40];
    char s[INET_ADDRSTRLEN];
    time_t now = time(&now);
    struct tm *ptm = gmtime(&now);
    int portNumberi = atoi(smtpPortNumber);
    char portNumber[40];
    char* mailFromMessage = "MAIL FROM";
    char* rcptToMessage = "RCPT TO";
    char* emptyMessage = "";
    char* dataMessage = "DATA";
    char host[256];
    struct hostent *host_entry;
    char* ip;
    char* prevMessage;
    bool authenticated = false;
    char passwordWithSalt[13];
    char* salt = "SNOWY22";
    char* base64EncodeOutput;
    char* base64DecodeOutput;
    time_t t;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char passwordNoSalt[5];
    int passwordSize = 5;
    char username[100];
    char userPassCombo[100];
    bool firstTimeUser = true;
    char* storedUsername;
    char* storedPassword;
    char passwordResponse[100];
    char enteredPassword[20];
    char* passwordAndSalt;
    size_t decodeLength;
    char fileBuf[100];
    char moniker[100];
    char* passwordNoSaltEncrypted;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, smtpPortNumber, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        exit(1);
    }

    gethostname(host, sizeof(host));
    host_entry = gethostbyname(host);
    ip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));

    freeaddrinfo(servinfo);

    addr_len = sizeof(their_addr);

    rv = mkdir("db", 0755);
    rv = mkdir("db/passwords", 0755);
    
    while(1){
        portNumberi++;
        sprintf(portNumber, "%d", portNumberi);
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }
        struct client_info client = get_client_info(&their_addr);
        if(!fork()){
            if ((rv = getaddrinfo(NULL, portNumber, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                exit(1);
            }
            int newfd = socket(AF_INET, SOCK_DGRAM, 0);
            bind(newfd, p->ai_addr, p->ai_addrlen);
            if(strncmp("HELO", buf, 4) == 0){
                helo = buf;
                parse = strtok(helo, " ");
                parse = strtok(NULL, " ");
                if(strncmp(parse, "447f22.edu", 10) == 0){
                    replyCode = "250 OK";
                    prevMessage = "HELO";
                    bzero(buf, sizeof(buf));
                    sprintf(buf, "%s %s greets %s", replyCode, ip, client.host);
                    if((rv = sendto(newfd, buf, sizeof(buf), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", buf);
                }else{
                    replyCode = "501 DOMAIN NOT SUPPORTED";
                    prevMessage = "";
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);
                }
            }else{
                replyCode = "500 command unrecognized";
                prevMessage = "";
                if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                    perror("sendto");
                    exit(1);
                }
                printf("%s\n", replyCode);
            }
             for(;;){
                bzero(buf, sizeof(buf));
                if ((numbytes = recvfrom(newfd, buf, MAXBUFLEN-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                    perror("recvfrom");
                    exit(1);
                }
                if(strncmp("AUTH", buf, 4) == 0){
                    replyCode = "334 dXN1cm5hbWU6\nEnter username:";
                    prevMessage = "AUTH"; 
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);
                }else if(strncmp("AUTH", prevMessage, 4) == 0){
                    buf[strcspn(buf, "\n")] = '\0';
                    strcpy(username, buf);
                    prevMessage = "password"; 
                    fp = fopen("db/passwords/.user_pass", "r");
                    if(fp != NULL){
                        bzero(fileBuf, sizeof fileBuf);
                        while(fgets(fileBuf, sizeof fileBuf, fp)){
                            storedUsername = strtok(fileBuf, ":");
                            printf("username: %s | storedUsername: %s\n", username, storedUsername);
                            if(strcmp(username, storedUsername) == 0){
                                firstTimeUser = false;
                                break;
                            }
                        }
                        fclose(fp);
                    }
                    if(firstTimeUser){
                        bzero(passwordNoSalt, sizeof passwordNoSalt);
                        srand((unsigned) time(&t));
                        for(int i = 0; i < passwordSize; i++){
                            int key = rand() % (int) (sizeof charset - 1);
                            passwordNoSalt[i] = charset[key];
                        }
                        passwordNoSalt[passwordSize] = '\0';
                        sprintf(passwordWithSalt, "%s%s", salt, passwordNoSalt);
                        bzero(path, sizeof path);
                        sprintf(path, "db/passwords/.user_pass");
                        sprintf(userPassCombo, "%s:%s\n", username, passwordWithSalt);
                        fp = fopen(path, "a");
                        fputs(userPassCombo, fp);
                        fclose(fp);
                        replyCode = "330 PASSWORD CREATED";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }   
                        if((rv = sendto(newfd, passwordNoSalt, strlen(passwordNoSalt), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }else{
                        replyCode = "334 cGFzc3dvcmQ6\nEnter password:";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }else if(strncmp("password", prevMessage, 8) == 0){
                    strcpy(enteredPassword, buf);
                    bzero(passwordWithSalt, sizeof passwordWithSalt);
                    sprintf(passwordWithSalt, "SNOWY22%s", enteredPassword);
                    bzero(path, sizeof path);
                    sprintf(path, "db/passwords/.user_pass");
                    fp = fopen(path, "r");
                    if(fp != NULL){
                        bzero(fileBuf, sizeof fileBuf);
                        while(fgets(fileBuf, sizeof fileBuf, fp)){
                            storedUsername = strtok(fileBuf, ":");
                            storedPassword = strtok(NULL, ":");
                            if((strcmp(passwordWithSalt, storedPassword) == 0) && (strcmp(username, storedUsername) == 0)){
                                authenticated = true;
                            }
                        }
                        fclose(fp);
                    }
                    // we are here work on authentication
                    if(authenticated){
                        replyCode = "235 USER AUTHENTICATED";
                        prevMessage = "HELO";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                        break;
                    }else{
                        replyCode = "535 USER AUTHENTICATION FAILED\nEnter password:";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }else{
                    replyCode = "500 command unrecognized";
                    prevMessage = "";
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);
                }
             }

            for(;;){

                replyCode = "";
                bzero(buf, sizeof(buf));
                if ((numbytes = recvfrom(newfd, buf, MAXBUFLEN-1 , 0,
                    (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                    perror("recvfrom");
                    exit(1);
                }
                if(strncmp("HELO", buf, 4) == 0 && strcmp("", prevMessage) == 0){
                    helo = buf;
                    parse = strtok(helo, " ");
                    parse = strtok(NULL, " ");
                    if(strncmp(parse, "447f22.edu", 10) == 0){
                        replyCode = "250 OK";
                        prevMessage = "HELO";
                        bzero(buf, sizeof(buf));
                        sprintf(buf, "%s %s greets %s", replyCode, ip, client.host);
                        if((rv = sendto(newfd, buf, sizeof(buf), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", buf);
                    }else{
                        replyCode = "501 DOMAIN NOT SUPPORTED";
                        prevMessage = "";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }else if(strncmp("MAIL FROM", buf, 9) == 0 && authenticated && strncmp("HELO", prevMessage, 4) == 0){
                    mailFrom = buf;
                    parse = strtok(mailFrom, "<");
                    while(parse != NULL){
                        temp = parse;
                        parse = strtok(NULL, "<");
                        if(parse == NULL){
                            break;
                        }
                    }
                    parse = strtok(temp, "@");
                    strcpy(moniker, parse);
                    sprintf(from, "From: <%s@447f22.edu>\n", parse);
                    parse = strtok(NULL, "@");
                    if((strncmp(parse, "447f22.edu>", 11) == 0) && (strcmp(moniker, username) == 0)){
                        prevMessage = "MAIL FROM";
                        replyCode = "250 OK";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }else if(strcmp(moniker, username) != 0){
                        replyCode = "535 USERNAME AND MONIKER DO NOT MATCH";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }else{
                        replyCode = "501 DOMAIN NOT SUPPORTED";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }else if(strncmp("RCPT TO", buf, 7) == 0){
                    if(strncmp("MAIL FROM", prevMessage, 10) == 0){
                        rcptTo = buf;
                        parse = strtok(rcptTo, "<");
                        while(parse != NULL){
                            temp = parse;
                            parse = strtok(NULL, "<");
                            if(parse == NULL){
                                break;
                            }
                        }
                        parse = strtok(temp, "@");
                        strcpy(recipient, parse);
                        sprintf(path, "db/%s", parse);
                        sprintf(to, "To: <%s@447f22.edu>\n", recipient);
                        parse = strtok(NULL, "@");
                        rv = mkdir(path, 0755);
                        if(strncmp(parse, "447f22.edu>", 11) == 0){
                            prevMessage = "RCPT TO";
                            replyCode = "250 OK";
                            if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                                perror("sendto");
                                exit(1);
                            }
                            printf("%s\n", replyCode);
                        }else{
                            replyCode = "501 DOMAIN NOT SUPPORTED";
                            if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                                perror("sendto");
                                exit(1);
                            }
                            printf("%s\n", replyCode);
                        }
                    }else{
                        replyCode = "503 BAD SEQUENCE OF COMMANDS";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }else if(strncmp("DATA", buf, 4) == 0){
                    if(strncmp("RCPT TO", prevMessage, 8) == 0){
                        prevMessage = "DATA";
                        replyCode = "354 OK";
                        data = buf;
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }else{
                        replyCode = "503 BAD SEQUENCE OF COMMANDS";
                        if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }else if(strncmp(prevMessage, "DATA", 4) == 0){
                    bzero(path, sizeof path);
                    prevMessage = "HELO";
                    replyCode = "250 OK\n";
                    sprintf(path, "db/%s/%d.email", recipient, num);
                    num++;
                    sprintf(dateTime, "Date: %s", asctime(ptm));
                    fp = fopen(path, "w");
                    fputs(dateTime, fp);
                    fputs(from, fp);
                    fputs(to, fp);
                    for(int i = 0; i < MAXBUFLEN; i++){
                        fputc(buf[i], fp);
                    }
                    fclose(fp);
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);

                }else if(strncmp("HELP", buf, 4) == 0){
                    prevMessage = "";
                    replyCode = "214 OK\nHELO - HELO followed by email domain\nMAIL FROM - MAIL FROM: <email address>\nRCPT TO - RCPT TO: <email address>\nDATA - DATA then write text ending <CRLF>.<CRLF>\n";
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);
                }else if(strncmp("QUIT", buf, 4) == 0){
                    replyCode = "221 BYE";
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);
                }else{
                    replyCode = "500 command unrecognized";
                    if((rv = sendto(newfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                        perror("sendto");
                        exit(1);
                    }
                    printf("%s\n", replyCode);
                }
            }
            close(newfd);
        }
    }
    
    close(sockfd);
}

void* commincateWithReceiver(char* httpPortNumber){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    int rv;
    int numbytes;
    char buf[MAXBUFLEN];
    char s[INET_ADDRSTRLEN];
    int n = 0;
    char* replyCode;
    char dateTime[40];
    char path[40];
    char db[10];
    char recipient[20];
    char* request;
    char* parse;
    char* get;
    char* server;
    char* count;
    char temp[20];
    char host[256];
    char hostname[258];
    int emailCount;
    time_t now = time(&now);
    struct tm *ptm = gmtime(&now);
    
    

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP   

    if ((rv = getaddrinfo(NULL, httpPortNumber, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        exit(1);
    }

    const int so_reuseaddr = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(int));

    freeaddrinfo(servinfo);

    addr_len = sizeof(their_addr); 
    
    for(;;){
        gethostname(host, sizeof(host));
        sprintf(hostname, "<%s>", host);
        replyCode = "";
        bzero(buf, sizeof(buf));
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }
        
        if(strncmp("GET", buf, 3) == 0){
            request = buf;
            char prev[20];
            parse = strtok(request, "\n");
            while(parse != NULL){
                if(strncmp("GET", parse, 3) == 0){
                    get = parse;
                }
                if(strncasecmp("Server", parse, 6) == 0){
                    server = parse;
                }
                if(strncasecmp("count", parse, 5) == 0){
                    count =  parse;
                }
                parse = strtok(NULL, "\n");
            }

            parse = strtok(get, "/");
            while(parse != NULL){
                strcpy(temp, parse);
                if(strncmp("db", prev, 2) == 0){
                    strcpy(recipient, temp);
                    break;
                }
                if(strncmp("db", temp, 2) == 0){
                    strcpy(db, temp);
                    strcpy(prev, temp);
                }
                parse = strtok(NULL, "/");
            }

            parse = strtok(server, " ");
            parse = strtok(NULL, " ");
            server = parse;

            parse = strtok(count, " ");
            parse = strtok(NULL, " ");
            count = parse;
            emailCount = atoi(count);
            sprintf(dateTime, "%s", asctime(ptm));
            printf("Server: %s Hostname: %s", server, hostname);
            if(strcmp(server, hostname) == 0){
                bzero(buf, sizeof(buf));
                
                sprintf(buf, "HTTP/1.1 200 OK\nLast-Modified: %s\nCount: %d\nContent-Type: text/plain\n\n", dateTime, emailCount);
                for(int i = 1; i <= emailCount; i++){
                    int n = 0;
                    sprintf(path, "%s/%s/%d.email", db, recipient, i);
                    char fbuf[1000];
                    FILE *fp;
                    fp = fopen(path, "r");
                    if(fp != NULL){
                        do{
                            fbuf[n] = fgetc(fp);
                            if(feof(fp)){
                                break;
                            }
                            n++;
                        }while(1);
                        fclose(fp);
                        strcat(buf, fbuf);
                    }else{
                        replyCode = "404 FILE DOES NOT EXIST\n";
                        if((rv = sendto(sockfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                            perror("sendto");
                            exit(1);
                        }
                        printf("%s\n", replyCode);
                    }
                }
                if((rv = sendto(sockfd, buf, MAXBUFLEN, 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                    perror("sendto");
                    exit(1);
                }
                printf("%s\n", buf);
            }else{
                replyCode = "400 BAD REQUEST\n";
                if((rv = sendto(sockfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                    perror("sendto");
                    exit(1);
                }
                printf("%s\n", replyCode);
            }
        }else{
            replyCode = "400 BAD REQUEST\n";
            if((rv = sendto(sockfd, replyCode, strlen(replyCode), 0, (struct sockaddr *)&their_addr, addr_len)) == -1){
                perror("sendto");
                exit(1);
            }
            printf("%s\n", replyCode);
        }
    }
    close(sockfd);
}

int main(int argc, char* argv[])
{
    char smtpPort[50];
    char httpPort[50];
    char* temp;
    char* smtpPortToken;
    char* smtpPortNumber;
    char* httpPortToken;
    char* httpPortNumber;
    char* ipAddress;
    int count = 0;
    pthread_t tid[10];

    FILE* file = fopen(argv[1], "r");
    if(file == NULL){
    	perror("Cannot open the file");
	    exit(1);
    }
    fscanf(file, "%s %s", smtpPort, httpPort);
    smtpPortToken = strtok(smtpPort, "=");
    while(smtpPortToken != NULL){
        temp = smtpPortToken;
        smtpPortToken = strtok(NULL, "=");
        if(smtpPortToken == NULL){
            smtpPortNumber = temp;
        }
    }
    httpPortToken = strtok(httpPort, "=");
    while(httpPortToken != NULL){
        temp = httpPortToken;
        httpPortToken = strtok(NULL, "=");
        if(httpPortToken == NULL){
            httpPortNumber = temp;
        }
    }

    // char* base64EncodeOutput, *text="Hello World";
    // Base64Encode(text, strlen(text), &base64EncodeOutput);
    // printf("Output (base64): %s\n", base64EncodeOutput);

    // char* base64DecodeOutput;
    // size_t test;
    // Base64Decode(base64EncodeOutput, &base64DecodeOutput, &test);
    // printf("Output: %s %d\n", base64DecodeOutput, test);
    // return 0;
    

    if(!fork()){
        communicateWithSender(smtpPortNumber);
    }
    commincateWithReceiver(httpPortNumber);

    return 0;
}