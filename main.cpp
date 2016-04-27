//
// Created by Erica Braunschweig, braune, on 4/25/16.
//
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#define USERAGENT "HTMLGET 1.1"
#define BUFFERSIZE 1024
#define USERAGENT "HTMLGET 1.1"

int tmpres;
//=================================================================================================================

char *build_get_query(char *host, char *page)
{
    char *query;
    char *getpage = page;

    std::string input = "GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";
    char *tpl = new char[input.length() + 1];
    strcpy(tpl, input.c_str());

    if(getpage[0] == '/'){
        getpage = getpage + 1;
        fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
    }
    // -5 is to consider the %s %s %s in tpl and the ending \0
    query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)-5);
    sprintf(query, tpl, getpage, host, USERAGENT);
    return query;
}

//=================================================================================================================

int main(int argc, char *argv[]) {
    int sockfd, ret;
    struct addrinfo ai_hints;
    struct addrinfo *ai_results, *j;

    //=============================================================================================================
    /* Get url and parse it*/
    std::string URL = argv[1];

    std::string url_prefix;
    std::string host;
    std::string port;
    std::string path;

    //Get URL Prefix
    unsigned int i = 0;
    for (i = 0; i < URL.length(); ++i) {

        if ((URL[i] == '/') && (URL[i + 1] == '/')) {
            i = i + 2;
            break;
        }

        if(i == URL.length() - 1) {
            i = 0;
            break;
        }
        if (URL[i] != ':') {
           url_prefix += URL[i];
        }
    }

    std::cout << "\n\n\n" << URL << "\n";
    while(i < URL.length()) {

        //get path
        if (URL[i] == '/') {

            while(i < URL.length()) {
                path += URL[i];
                ++i;
            }
        }

        //get port
        else if (URL[i] == ':') {
            ++i;
            while(i < URL.length() && URL[i] != '/') {
                port += URL[i];
                ++i;
            }
            --i;
        }

        //host
        else {
            host += URL[i];
        }
        ++i;
    }

    if (port.length() == 0 && url_prefix == "http") {
        port = "80";
    }

    else if (port.length() == 0 && url_prefix == "https") {
        port = "443";
    }

    std::cout << "URL PREFIX: \t" << url_prefix << "\n";
    std::cout << "HOST: \t\t" << host << "\n";
    std::cout << "PORT: \t\t" << port << "\n";
    std::cout << "PATH: \t\t" << path << "\n\n\n";
    //=============================================================================================================
    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_STREAM;
    ai_hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;

    ret = getaddrinfo(host.c_str(), port.c_str(), &ai_hints, &ai_results);

    if (ret != 0) {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(ret));
        return 1;
    }

    for (j = ai_results; j != NULL; j = j->ai_next) {
        /* create TCP socket */
        sockfd = socket(j->ai_family, j->ai_socktype, 0);
        if (sockfd == -1) {
            continue;
        }

        if(connect(sockfd, j->ai_addr, j->ai_addrlen) != -1) {
            break;
        }

        close(sockfd);
    }

    char *host_c = new char[host.length() + 1];
    strcpy(host_c, host.c_str());

    char *path_c = new char[path.length() + 1];
    strcpy(path_c, path.c_str());

    char * get = build_get_query(host_c, path_c);

    //Send the query to the server
    unsigned int sent = 0;
    while(sent < strlen(get))
    {
        tmpres = send(sockfd, get+sent, strlen(get)-sent, 0);
        if(tmpres == -1){
            perror("Can't send query");
            exit(1);
        }
        sent += tmpres;
    }


    //now it is time to receive the page
    char buf[BUFFERSIZE];
    memset(buf, 0, sizeof(buf));
    int htmlstart = 0;
    char * htmlcontent;

    while((tmpres = recv(sockfd, buf, BUFFERSIZE, 0)) > 0){

        if(htmlstart == 0) {
            htmlcontent = strstr(buf, "\r\n\r\n");
            if(htmlcontent != NULL){
                htmlstart = 1;
                htmlcontent += 4;
            }
        }
        else{
            buf[BUFFERSIZE] = '\0';
            htmlcontent = buf;

        }
        if(htmlstart){
            write(0, htmlcontent, BUFFERSIZE);
        }
        memset(buf, 0, tmpres);

    }

    if(tmpres < 0)
    {
        perror("Error receiving data");
    }

    exit(0);
}

//=================================================================================================================
