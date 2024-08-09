// CMakeProject1.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。


#include <iostream>
//
//  httpserver.h
//  http-server
//
//  Created by 刘云海 on 2022/10/28.
//


#include <stdio.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

//close()使用
#include <fcntl.h>//for open
#include <unistd.h>//for close

#include <openssl/ssl.h>
#include <openssl/err.h>


int rangeParser(char* range, int len);//尝试解析range字段

#define MAX_CACHE 1024
#define MAX_PENDING 5

#define HTTPHANDLE(NAME) http##NAME##Handle

#define HTTPHANDLEFUNC(NAME,...) int HTTPHANDLE(NAME)(void* inputHTTP,void* otherData,int otherLen,void* outputData){__VA_ARGS__}

#define HTTPREQUESTHANDLEFUNC(NAM,...) HTTPHANDLEFUNC(NAM,{  struct HTTPRequest* httpRequest =  (struct HTTPRequest*)inputHTTP;__VA_ARGS__})
#define HTTPRESPONSEHANDLEFUNC(NAM,...) HTTPHANDLEFUNC(NAM,{  struct HTTPResponse* httpResponse =  (struct HTTPResponse*)inputHTTP; __VA_ARGS__})

#define _LOG(...) {printf(__VA_ARGS__);}

#define _ERROR(...) {printf(__VA_ARGS__);exit(1);}
#define _ASSERT(...)  if(__VA_ARGS__){printf(#__VA_ARGS__);printf("failed!\n");exit(1);}

#define _FREEPTR(NAME) if(NAME!=NULL) {free(NAME);}

#define NONONEDATACPY(m,n) if (m != NULL) {sprintf(outData + strlen(outData), #n": %s\r\n", m);}

enum HTTPTYPE { HTTPGET=0, HTTPBASERESPONSE };

struct HTTPHandlePair{
    int (*handle)(void* inputHTTP, void* otherData, int otherLen, void* outputData);
};


struct HTTPRange {
    unsigned int from;
    unsigned int to;
    unsigned int fileSize;
};

struct HTTPResponse {
    int httpType;
    char* httpServer;
    char* httpLocation;
    char* httpURL;
    char* httpConnection;
    char* httpContenRange;
    char* httpFileCache;
    int httpFileLen;
    int httpFileAllSize;
    int httpStatusCode;
};



struct HTTPRequest {
    //int hostSock;//客户端建立连接的socket
    int httpType;//类型字符串
    char* httpHost;//存储Host字段
    char* httpRange;//HTTP范围
    char* httpConnection;//CONNECT类型
    char* httpURL;
};


struct HTTPLink {
    int serverSocket;
    int hostSocket;
    int (*buildLink)(void* inputHTTP, void* otherData, int otherLen, void* outputData);
    int (*sendLink)(void* inputHTTP, void* otherData, int otherLen, void* outputData);
    int (*closeLink)(void* inputHTTP, void* otherData, int otherLen, void* outputData);
};

/*
 解析HTTP报文的关键内容
 */
// TODO: 在此处引用程序需要的其他标头。
