// CMakeProject1.cpp: 定义应用程序的入口点。
//

#include "CMakeProject1.h"

#define MAXNUM 999999999
/*
* 虽然是全局变量，但是子进程和父进程不使用同一个数据。
*/

//用于控制子进程发送方式的部分
int (*sendFunc) (char* data, int len);
int hostSocket=MAXNUM;
SSL* hostssl=NULL;

char defaultDir[] = ".";
char defaultFile[] = "/index.html";


int sendFundHTTP(char* data, int len) {

	_ASSERT(hostSocket == MAXNUM)

	_ASSERT(send(hostSocket, data, len, 0) < 0)

	return 0;

}


int sendFuncHTTPS(char* data, int len) {

	_ASSERT(hostssl == NULL)

	_ASSERT(SSL_write(hostssl, data, len) < 0)

		return 0;
}

//类似strtok_r，根据，分割字符串，然后返回，分割字符串的第二项的指针。
//返回值NULL表示后面没有字符串了
char* rangeParser(struct HTTPRange* range,char* rangeStr) {

	char* save_ptr;
	char* curr_ptr1;
	char* curr_ptr2;
	
	curr_ptr1 = strtok_r(rangeStr, ",", &save_ptr);
	int i;
	for(i=0;i<strlen(curr_ptr1);i++)
	{
	if(curr_ptr1[i] == '-'){
	curr_ptr1[i] = '\0';//slide string
	curr_ptr2 = curr_ptr1 + i + 1;
	break;
	}
	}
	if (i==0)//如果是-xxx型，那就是文件最后的xxx字节
	{
		
		_ASSERT(!strcmp(curr_ptr2,""));
		range->from = range->fileSize - atoi(curr_ptr2);
		range->to = range->fileSize - 1;

	}
	else
	{
		//判断是xxx-型还是xxx-xxx型
		
		int num = atoi(curr_ptr1);
		//curr_ptr2 = strtok(NULL, "-");
		if (!strcmp(curr_ptr2, "")) {//如果是xxx-型，就是从xxx+1到结尾的文件字节
			_ASSERT(num > range->fileSize)
			range->to = range->fileSize;
			range->from = num;

		}
		else {//如果是xxx-xxx型，就xxx到xxx
		
			range->from = num;
			range->to = atoi(curr_ptr2) + 1;
			_ASSERT(num > range->to);
		}

	}
#ifdef DEBUG
	_LOG("range From%d,range To%d\n",range->from,range->to);
#endif // DEBUG

	
	return save_ptr;
}

HTTPRESPONSEHANDLEFUNC(RESPONSEINIT, {
	/*
	* int httpType;
	char* httpServer;
	char* httpLocation;
	char* httpURL;
	char* httpConnection;
	char* httpContenRange;
	char* httpFileCache;
	int httpFileLen;
	*/

	httpResponse->httpServer = NULL;
	httpResponse->httpLocation = NULL;
	httpResponse->httpURL = NULL;
	httpResponse->httpConnection = NULL;
	httpResponse->httpContenRange = NULL;
	httpResponse->httpFileCache = NULL;
	httpResponse->httpStatusCode = 0;
	httpResponse->httpFileLen = 0;
	httpResponse->httpFileAllSize = 0;

	return 0;
	})
HTTPREQUESTHANDLEFUNC(REQUESTINIT, {
		/*
		 int httpType;//类型字符串
	char* httpHost;//存储Host字段
	char* httpRange;//HTTP范围
	char* httpConnection;//CONNECT类型
	char* httpURL;*/
		httpRequest->httpType = 0;
		httpRequest->httpRange = NULL;
		httpRequest->httpConnection = NULL;
		httpRequest->httpURL = NULL;



		return 0;

		})



HTTPRESPONSEHANDLEFUNC(RESPONSESEND, {
#ifdef DEBUG
		_LOG("SEND MESSAGE\n");
#endif // DEBUG
	
	char* httpServer = httpResponse->httpServer;
	char* httpLocation = httpResponse->httpLocation;
	//char* httpURL = httpResponse->httpURL;
	char* httpConnection = httpResponse->httpConnection;
	char* httpContenRange = httpResponse->httpContenRange;
	char* httpFileCache = httpResponse->httpFileCache;
	int httpFileLen = httpResponse->httpFileLen;
	int httpStatusCode = httpResponse->httpStatusCode;
	char* outData = (char*)malloc(2 * MAX_CACHE);
	outData[0] = '\0';
#ifdef DEBUG
		_LOG("wuwuwuuwu\n");
		_LOG("STATUS CODE%d\n",httpResponse->httpStatusCode);
#endif // DEBUG
	switch (httpStatusCode) {
	case 200:
		strcpy(outData, "HTTP/1.1 200 OK\r\n");
		break;
	case 206:
		strcpy(outData, "HTTP/1.1 206 Partial Content\r\n");
		break;
	case 404:
		strcpy(outData, "HTTP/1.1 404 Not Found\r\n");
		break;
	case 302:
		strcpy(outData, "HTTP/1.1 302 Moved Temporarily\r\n");
		break;
	case 301:
		strcpy(outData, "HTTP/1.1 301 Moved Temporarily\r\n");
		break;
	}
	NONONEDATACPY(httpLocation, Location)
	NONONEDATACPY(httpConnection, Connection)
	NONONEDATACPY(httpServer, Server)
	if(httpStatusCode==200||httpStatusCode==206){
	if(httpFileCache!=NULL&&httpFileLen!=0&&httpStatusCode==200){
	sprintf(outData+strlen(outData),"Content-Length: %d\r\n",httpResponse->httpFileAllSize);
	}
	if(httpStatusCode==206){
	sprintf(outData+strlen(outData),"Content-Range: bytes %s\r\n",httpResponse->httpContenRange);
	_LOG("CONTENTRANGE:%s\n",httpResponse->httpContenRange);
	
	}
	strcat(outData,"\r\n");
	
	}

	int size = strlen(outData);
	//outData[0] = '\0';
	if (httpFileCache != NULL){
#ifdef DEBUG
	_LOG("FILECACHE%s,%d\n",httpFileCache,httpFileLen);
#endif
	memcpy(outData + size, httpFileCache, httpFileLen);}
	#ifdef DEBUG
		_LOG("Message %s\n", outData);
#endif // DEBUG
	//接下来将数据进行发送
	_ASSERT(sendFunc == NULL)
	(*sendFunc)(outData,size+httpFileLen);
	
	_FREEPTR(outData);
	_FREEPTR(httpServer);
	_FREEPTR(httpLocation);
	_FREEPTR(httpFileCache);
	_FREEPTR(httpContenRange);
	_FREEPTR(httpConnection);

	
	//清空数据
	HTTPHANDLE(RESPONSEINIT)(inputHTTP, NULL, 0, NULL);
	
#ifdef DEBUG
		_LOG("SEND FINISHED.\n");
#endif // DEBUG
	return 0;
	})




HTTPREQUESTHANDLEFUNC(GET, {

	struct HTTPResponse* httpResponse = (struct HTTPResponse*)malloc(sizeof(struct HTTPResponse));
#ifdef DEBUG
			_LOG("HTTP TYPE GET\n");
#endif // DEBUG  
    if (httpRequest->httpURL != NULL) {
		httpResponse->httpURL = (char*)malloc(50);
		char* trueURL = httpResponse->httpURL;
		strcpy(trueURL, defaultDir);
		strcat(trueURL,defaultFile);
		if (strcmp(httpRequest->httpURL, "/"))//获取真实地址
		{
			trueURL[0] = '\0';
			strcat(trueURL,defaultDir);
			strcat(trueURL, httpRequest->httpURL);


		}
		

		//
		{	
			#ifdef DEBUG
			_LOG("needed trueURL:%s\n",httpResponse->httpURL);
			#endif // DEBUG
			HTTPHANDLE(RESPONSEINIT)((void*)httpResponse,NULL,0,NULL);//初始化回复报文
			if(httpRequest->httpConnection!=NULL){
			httpResponse->httpConnection = (char*)malloc(20);
			strcpy(httpResponse->httpConnection,httpRequest->httpConnection);}
			//httpResponse->httpConnection = httpRequest->httpConnection;
			httpResponse->httpServer = (char*)malloc(20);
			strcpy(httpResponse->httpServer, "JSP2/1.0.26");
			
			//if http jump to 301
			if(hostSocket!=MAXNUM){
			
				httpResponse->httpFileCache = (char*)malloc(MAX_CACHE);//分配一块缓冲区
				httpResponse->httpStatusCode = 301;
				httpResponse->httpLocation = (char*)malloc(30);
				strcpy(httpResponse->httpLocation,"https://");
				strcat(httpResponse->httpLocation,httpRequest->httpHost);
				strcat(httpResponse->httpLocation,trueURL+strlen(defaultDir));
				_LOG("LOC%s\n",httpResponse->httpLocation);
				//strcpy(httpResponse->httpFileCache, "<html>404 Not Found!</html>");
				strcpy(httpResponse->httpFileCache, "\r\n");
				httpResponse->httpFileLen = strlen(httpResponse->httpFileCache);
				//调用发送Handle
				HTTPHANDLE(RESPONSESEND)((void*)httpResponse, NULL, 0, NULL);
				//close(hostSocket);
				return 0;
			}

			int fd = open(trueURL, O_RDONLY);
			
			if (fd == -1) {
#ifdef DEBUG
				_LOG("FILE open failed\n");
#endif // DEBUG
				
				httpResponse->httpFileCache = (char*)malloc(MAX_CACHE);//分配一块缓冲区
				httpResponse->httpStatusCode = 404;
				//strcpy(httpResponse->httpFileCache, "<html>404 Not Found!</html>");
				strcpy(httpResponse->httpFileCache, "\r\n");
				httpResponse->httpFileLen = strlen(httpResponse->httpFileCache);
				//调用发送Handle
				HTTPHANDLE(RESPONSESEND)((void*)httpResponse, NULL, 0, NULL);
				return 0;
			}
			else if (httpRequest->httpRange == NULL) {
#ifdef DEBUG
			_LOG("SEND FILE!\n");
#endif

				httpResponse->httpStatusCode = 200;
				int fileSize = lseek(fd, 0, SEEK_END);
				httpResponse->httpFileAllSize = fileSize;
				lseek(fd, 0, SEEK_SET);
				int num = 0;
				char* data = httpResponse->httpFileCache;
				data = (char*)malloc(MAX_CACHE);
				
				while ((num = read(fd, data, MAX_CACHE)) > 0) {
					httpResponse->httpFileCache = data;
					#ifdef DEBUG
					_LOG("DATA%s\n",data);
					_LOG("DATALEN%d\n",num);
					#endif
					httpResponse->httpFileLen = num;
					//httpResponse->httpFileAllSize = num;
					#ifdef DEBUG
					if(httpResponse->httpStatusCode!=0) _LOG("CODE:%d\n",httpResponse->httpStatusCode);
					if(httpResponse->httpServer!=NULL) _LOG("Server:%s\n",httpResponse->httpServer);
#endif
					HTTPHANDLE(RESPONSESEND)((void*)httpResponse, NULL, 0, NULL);
					//发送报文
					data = (char*)malloc(MAX_CACHE);

				}
				
				free(data);
				close(fd);
				return 0;
			}
			else {
#ifdef DEBUG
			_LOG("SEND RANGE FILE\n");
#endif
				httpResponse->httpStatusCode = 206;
				int fileSize = lseek(fd, 0, SEEK_END);
				httpResponse->httpFileAllSize = fileSize;
				lseek(fd, 0, SEEK_SET);
				struct HTTPRange range;
				range.fileSize = fileSize;
				range.from = 0;
				range.to = fileSize-1;
				//_ASSERT(rangeParser(&range,httpRequest->httpRange,strlen(httpRequest->httpRange))!=0);
				char* rangeStr = httpRequest->httpRange;
				do {
					httpResponse->httpStatusCode = 206;
					//int fileSize = lseek(fd, 0, SEEK_END);
					httpResponse->httpFileAllSize = fileSize;
					rangeStr = rangeParser(&range, rangeStr);
					lseek(fd,range.from, SEEK_SET);
					int hasSendedSize = 0;
					int num;
					if(httpRequest->httpConnection!=NULL&&httpResponse->httpConnection==NULL){
					httpResponse->httpConnection = (char*)malloc(20);
					strcpy(httpResponse->httpConnection,httpRequest->httpConnection);}
					//httpResponse->httpConnection = httpRequest->httpConnection;
					if(httpResponse->httpServer==NULL){
					httpResponse->httpServer = (char*)malloc(20);
					strcpy(httpResponse->httpServer, "JSP2/1.0.26");}
					if(httpResponse->httpContenRange==NULL)
					httpResponse->httpContenRange = (char*)malloc(30);
					//content-range:xx-xx/xx
					sprintf(httpResponse->httpContenRange,"%d-%d/%d",range.from,range.to,fileSize);
					HTTPHANDLE(RESPONSESEND)((void*)httpResponse, NULL, 0, NULL);
					//send data
					/*
					char* data = httpResponse->httpFileCache;
					data = (char*)malloc(MAX_CACHE);
					httpResponse->httpFileCache = data;
					*/
					char* data = httpResponse->httpFileCache;
					data = (char*)malloc(MAX_CACHE);
					httpResponse->httpFileCache = data;
					while ((num = read(fd, data, MAX_CACHE)) > 0&&hasSendedSize<(range.to-range.from)) {
#ifdef DEBUG
					_LOG("DATAP%s\n",data+3);
#endif
						httpResponse->httpFileCache = data;
						httpResponse->httpFileLen = range.to - range.from  - hasSendedSize;
#ifdef DEBUG
					_LOG("DATA%s\n",httpResponse->httpFileCache);
#endif	
						httpResponse->httpFileLen = httpResponse->httpFileLen > num ? num:httpResponse->httpFileLen;
#ifdef DEBUG
					_LOG("LEN%d\n",httpResponse->httpFileLen);
#endif				

					if(httpResponse->httpFileLen==0)
					break;
						
						//httpResponse->httpFileLen = httpResponse->httpFileLen > num ? MAX_CACHE, httpResponse->httpFileLen;
						hasSendedSize += httpResponse->httpFileLen;
						HTTPHANDLE(RESPONSESEND)((void*)httpResponse, NULL, 0, NULL);
						
						data = (char*)malloc(MAX_CACHE);
						
					}
					free(data);
				} while (rangeStr != NULL&&strcmp(rangeStr,""));
				
				close(fd);
				return 0;
			
			}
			
		}
	

    }

    return -1;
	})


struct HTTPHandlePair handlePair[10] = { [HTTPGET]={&(HTTPHANDLE(GET))},[HTTPBASERESPONSE]={&(HTTPHANDLE(RESPONSESEND))} };
		//将报文指针转换成HTTPRequest结构并进行处理
HTTPHANDLEFUNC(REQUESTIN, {
	char* ptr;
	char* currs;
	struct HTTPRequest httpRequest;
HTTPHANDLE(REQUESTINIT)((void*)&httpRequest, NULL, 0, NULL);
#ifdef DEBUG
	_LOG("Loading HTTPRequest...\n");
#endif
currs = strtok_r((char*)inputHTTP, "\r\n", &ptr);
do {
#ifdef DEBUG
	fputs(currs, stdout);
	printf("\n");
	//fputs(currs1, stdout);
#endif
	char* currs1;
	currs1 = strtok(currs, " ");

	if (!strcmp(currs, "GET")) { httpRequest.httpType = HTTPGET; httpRequest.httpURL = strtok(NULL, " "); continue; };
	if (!strcmp(currs, "Connection:")) { httpRequest.httpConnection = strtok(NULL, " "); continue; };
	if (!strcmp(currs, "Host:")) { httpRequest.httpHost = strtok(NULL, " "); continue; };
	if (!strcmp(currs, "Range:")) { httpRequest.httpRange = strtok(NULL, " ") + 6; continue; };
} while ((currs = strtok_r(ptr, "\r\n", &ptr)) != NULL);
#ifdef DEBUG
if (httpRequest.httpURL != NULL)
_LOG("httpURL:%s\n", httpRequest.httpURL);
if (httpRequest.httpRange != NULL)
_LOG("httpRange:%s\n", httpRequest.httpRange);
if (httpRequest.httpConnection != NULL)
_LOG("httpConnect:%s\n",httpRequest.httpConnection);
if (httpRequest.httpHost != NULL)
_LOG("httpHost:%s\n",httpRequest.httpHost);
#endif // DEBUG
if (httpRequest.httpType == HTTPGET) {
	_ASSERT(handlePair[HTTPGET].handle == NULL);
	handlePair[HTTPGET].handle((void*)&httpRequest, NULL, 0, NULL);
	close(hostSocket);
}
return 0;
	})


int buildLink() {
#ifdef DEBUG
	_LOG("RUNNING>>>\n");
#endif
	//先建立HTTP的socket
	struct sockaddr_in saddr;
	int serverhttpd = socket(AF_INET, SOCK_STREAM, 0);
	_ASSERT(serverhttpd == -1)
	memset((void*)(&saddr), 0, (unsigned long)(sizeof(saddr)));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(80);
	saddr.sin_addr.s_addr = INADDR_ANY;
	

	
	int reuse = 0;
	_ASSERT(setsockopt(serverhttpd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(int)) < 0)
	reuse = 1;

	_ASSERT(setsockopt(serverhttpd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(int)) < 0)
	
	reuse = 1;
	_ASSERT(setsockopt(serverhttpd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(int)) < 0)
	_ASSERT(bind(serverhttpd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0)
	_ASSERT(listen(serverhttpd, MAX_PENDING) < 0)

	//再建立HTTPS的socket
	struct sockaddr_in ssaddr;
	int serverhttpsd = socket(AF_INET, SOCK_STREAM, 0);
	_ASSERT(serverhttpsd == -1)
	memset((void*)(&ssaddr), 0, (unsigned long)(sizeof(ssaddr)));
	ssaddr.sin_family = AF_INET;
	ssaddr.sin_port = htons(443);
	ssaddr.sin_addr.s_addr = INADDR_ANY;
	reuse = 1;
	_ASSERT(setsockopt(serverhttpsd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
	_ASSERT(setsockopt(serverhttpsd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(int)) < 0)
	
	_ASSERT(bind(serverhttpsd, (struct sockaddr*)&ssaddr, sizeof(ssaddr)) < 0)
	_ASSERT(listen(serverhttpsd, MAX_PENDING) < 0)
#ifdef DEBUG
	_LOG("SSL BUILDING>>>\n");
#endif


	/*针对HTTP使用的*/
	int hosthttpd;
	struct sockaddr_in hosthttpaddr;
	unsigned int hosthttpaddrlen = sizeof(saddr);
	char hosthttpbuffer[512];
	/*针对HTTPS使用的*/
	int hosthttpsd;
	struct sockaddr_in hosthttpsaddr;
	unsigned int hosthttpsaddrlen = sizeof(saddr);
	char hosthttpsbuffer[512];

	pid_t pid1 = fork();//针对80端口开一个进程，这里有一个fork
	pid_t pid2;
	if (pid1 == 0) {//80端口进程1的部分
#ifdef DEBUG
		_LOG("SUB PROC..\n");
#endif
		while (1) {
			if ((hosthttpd = accept(serverhttpd, (struct sockaddr*)&hosthttpaddr, &hosthttpaddrlen)) >= 0) {
#ifdef DEBUG
				_LOG("HOSTIP:%s\n", inet_ntoa((&hosthttpaddr)->sin_addr))
#endif // DEBUG

				pid_t pid = fork();//这里一个0
				if (pid == 0)
				{

					sendFunc = &sendFundHTTP;
					hostSocket = hosthttpd;

					int buffer_len = 0;
					while ((buffer_len = recv(hosthttpd, hosthttpbuffer, sizeof(hosthttpbuffer), 0)) > 0)
					{
#ifdef DEBUG
						_LOG("FINISH once load\n");
						_LOG("BufferLen:%u\n", buffer_len);

						fputs(hosthttpbuffer, stdout);
						
#endif
						
						_ASSERT(HTTPHANDLE(REQUESTIN)((void*)hosthttpbuffer,NULL,0,NULL)!=0);
						
						
					}
#ifdef DEBUG
					_LOG("Socket Closed.\n");
#endif // DEBUG

					//shutdown(hosthttpd,SHUT_RDWR);
					close(hosthttpd);
					//close(hosthttpd);
					//sleep(3);
					exit(0);
				}
				close(hosthttpd);
			} 
		}
		exit(0);
	}
	else {
		pid2 = fork();//SSL不支持fork的多进程，需要替换为pthread
		if (pid2 == 0) {//443端口进程2的部分
#ifdef DEBUG
			_LOG("SUB PROC..\n");
#endif
			while (1) {
				if ((hosthttpsd = accept(serverhttpsd, (struct sockaddr*)&hosthttpsaddr, &hosthttpsaddrlen)) >= 0)
				{
				
				//close(serverhttpsd);
#ifdef DEBUG
					_LOG("HOSTIP:%s\n", inet_ntoa((&hosthttpsaddr)->sin_addr))
#endif // DEBUG
					pid_t pid = fork();
					if (pid == 0) {
						SSL_library_init();
						OpenSSL_add_all_algorithms();
						SSL_load_error_strings();
						const SSL_METHOD* method = TLS_server_method();
						SSL_CTX* ctx = SSL_CTX_new(method);

						SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /*验证与否*/
						//SSL_CTX_load_verify_locations(ctx, CACERT, NULL); /*若验证,则放置CA证书*/
						//load certificate and private key

						_ASSERT(SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0);
						_ASSERT(SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0);
						_ASSERT(!SSL_CTX_check_private_key(ctx))
						
						SSL_CTX_set_cipher_list(ctx,"RC4-MD5");
						SSL* ssl = SSL_new(ctx);
						SSL_set_accept_state(ssl);
						SSL_set_fd(ssl, hosthttpsd);
						sendFunc = &sendFuncHTTPS;//设置最终的HTTP发送函数
						hostssl = ssl;
						_ASSERT(SSL_accept(ssl) == -1)

						unsigned int buffer_len = 0;
						
						//buffer_len = SSL_read(ssl, hosthttpsbuffer, MAX_CACHE);
						//_LOG("LEN%d\n",buffer_len);
#ifdef DEBUG
						_LOG("read ssl buffer.\n");
						
						
#endif
						while ((buffer_len = SSL_read(ssl, hosthttpsbuffer, sizeof(hosthttpsbuffer))) > 0)
						{
							//fputs(hosthttpbuffer, stdout);
							printf("%s",hosthttpsbuffer);
							_ASSERT(HTTPHANDLE(REQUESTIN)((void*)hosthttpsbuffer,NULL,0,NULL)!=0);
							
							//close(hosthttpsd);
							break;
						}
#ifdef DEBUG
						_LOG("finish read.\n");
#endif
						
						//SSL_shutdown(hostssl);
						SSL_shutdown(ssl);
						SSL_free(ssl);
						//SSL_free(hostssl);
						SSL_CTX_free(ctx);
						//shutdown(hosthttpsd,SHUT_RDWR);
						close(hosthttpsd);
						
#ifdef DEBUG
						_LOG("Socket Closed.\n");
#endif // DEBUG
						exit(0);

					}
					close(hosthttpsd);
				}
			}
			
			exit(0);
		}
		close(hosthttpsd);
		
	}

	//主进程需要去等待子进程，防止子进程变成孤儿进程
	while (1) {
		sleep(1);
	}


}

void testRange()
{

struct HTTPRange range;
				range.fileSize = 500;
				range.from = 0;
				range.to = 500-1;
				//_ASSERT(rangeParser(&range,httpRequest->httpRange,strlen(httpRequest->httpRange))!=0);
				char* rangeStr = (char*)malloc(20);
				char* retx = rangeStr;
				strcpy(rangeStr,"-200,100-200,100-");
				
				
				
				do {
					rangeStr = rangeParser(&range, rangeStr);
					//lseek(fd,range.from, SEEK_SET);
					/*
					unsigned int hasSendedSize = 0;
					int num;
					char* data = httpResponse->httpFileCache;
					while ((num = read(fd, data, MAX_CACHE)) > 0) {
						httpResponse->httpFileLen = range.from - range.to + 1 - hasSendedSize;
						httpResponse->httpFileLen = httpResponse->httpFileLen > num ? num:httpResponse->httpFileLen;
						//httpResponse->httpFileLen = httpResponse->httpFileLen > num ? MAX_CACHE, httpResponse->httpFileLen;
						HTTPHANDLE(RESPONSESEND)((void*)httpResponse, NULL, 0, NULL);
					}*/
				_LOG("from%d,to%d\n",range.from,range.to);

				} while (rangeStr != NULL&&strcmp(rangeStr,""));
				free(retx);
}
int main()
{
	buildLink();
	//testRange();
	//cout << "Hello CMake." << endl;
	return 0;
}
