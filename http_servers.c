#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
 
/*
* 网络编程    包含头文件：    winsock2.h
*                      引用库文件：    ws2_32.lib
*/
 
 
char rev_buffer[1024];	//接收信息缓冲区
char filePath[128];		//网页文件路径
 
 
/**
* 主要步骤：
* 1.初始化网络库
* 2.创建socket
* 3.绑定IP地址和端口号
* 4.监听连接
* 5.接收连接
* 6.处理连接请求
* 7.关闭连接，关闭网络库
**/
 
 
int main()
{
 
	//============================================================================
	//1.初始化网络库    WSA --> Windows Socket API
	//para1:指定socket版本    使用最新的2.2版本即可
	//para2:是一个传出参数
 
	int ret;
	WSADATA wsadata;
 
	ret = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (ret != 0)
	{
		printf("WSADATA启动失败\r\n");
		exit(-1);
	}
	else
	{
		printf("WSADATA启动成功\r\n");
	}
 
	//============================================================================
	//2.创建socket
	//para1:指定IP协议    AF_INET -> IPV4    AF_INET6 -> IPV6
	//para2:数据传输格式    常用的有两种：流式传输（TCP）    数据包传输（UDP）
	//para3:传输协议：
 
	SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET)
	{
		printf("创建serverSocket失败\r\n");
		exit(-1);
	}
	else
	{
		printf("创建serverSocket成功\r\n");
	}
 
	============================================================================
	//3.绑定IP地址和端口号(对于服务器是绑定，对于客户端是连接)
	//para1:    指定socket
	//para2:    IP地址和端口号
	//para3:    para2的长度
 
	SOCKADDR_IN serverAddr;
	serverAddr.sin_family = AF_INET;//必须和创建socket时一样
	serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	serverAddr.sin_port = htons(80);//此处涉及到大端存储和小端存储        一般计算机上都是小端的 网络上一般都是大端的    所以需要将本地字节序转为网络字节序
 
	ret = bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr));
	if (ret == SOCKET_ERROR)
	{
		printf("套接字绑定失败\r\n");
		exit(-1);
	}
	else
	{
		printf("套接字绑定成功\r\n");
	}
 
	//============================================================================
	//4.监听连接
 
	listen(serverSocket, 10);
	printf("服务器监听中......\r\n");
 
	//============================================================================
	//5.接收连接
 
	SOCKADDR clientAddr;
	int len_clientAddr = sizeof(clientAddr);
 
	while (1)
	{
		SOCKET clientSocket = accept(serverSocket, &clientAddr, &len_clientAddr);
		if (clientSocket == INVALID_SOCKET)
		{
			printf("建立客户端连接失败\r\n");
			exit(-1);
		}
		else
		{
			printf("成功建立客户端连接\r\n");
		}
 
		//6.处理连接请求
		//从clientSocket接受数据
 
		ret = recv(clientSocket, rev_buffer, sizeof(rev_buffer), 0);
		printf("The return of recv is:%d\r\n", ret);
 
		if (ret <= 0)
		{
			printf("接收来自客户端的数据失败\r\n");
			printf("重新进入等待连接状态......\r\n");
			closesocket(clientSocket);
			continue;
			//exit(-1);
		}
		else
		{
			printf("成功接收来自客户端的数据：\r\n");
			printf("%s\r\n", rev_buffer);
		}
 
		//给客户发送网页	后续可以根据具体请求，转向不同页面
		strcpy(filePath, "index.html");
 
		ret = access(filePath, 0);//0 代表判断文件是否存在    如果存在返回0 否则返回-1
		if (ret != 0)
		{
			//未找到文件
			char sendBuf[1024] = { 0 };
 
			sprintf(sendBuf, "HTTP/1.1 404 NOT FOUND\r\n");
			send(clientSocket, sendBuf, strlen(sendBuf), 0);
 
			sprintf(sendBuf, "Content-type:text/html\r\n");
			send(clientSocket, sendBuf, strlen(sendBuf), 0);
 
			sprintf(sendBuf, "\r\n");
			send(clientSocket, sendBuf, strlen(sendBuf), 0);
 
 
			sprintf(sendBuf, "找不到，滚！！！！\r\n");
			send(clientSocket, sendBuf, strlen(sendBuf), 0);
		}
		else
		{
			//找到相关网页文件
			FILE* fs = fopen(filePath, "r");
			if (fs == NULL)
			{
				printf("打开网页文件失败\r\n");
				exit(-1);
			}
			else
			{
				char dataBuf[1024] = { 0 };
 
				sprintf(dataBuf, "http/1.1 200 success\r\n");
				send(clientSocket, dataBuf, strlen(dataBuf), 0);
 
				sprintf(dataBuf, "content-type:text/html\r\n");
				send(clientSocket, dataBuf, strlen(dataBuf), 0);
 
				sprintf(dataBuf, "\r\n");
				send(clientSocket, dataBuf, strlen(dataBuf), 0);
 
				do
				{
					fgets(dataBuf, 1024, fs);
					send(clientSocket, dataBuf, strlen(dataBuf), 0);
				} while (!feof(fs));
 
				fclose(fs);
			}
		}
		closesocket(clientSocket);//发送完直接关闭    因为HTTP协议是无连接的
	}
 
	//7.关闭连接，清理网络库
 
	closesocket(serverSocket);
	WSACleanup();
 
	return 0;
}
