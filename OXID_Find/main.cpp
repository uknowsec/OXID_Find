#include<WinSock2.h>
#include <stdio.h>
#include <cstdint>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <Windows.h>
#include <mutex>
using namespace std;
mutex mu;  //线程互斥对象
CRITICAL_SECTION Critical;      //定义临界区句柄

#pragma comment(lib,"ws2_32.lib")

#define _IP_MARK "."
int oxid(const char* host);
int oxid1(uint32_t host);
string INTtoIP(uint32_t num);
int cidr_to_ip_and_mask(const char* cidr, uint32_t* ip, uint32_t* mask);
/**
 * Spawns n threads
 */
void spawnThreads(char* host)
{
	uint32_t ip;
	uint32_t mask;
	uint32_t first_ip;
	std::vector<std::thread> threads;
	InitializeCriticalSection(&Critical);   //初始化临界区对象
	if (cidr_to_ip_and_mask(host, &ip, &mask) == -1) {
		printf("error in cidr call.\n");
		exit(1);
	}
	first_ip = ip & mask;
	uint32_t final_ip = first_ip | ~mask;
	uint32_t sum = final_ip - first_ip;
	for (uint32_t i = first_ip; i <= final_ip; i++) {
		threads.push_back(std::thread(oxid1, i));
		//cout << INTtoIP(i) << endl;
	}
	for (auto& th : threads) {
		th.join();
	}
}

int cidr_to_ip_and_mask(const char* cidr, uint32_t* ip, uint32_t* mask)
{
	uint8_t a, b, c, d, bits;
	try
	{
		sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits);
	}
	catch (char* str)
	{
		cout << str << endl;
	}
	if (bits > 32) {
		return -1; /* Invalid bit count */
	}
	*ip =
		(a << 24UL) |
		(b << 16UL) |
		(c << 8UL) |
		(d);
	*mask = (0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL;
}

string INTtoIP(uint32_t num)
{

	string strRet = "";
	for (int i = 0; i < 4; i++)
	{
		uint32_t tmp = (num >> ((3 - i) * 8)) & 0xFF;

		char chBuf[8] = "";
		_itoa_s(tmp, chBuf, 10);
		strRet += chBuf;

		if (i < 3)
		{
			strRet += _IP_MARK;
		}
	}

	return strRet;
}

const char buffer_v1[] = { /* Packet 431 */
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
	0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
	0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };

const char buffer_v2[] = {/* Packet 433 */
			0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
			0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00 };

int oxid(const char* host) {
	WSADATA wsd;//定义	WSADATA对象
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {//初始化WSA
		WSACleanup();
		return -1;
	}

	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientSocket == INVALID_SOCKET) {
		//cout << "[-] error:" << WSAGetLastError()  << endl;
		WSACleanup();
		return -2;
	}

	SOCKADDR_IN client;
	client.sin_family = AF_INET;
	client.sin_port = htons(135);
	client.sin_addr.S_un.S_addr = inet_addr(host);

	int const SERVER_MSG_SIZE = 1024;
	char recvdata1[SERVER_MSG_SIZE] = { 0 };
	char recvdata2[SERVER_MSG_SIZE] = { 0 };
	//连接服务器失败
	if (connect(clientSocket, (struct sockaddr*)&client, sizeof(client)) < 0) {
		//cout << "[-] error:" << WSAGetLastError() << " connect fail " << endl;
		closesocket(clientSocket);
		WSACleanup();
		return -3;
	}
	//连接服务器成功
	else {

		cout << "\n[*] Retrieving network interfaces of " << host << endl;
		send(clientSocket, buffer_v1, sizeof(buffer_v1), 0);
		int size1 = recv(clientSocket, recvdata1, SERVER_MSG_SIZE, 0);
		send(clientSocket, buffer_v2, sizeof(buffer_v2), 0);
		int size2 = recv(clientSocket, recvdata2, 2048, 0);
		char* a = recvdata2;
		printf("  [>] Computer name: ");
		for (int i = 40; i < size2; i++) {
			if (a[i] != 0)
			{
				printf("%c", a[i]);
			}
			if (a[i + 1] == 9 && a[i + 2] == 0 && a[i + 3] == -1 && a[i + 4] == -1)
			{
				break;
			}
			if (a[i] == 0 && a[i + 1] == 0 && a[i + 2] == 0 && a[i + 3] == 7)
			{
				printf("\n  [>] IP Address: ");
			}

		}
		memset(recvdata1, 0, SERVER_MSG_SIZE);
		memset(recvdata2, 0, SERVER_MSG_SIZE);
	}

	closesocket(clientSocket);
	WSACleanup();

	return 0;

}

int oxid1(uint32_t host) {
	WSADATA wsd;//定义	WSADATA对象
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {//初始化WSA
		WSACleanup();
		return -1;
	}

	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientSocket == INVALID_SOCKET) {
		//cout << "[-] error:" << WSAGetLastError()  << endl;
		WSACleanup();
		return -2;
	}

	SOCKADDR_IN client;
	client.sin_family = AF_INET;
	client.sin_port = htons(135);
	client.sin_addr.S_un.S_addr = inet_addr(INTtoIP(host).c_str());

	int const SERVER_MSG_SIZE = 1024;
	char recvdata1[SERVER_MSG_SIZE] = { 0 };
	char recvdata2[SERVER_MSG_SIZE] = { 0 };
	//连接服务器失败
	if (connect(clientSocket, (struct sockaddr*)&client, sizeof(client)) < 0) {
		//cout << "[-] error:" << WSAGetLastError() << " connect fail " << endl;
		closesocket(clientSocket);
		WSACleanup();
		return -3;
	}
	//连接服务器成功
	else {
		//mu.lock(); //同步数据锁
		EnterCriticalSection(&Critical);

		cout << "\n[*] Retrieving network interfaces of " << INTtoIP(host).c_str() << endl <<"  [>] Computer name : ";
		send(clientSocket, buffer_v1, sizeof(buffer_v1), 0);
		int size1 = recv(clientSocket, recvdata1, SERVER_MSG_SIZE, 0);
		send(clientSocket, buffer_v2, sizeof(buffer_v2), 0);
		int size2 = recv(clientSocket, recvdata2, 2048, 0);
		char* a = recvdata2;
		//printf("  [>] Computer name: ");
		for (int i = 40; i < size2; i++) {
			if (a[i + 1] == 9 && a[i + 2] == 0 && a[i + 3] == -1 && a[i + 4] == -1)
			{
				break;
			}
			if (a[i] == 0 && a[i + 1] == 0 && a[i + 2] == 0 && a[i + 3] == 7)
			{
				printf("\n  [>] IP Address: ");
			}
			if (a[i] != 0)
			{
				printf("%c", a[i]);
			}

		}
		memset(recvdata1, 0, SERVER_MSG_SIZE);
		memset(recvdata2, 0, SERVER_MSG_SIZE);
		//mu.unlock();  //解除锁定
		LeaveCriticalSection(&Critical);

		std::this_thread::sleep_for(std::chrono::milliseconds(100));

	}

	closesocket(clientSocket);
	WSACleanup();

	return 0;

}



void usage() {
	printf("Author: Uknow\n");
	printf("Github: https://github.com/uknowsec/OXID_Find\n");
	printf("usage: OXID_Find.exe -i 192.168.0.1\n");
	printf("usage: OXID_Find.exe -c 192.168.0.1/24\n");
}


int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		usage();
		return -1;
	}
	else if (strcmp(argv[1], "-c") == 0)
	{
		printf("Author: Uknow\n");
		printf("Github: https://github.com/uknowsec/OXID_Find\n");
		spawnThreads(argv[2]);
		///	uint32_t ip;
		//	uint32_t mask;
		//	uint32_t first_ip;
			//if (cidr_to_ip_and_mask(argv[2], &ip, &mask) == -1) {
			//	printf("error in cidr call.\n");
			//	exit(1);
		//	}

			//first_ip = ip & mask;
			//uint32_t final_ip = first_ip | ~mask;
		//	for (uint32_t i = first_ip; i <= final_ip; i++) {
				//spawnThreads(20, INTtoIP(i).c_str());
				//oxid(INTtoIP(i).c_str());
			//}
	}
	else if (strcmp(argv[1], "-i") == 0)
	{
		printf("Author: Uknow\n");
		printf("Github: https://github.com/uknowsec/OXID_Find\n");
		oxid(argv[2]);
	}
	else {
		usage();
		return -1;
	}
	return 0;
}
