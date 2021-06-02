#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

int main() {

	char server_ip_addr[32] = "127.0.0.1";
	int port_number = 19090;
	char send_buf[256] = "send test text\n";
	char recv_buf[256];

	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 0), &wsa_data) != 0) {
		printf("Initialize winsock failed (WSAStartup)\n");
	}

	struct sockaddr_in dst_addr;
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_port = htons(port_number);
	dst_addr.sin_family = AF_INET;

	inet_pton(dst_addr.sin_family, server_ip_addr, &dst_addr.sin_addr.s_addr);

	int dst_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (connect(dst_socket, (struct sockaddr*)&dst_addr, sizeof(dst_addr))) {
		printf("error: serverIP\n");
		exit(0);
	}

	printf("accepted: serverIP\n");;

	send(dst_socket, send_buf, 256, 0);
	recv(dst_socket, recv_buf, 256, 0);

	printf("recv: %s\n", recv_buf);


	closesocket(dst_socket);

	WSACleanup();
	return 0;
}