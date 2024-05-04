/*
 *  Copyright (c) 2024 Filippo Rossoni
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAX_REQUEST_SIZE 4096

static void print_url(char *gateway_host, uint16_t gateway_port, char *realm) {
	char url[512];
	snprintf(url, sizeof(url), "https://%s:%d/remote/saml/start?redirect=1",
			gateway_host, gateway_port);

	if (realm[0] != '\0') {
		strncat(url, "&realm=", sizeof(url) - 1);
		strncat(url, realm, sizeof(url) - 1);
	}
	char command[600];
	sprintf(command,"xdg-open %s",url);
	system(command);
}

// Function to parse HTTP request and extract parameter "id"
static char* parse_request(const char *request) {
	char *id_param;
	char *query_start = strchr(request, '?');
	if (query_start != NULL) {
		id_param = strstr(query_start, "id=");
		if (id_param != NULL) {
			id_param += 3; // Length of "id="
			char *id_end = strchr(id_param, '&');
			if (id_end == NULL) {
				id_end = strchr(id_param, ' ');
			}
			if (id_end == NULL) {
				id_end = strchr(id_param, '\r');
			}
			if (id_end == NULL) {
				id_end = id_param + strlen(id_param); // End of string
			}
			*id_end = '\0'; // Null-terminate the string
			return strdup(id_param);

		}
	}
	return NULL;
}

static void send_response(int sockfd, const char *message) {
	char response[MAX_REQUEST_SIZE];
	sprintf(response, "HTTP/1.1 200 OK\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: text/html\r\n\r\n"
			"%s", strlen(message), message);
	write(sockfd, response, strlen(response));
}

char* listen_for_id(uint16_t listen_port, char *gateway_host,
		uint16_t gateway_port, char *realm) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Error opening socket\n");
		exit(1);
	}

	struct sockaddr_in serv_addr;
	bzero((char*) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serv_addr.sin_port = htons(listen_port);

	if (bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error on binding");
		exit(1);
	}

	int opt = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("Error setting SO_REUSEADDR\n");
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int)) < 0) {
		perror("error set SO_REUSEPORT\n");
	}

	listen(sockfd, 1);

	print_url(gateway_host, gateway_port, realm);

	// Accept incoming connections
	struct sockaddr cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	int newsockfd = accept(sockfd, &cli_addr, &clilen);
	if (newsockfd < 0) {
		perror("Error on accept\n");
		return NULL;
	}
	close(sockfd);

	// Read HTTP request from client
	char buffer[MAX_REQUEST_SIZE];
	bzero(buffer, MAX_REQUEST_SIZE);
	read(newsockfd, buffer, MAX_REQUEST_SIZE - 1);

	char *id = parse_request(buffer);
	if (id != NULL) {
		// Send response to client
		send_response(newsockfd,
				"<html><body><h1>ID retrieved. Connecting...!</h1></body></html>");
	} else {
		perror("id parameter not found\n");
		send_response(newsockfd,
				"<html><body><h1>ERROR! id not found</h1></body></html>");
	}
	close(newsockfd);

	return id;
}

int main(int argc, char *argv[]) {
	if (argc < 3) {
		perror("use idretriever gateway_host gateway_port [realm]\n");
		return -1;
	}
	char *gateway_host = argv[1];
	uint16_t gateway_port = strtol(argv[2], NULL, 0);
	if (gateway_port < 1 || gateway_port > 65535) {
		perror("Specify a valid gateway_port\n");
		return -1;
	}

	char *realm = argc>3?argv[4]:"";

	char *id = listen_for_id(8020, gateway_host, gateway_port, realm);
	printf("remote/saml/auth_id?id=%s\n",id);
}

