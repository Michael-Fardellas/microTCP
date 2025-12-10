/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Test microTCP server.
 * Usage: ./test_microtcp_server <port>
 *
 * The server binds to the specified port, accepts one connection,
 * receives messages, echoes them back, and shuts down when the client closes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../lib/microtcp.h"

#define BUFFER_SIZE 4096

static void print_usage(const char *prog)
{
  fprintf(stderr, "Usage: %s <port>\n", prog);
  fprintf(stderr, "  port  - The port number to listen on (1024-65535)\n");
}

int main(int argc, char **argv)
{
  uint16_t port;
  microtcp_sock_t sock;
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  uint8_t buffer[BUFFER_SIZE];
  ssize_t received;

  /* Parse command-line arguments */
  if (argc != 2) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  port = (uint16_t) atoi(argv[1]);
  if (port < 1024) {
    fprintf(stderr, "Error: Port must be >= 1024\n");
    return EXIT_FAILURE;
  }

  printf("[Server] Starting microTCP server on port %u...\n", port);

  /* Create the microTCP socket (over UDP) */
  sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock.sd < 0) {
    perror("[Server] microtcp_socket failed");
    return EXIT_FAILURE;
  }

  /* Prepare the server address structure */
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  /* Bind the socket */
  if (microtcp_bind(&sock, (struct sockaddr *) &server_addr,
                    sizeof(server_addr)) < 0) {
    perror("[Server] microtcp_bind failed");
    close(sock.sd);
    return EXIT_FAILURE;
  }

  printf("[Server] Socket bound. Waiting for a client connection...\n");

  /* Accept a connection (blocks until a client connects via 3-way handshake) */
  memset(&client_addr, 0, sizeof(client_addr));
  if (microtcp_accept(&sock, (struct sockaddr *) &client_addr,
                      sizeof(client_addr)) < 0) {
    perror("[Server] microtcp_accept failed");
    close(sock.sd);
    return EXIT_FAILURE;
  }

  printf("[Server] Client connected from %s:%u\n",
         inet_ntoa(sock.peer_addr.sin_addr),
         ntohs(sock.peer_addr.sin_port));

  /* Receive loop: receive data, print it, echo it back */
  while (1) {
    memset(buffer, 0, BUFFER_SIZE);
    received = microtcp_recv(&sock, buffer, BUFFER_SIZE - 1, 0);

    if (received < 0) {
      fprintf(stderr, "[Server] microtcp_recv error\n");
      break;
    }

    if (received == 0) {
      printf("[Server] Client closed connection.\n");
      break;
    }

    /* Null-terminate for safe printing */
    buffer[received] = '\0';
    printf("[Server] Received %zd bytes: \"%s\"\n", received, buffer);

    /* Echo data back to the client */
    ssize_t sent = microtcp_send(&sock, buffer, (size_t) received, 0);
    if (sent < 0) {
      fprintf(stderr, "[Server] microtcp_send error\n");
      break;
    }
    printf("[Server] Echoed %zd bytes back to client.\n", sent);
  }

  /* Shutdown the connection */
  printf("[Server] Shutting down...\n");
  microtcp_shutdown(&sock, SHUT_RDWR);

  /* Print statistics */
  printf("\n=== Server Statistics ===\n");
  printf("Packets sent:     %lu\n", (unsigned long) sock.packets_send);
  printf("Packets received: %lu\n", (unsigned long) sock.packets_received);
  printf("Packets lost:     %lu\n", (unsigned long) sock.packets_lost);
  printf("Bytes sent:       %lu\n", (unsigned long) sock.bytes_send);
  printf("Bytes received:   %lu\n", (unsigned long) sock.bytes_received);
  printf("Bytes lost:       %lu\n", (unsigned long) sock.bytes_lost);

  return EXIT_SUCCESS;
}
