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
 * Test microTCP client.
 * Usage: ./test_microtcp_client <server_ip> <port> [message]
 *
 * Connects to the server, sends a message (or default), receives the echo,
 * prints it, and shuts down.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../lib/microtcp.h"

#define BUFFER_SIZE 4096
#define DEFAULT_MESSAGE "Hello from microTCP client!"

static void
print_usage(const char *prog)
{
  fprintf(stderr, "Usage: %s <server_ip> <port> [message]\n", prog);
  fprintf(stderr, "  server_ip - IP address of the server (e.g. 127.0.0.1)\n");
  fprintf(stderr, "  port      - Port number the server is listening on\n");
  fprintf(stderr, "  message   - (optional) Message to send; default: \"%s\"\n",
          DEFAULT_MESSAGE);
}

int
main(int argc, char **argv)
{
  const char *server_ip;
  uint16_t port;
  const char *message;
  microtcp_sock_t sock;
  struct sockaddr_in server_addr;
  uint8_t buffer[BUFFER_SIZE];
  ssize_t sent, received;

  /* Parse command-line arguments */
  if (argc < 3) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  server_ip = argv[1];
  port = (uint16_t) atoi(argv[2]);
  message = (argc >= 4) ? argv[3] : DEFAULT_MESSAGE;

  if (port < 1024) {
    fprintf(stderr, "Error: Port must be >= 1024\n");
    return EXIT_FAILURE;
  }

  printf("[Client] Connecting to %s:%u...\n", server_ip, port);

  /* Create the microTCP socket (over UDP) */
  sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock.sd < 0) {
    perror("[Client] microtcp_socket failed");
    return EXIT_FAILURE;
  }

  /* Prepare the server address structure */
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
    fprintf(stderr, "[Client] Invalid server IP address: %s\n", server_ip);
    close(sock.sd);
    return EXIT_FAILURE;
  }

  /* Connect to the server (3-way handshake) */
  if (microtcp_connect(&sock, (struct sockaddr *) &server_addr,
                       sizeof(server_addr)) < 0) {
    perror("[Client] microtcp_connect failed");
    close(sock.sd);
    return EXIT_FAILURE;
  }

  printf("[Client] Connected!\n");

  /* Send the message */
  size_t msg_len = strlen(message);
  sent = microtcp_send(&sock, message, msg_len, 0);
  if (sent < 0) {
    fprintf(stderr, "[Client] microtcp_send error\n");
    microtcp_shutdown(&sock, SHUT_RDWR);
    return EXIT_FAILURE;
  }
  printf("[Client] Sent %zd bytes: \"%s\"\n", sent, message);

  /* Receive the echo from the server */
  memset(buffer, 0, BUFFER_SIZE);
  received = microtcp_recv(&sock, buffer, BUFFER_SIZE - 1, 0);
  if (received < 0) {
    fprintf(stderr, "[Client] microtcp_recv error\n");
    microtcp_shutdown(&sock, SHUT_RDWR);
    return EXIT_FAILURE;
  }

  buffer[received] = '\0';
  printf("[Client] Received echo (%zd bytes): \"%s\"\n", received, buffer);

  /* Shutdown the connection */
  printf("[Client] Shutting down...\n");
  microtcp_shutdown(&sock, SHUT_RDWR);

  /* Print statistics */
  printf("\n=== Client Statistics ===\n");
  printf("Packets sent:     %lu\n", (unsigned long) sock.packets_send);
  printf("Packets received: %lu\n", (unsigned long) sock.packets_received);
  printf("Packets lost:     %lu\n", (unsigned long) sock.packets_lost);
  printf("Bytes sent:       %lu\n", (unsigned long) sock.bytes_send);
  printf("Bytes received:   %lu\n", (unsigned long) sock.bytes_received);
  printf("Bytes lost:       %lu\n", (unsigned long) sock.bytes_lost);

  return EXIT_SUCCESS;
}
