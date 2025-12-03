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

#include "microtcp.h"
#include "../utils/crc32.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Instructional notes have been rewritten to describe the control flow in plain
 * English without course-specific watermarks.
 */

#define MICROTCP_FLAG_ACK 0x1000
#define MICROTCP_FLAG_RST 0x2000
#define MICROTCP_FLAG_SYN 0x4000
#define MICROTCP_FLAG_FIN 0x8000

static int rand_initialized = 0;

static void
microtcp_seed_rand (void)
{
  /* Seed the random number generator once so that sequence numbers vary. */
  if (!rand_initialized) {
    srand ((unsigned int) time (NULL));
    rand_initialized = 1;
  }
}

static int
microtcp_send_packet (microtcp_sock_t *socket, microtcp_header_t *header,
                      const uint8_t *payload, size_t payload_len)
{
  /* Build a zeroed packet buffer, compute the checksum, and send it via UDP. */
  size_t packet_len = sizeof(microtcp_header_t) + payload_len;
  uint8_t *packet = (uint8_t *) calloc (1, packet_len);
  ssize_t ret;

  if (!packet) {
    return -1;
  }

  memcpy (packet, header, sizeof(microtcp_header_t));
  if (payload_len && payload) {
    memcpy (packet + sizeof(microtcp_header_t), payload, payload_len);
  }

  ((microtcp_header_t *) packet)->checksum = 0;
  ((microtcp_header_t *) packet)->checksum =
      crc32 (packet, packet_len);

  ret = sendto (socket->sd, packet, packet_len, 0,
                (struct sockaddr *) &socket->peer_addr,
                socket->peer_addr_len);
  free (packet);

  if (ret != (ssize_t) packet_len) {
    return -1;
  }

  return 0;
}

static int
microtcp_validate_packet (const uint8_t *packet, size_t packet_len)
{
  /* Verify the checksum of the received packet before processing it further. */
  uint32_t received_checksum;
  uint32_t calculated_checksum;
  uint8_t *tmp = (uint8_t *) calloc (1, packet_len);
  microtcp_header_t *hdr;

  if (packet_len < sizeof(microtcp_header_t) || !tmp) {
    free (tmp);
    return -1;
  }

  memcpy (tmp, packet, packet_len);
  hdr = (microtcp_header_t *) tmp;
  received_checksum = hdr->checksum;
  hdr->checksum = 0;
  calculated_checksum = crc32 (tmp, packet_len);
  free (tmp);

  if (received_checksum != calculated_checksum) {
    return -1;
  }
  return 0;
}

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  /* Initialize a microTCP socket structure with default values. */
  microtcp_sock_t sock;
  memset (&sock, 0, sizeof(microtcp_sock_t));

  sock.sd = socket (domain, type, protocol);
  if (sock.sd < 0) {
    sock.state = INVALID;
    return sock;
  }

  sock.state = CLOSED;
  sock.init_win_size = MICROTCP_WIN_SIZE;
  sock.curr_win_size = MICROTCP_WIN_SIZE;
  sock.cwnd = MICROTCP_INIT_CWND;
  sock.ssthresh = MICROTCP_INIT_SSTHRESH;
  sock.seq_number = 0;
  sock.ack_number = 0;
  sock.peer_addr_len = 0;
  return sock;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  /* Bind the UDP socket to the requested local address and prepare buffers. */
  if (!socket || socket->sd < 0) {
    return -1;
  }

  if (bind (socket->sd, address, address_len) < 0) {
    return -1;
  }

  socket->state = LISTEN;
  socket->recvbuf = (uint8_t *) malloc (MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;
  return 0;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  /* Client side of the three-way handshake: SYN -> SYN/ACK -> ACK. */
  ssize_t received;
  uint8_t buffer[sizeof(microtcp_header_t)];
  microtcp_header_t syn_hdr;
  microtcp_header_t *recv_hdr;

  if (!socket || socket->sd < 0) {
    return -1;
  }

  microtcp_seed_rand ();
  socket->peer_addr_len = address_len;
  memcpy (&socket->peer_addr, address, address_len);

  socket->seq_number = (uint32_t) rand ();
  socket->ack_number = 0;

  memset (&syn_hdr, 0, sizeof(microtcp_header_t));
  syn_hdr.seq_number = socket->seq_number;
  syn_hdr.ack_number = 0;
  syn_hdr.control = MICROTCP_FLAG_SYN;
  syn_hdr.window = socket->curr_win_size;
  syn_hdr.data_len = 0;

  /* Transmit the initial SYN segment to start the connection. */
  if (microtcp_send_packet (socket, &syn_hdr, NULL, 0) < 0) {
    return -1;
  }

  /* SYN consumes one sequence number */
  socket->seq_number += 1;

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, NULL, NULL);
  if (received < (ssize_t) sizeof(microtcp_header_t)) {
    return -1;
  }

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) {
    return -1;
  }

  recv_hdr = (microtcp_header_t *) buffer;
  /* Expect a SYN+ACK response to continue the handshake. */
  if (!(recv_hdr->control & MICROTCP_FLAG_SYN) ||
      !(recv_hdr->control & MICROTCP_FLAG_ACK)) {
    return -1;
  }

  if (recv_hdr->ack_number != socket->seq_number) {
    return -1;
  }

  socket->ack_number = recv_hdr->seq_number + 1;
  socket->seq_number = recv_hdr->ack_number;
  socket->init_win_size = recv_hdr->window;
  socket->curr_win_size = recv_hdr->window;

  /* Send the final ACK to conclude the handshake. */
  memset (&syn_hdr, 0, sizeof(microtcp_header_t));
  syn_hdr.seq_number = socket->seq_number;
  syn_hdr.ack_number = socket->ack_number;
  syn_hdr.control = MICROTCP_FLAG_ACK;
  syn_hdr.window = socket->curr_win_size;
  syn_hdr.data_len = 0;

  if (microtcp_send_packet (socket, &syn_hdr, NULL, 0) < 0) {
    return -1;
  }

  socket->state = ESTABLISHED;
  socket->recvbuf = (uint8_t *) malloc (MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;
  return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  /* Server side of the three-way handshake: wait SYN, send SYN/ACK, receive ACK. */
  ssize_t received;
  uint8_t buffer[sizeof(microtcp_header_t)];
  microtcp_header_t synack_hdr;
  microtcp_header_t *recv_hdr;

  if (!socket || socket->sd < 0) {
    return -1;
  }

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0,
                       address, &address_len);
  if (received < (ssize_t) sizeof(microtcp_header_t)) {
    return -1;
  }

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) {
    return -1;
  }

  recv_hdr = (microtcp_header_t *) buffer;
  /* Ensure the first packet is a SYN before proceeding. */
  if (!(recv_hdr->control & MICROTCP_FLAG_SYN)) {
    return -1;
  }

  socket->peer_addr_len = address_len;
  memcpy (&socket->peer_addr, address, address_len);

  microtcp_seed_rand ();
  socket->seq_number = (uint32_t) rand ();
  socket->ack_number = recv_hdr->seq_number + 1;
  socket->init_win_size = MICROTCP_WIN_SIZE;
  socket->curr_win_size = MICROTCP_WIN_SIZE;

  memset (&synack_hdr, 0, sizeof(microtcp_header_t));
  synack_hdr.seq_number = socket->seq_number;
  synack_hdr.ack_number = socket->ack_number;
  synack_hdr.control = MICROTCP_FLAG_SYN | MICROTCP_FLAG_ACK;
  synack_hdr.window = socket->curr_win_size;
  synack_hdr.data_len = 0;

  /* Reply with a SYN/ACK carrying the newly chosen sequence number. */
  if (microtcp_send_packet (socket, &synack_hdr, NULL, 0) < 0) {
    return -1;
  }

  /* Account for the SYN we just sent */
  socket->seq_number += 1;

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, NULL, NULL);
  if (received < (ssize_t) sizeof(microtcp_header_t)) {
    return -1;
  }

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) {
    return -1;
  }

  recv_hdr = (microtcp_header_t *) buffer;
  /* Confirm that the client replied with the expected ACK. */
  if (!(recv_hdr->control & MICROTCP_FLAG_ACK)) {
    return -1;
  }

  if (recv_hdr->ack_number != socket->seq_number) {
    return -1;
  }

  socket->ack_number = recv_hdr->seq_number + 1;
  socket->state = ESTABLISHED;
  socket->recvbuf = (uint8_t *) malloc (MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;
  return 0;
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  /* Graceful connection teardown: FIN -> FIN/ACK -> ACK. */
  uint8_t buffer[sizeof(microtcp_header_t)];
  microtcp_header_t fin_hdr;
  microtcp_header_t *recv_hdr;
  ssize_t received;

  (void) how;

  if (!socket || socket->sd < 0) {
    return -1;
  }

  memset (&fin_hdr, 0, sizeof(microtcp_header_t));
  fin_hdr.seq_number = socket->seq_number;
  fin_hdr.ack_number = socket->ack_number;
  fin_hdr.control = MICROTCP_FLAG_FIN;
  fin_hdr.window = socket->curr_win_size;
  fin_hdr.data_len = 0;

  /* Send FIN to initiate shutdown. */
  if (microtcp_send_packet (socket, &fin_hdr, NULL, 0) < 0) {
    return -1;
  }

  /* FIN consumes one sequence number */
  socket->seq_number += 1;

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, NULL, NULL);
  if (received < (ssize_t) sizeof(microtcp_header_t)) {
    return -1;
  }

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) {
    return -1;
  }

  recv_hdr = (microtcp_header_t *) buffer;
  /* Expect a FIN/ACK acknowledging the FIN. */
  if (!(recv_hdr->control & MICROTCP_FLAG_FIN) ||
      !(recv_hdr->control & MICROTCP_FLAG_ACK)) {
    return -1;
  }

  if (recv_hdr->ack_number != socket->seq_number) {
    return -1;
  }

  socket->ack_number = recv_hdr->seq_number + 1;

  memset (&fin_hdr, 0, sizeof(microtcp_header_t));
  fin_hdr.seq_number = socket->seq_number;
  fin_hdr.ack_number = socket->ack_number;
  fin_hdr.control = MICROTCP_FLAG_ACK;
  fin_hdr.window = socket->curr_win_size;
  fin_hdr.data_len = 0;

  /* Send the last ACK to complete the close handshake. */
  if (microtcp_send_packet (socket, &fin_hdr, NULL, 0) < 0) {
    return -1;
  }

  socket->state = CLOSED;
  if (socket->recvbuf) {
    free (socket->recvbuf);
    socket->recvbuf = NULL;
  }
  close (socket->sd);
  socket->sd = -1;
  return 0;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Send application data without implementing retransmissions or ACK logic. */
  size_t sent = 0;
  size_t base_seq;

  (void) flags;

  if (!socket || socket->sd < 0 || socket->state != ESTABLISHED) {
    return -1;
  }

  base_seq = socket->seq_number;

  while (sent < length) {
    size_t chunk = MICROTCP_MSS;
    microtcp_header_t hdr;

    if (length - sent < MICROTCP_MSS) {
      chunk = length - sent;
    }

    memset (&hdr, 0, sizeof(microtcp_header_t));
    hdr.seq_number = base_seq + sent;
    hdr.ack_number = socket->ack_number;
    hdr.control = MICROTCP_FLAG_ACK;
    hdr.window = socket->curr_win_size;
    hdr.data_len = (uint32_t) chunk;

    /* Transmit the current chunk with updated sequence numbers. */
    if (microtcp_send_packet (socket, &hdr,
                              (const uint8_t *) buffer + sent,
                              chunk) < 0) {
      return -1;
    }

    sent += chunk;
    socket->bytes_send += chunk;
    socket->packets_send++;
  }

  socket->seq_number = base_seq + sent;

  return (ssize_t) sent;
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Receive data or FIN packets and validate them before updating state. */
  uint8_t *packet;
  ssize_t received;
  microtcp_header_t *hdr;

  (void) flags;

  if (!socket || socket->sd < 0 || socket->state == CLOSED) {
    return -1;
  }

  packet = (uint8_t *) malloc (sizeof(microtcp_header_t) + MICROTCP_RECVBUF_LEN);
  if (!packet) {
    return -1;
  }

  received = recvfrom (socket->sd, packet,
                       sizeof(microtcp_header_t) + MICROTCP_RECVBUF_LEN,
                       0, NULL, NULL);
  if (received < (ssize_t) sizeof(microtcp_header_t)) {
    free (packet);
    return -1;
  }

  if (microtcp_validate_packet (packet, (size_t) received) < 0) {
    free (packet);
    return -1;
  }

  hdr = (microtcp_header_t *) packet;

  if (hdr->control & MICROTCP_FLAG_FIN) {
    microtcp_header_t finack;

    /* After a FIN, reply with FIN/ACK and wait for the final ACK. */
    socket->ack_number = hdr->seq_number + 1;

    memset (&finack, 0, sizeof(microtcp_header_t));
    finack.seq_number = socket->seq_number;
    finack.ack_number = socket->ack_number;
    finack.control = MICROTCP_FLAG_FIN | MICROTCP_FLAG_ACK;
    finack.window = socket->curr_win_size;
    finack.data_len = 0;
    microtcp_send_packet (socket, &finack, NULL, 0);

    /* FIN consumes one sequence number */
    socket->seq_number += 1;

    received = recvfrom (socket->sd, packet,
                         sizeof(microtcp_header_t) + MICROTCP_RECVBUF_LEN,
                         0, NULL, NULL);
    if (received >= (ssize_t) sizeof(microtcp_header_t) &&
        microtcp_validate_packet (packet, (size_t) received) == 0) {
      hdr = (microtcp_header_t *) packet;
      if ((hdr->control & MICROTCP_FLAG_ACK) &&
          hdr->ack_number == socket->seq_number) {
        socket->state = CLOSED;
      }
    }

    if (socket->recvbuf) {
      free (socket->recvbuf);
      socket->recvbuf = NULL;
    }
    close (socket->sd);
    socket->sd = -1;
    free (packet);
    return 0;
  }

  if (hdr->data_len > 0 && (size_t) (received - sizeof(microtcp_header_t))
      >= hdr->data_len) {
    /* Copy as much payload as fits in the caller-provided buffer. */
    size_t copy_bytes = hdr->data_len;
    if (copy_bytes > length) {
      copy_bytes = length;
    }
    memcpy (buffer, packet + sizeof(microtcp_header_t), copy_bytes);
    socket->ack_number = hdr->seq_number + hdr->data_len;
    socket->bytes_received += copy_bytes;
    socket->packets_received++;
    free (packet);
    return (ssize_t) copy_bytes;
  }

  free (packet);
  return -1;
}
