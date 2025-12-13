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


#define MICROTCP_FLAG_ACK 0x1000 // flag gia ACK sto control pedio
#define MICROTCP_FLAG_RST 0x2000 // flag gia reset an ypirxe
#define MICROTCP_FLAG_SYN 0x4000 // flag gia SYN gia handshake
#define MICROTCP_FLAG_FIN 0x8000 // flag gia FIN gia kleisimo

static int rand_initialized = 0; // deixnei an exei ginei seed sto rand

static void microtcp_seed_rand (void) // kanei seed sto rand mia fora
{ 
  if (!rand_initialized) { // an den exei ginei seed akoma
    srand ((unsigned int) time (NULL)); // kanw seed me to trexon xrono
    rand_initialized = 1; // simatizei oti seed egine
  } 
} 

static int microtcp_send_packet (microtcp_sock_t *socket, microtcp_header_t *header, const uint8_t *payload, size_t payload_len) // stelnei paketo me header kai proairetiko payload
{ 
  /* Dhmioyrgei ena adeio buffer paketoy, ypologizei to checksum, kai to stelnei me UDP */
  size_t packet_len = sizeof(microtcp_header_t) + payload_len; // ypologizei to synoliko megethos paketou
  uint8_t *packet = (uint8_t *) calloc (1, packet_len); // kanei allocate kai mhdenizei buffer
  ssize_t ret; // metavliti gia apotelesma sendto

  if (!packet) { // an den yparxei mnimi
    return -1; // epistrefei sfalma
  } 

  memcpy (packet, header, sizeof(microtcp_header_t)); // antigrafei to header ston buffer
  if (payload_len && payload) { // an exoume payload kai megethos
    memcpy (packet + sizeof(microtcp_header_t), payload, payload_len); // antigrafei to payload meta to header
  } 

  ((microtcp_header_t *) packet)->checksum = 0; // mhdenizei to checksum gia ypologismo
  ((microtcp_header_t *) packet)->checksum = // ypologismos checksum exei dyo vimata
      crc32 (packet, packet_len); // ypologizei to alithino checksum se olo to paketo
  // klisi sendto gia apostoli
  ret = sendto (socket->sd, packet, packet_len, 0, (struct sockaddr *) &socket->peer_addr, socket->peer_addr_len); // stelnei to paketo meso UDP ston peer
  free (packet); // apeleftherwnei ton buffer

  if (ret != (ssize_t) packet_len) { // elegxei an stalthike olo to paketo
    return -1; // sfalma an den stalthike
  } 

  return 0; 
}

static int microtcp_validate_packet (const uint8_t *packet, size_t packet_len) // elegxei checksum paketou
{ 
  /* verify to checksum toy received packet prin to xrhsimopoihsoume peraitero */
  uint32_t received_checksum; // to checksum pou irthe
  uint32_t calculated_checksum; // to checksum pou ypologoume
  uint8_t *tmp = (uint8_t *) calloc (1, packet_len); // prosorinos buffer gia ypologismo
  microtcp_header_t *hdr; // deiktis gia na doume header

  if (packet_len < sizeof(microtcp_header_t) || !tmp) { // an to paketo einai poly mikro i dn exei mnimi
    free (tmp); // katharizei an yparxei
    return -1; 
  } 

  memcpy (tmp, packet, packet_len); // antigrafei olo to paketo sto prosorino buffer
  hdr = (microtcp_header_t *) tmp; // kanei cast gia na dei to header
  received_checksum = hdr->checksum; // apothikeuei to checksum pou irthe
  hdr->checksum = 0; // mhdenizei gia na ypologisei ksana
  calculated_checksum = crc32 (tmp, packet_len); // ypologizei checksum sto prosorino
  free (tmp); // eleutherwnei buffer

  if (received_checksum != calculated_checksum) { // sugkrinei ta checksums
    return -1; // an einai diaforetika sfalma
  } 
  return 0; // alliws ok
} 

microtcp_sock_t 
microtcp_socket (int domain, int type, int protocol) 
{ 
  /* Arxikopoiei to microTCP socket me tis default times */
  microtcp_sock_t sock; // to struct pou tha gyrisoume
  memset (&sock, 0, sizeof(microtcp_sock_t)); // mhdenizei ola ta pedia

  sock.sd = socket (domain, type, protocol); // anoigei real UDP socket
  if (sock.sd < 0) { // an apotyxei
    sock.state = INVALID; // simainei invalid katastasi
    return sock; // gyrnaei apla to struct
  } 

  sock.state = CLOSED; // arxiki katastasi kleisto
  sock.init_win_size = MICROTCP_WIN_SIZE; // arxiki window size
  sock.curr_win_size = MICROTCP_WIN_SIZE; // trexousa window size
  sock.cwnd = MICROTCP_INIT_CWND; // congestion window (oxi xrisimopoioume phase1 alla arxikopoiei)
  sock.ssthresh = MICROTCP_INIT_SSTHRESH; // ssthresh default
  sock.seq_number = 0; // arxiki timi seq
  sock.ack_number = 0; // arxiki timi ack
  sock.peer_addr_len = 0; // peer addr len miden
  return sock; // epistrefei to etoimo struct
} 

int 
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) // kanei bind se local dieuthinsi
{ 
  /* Kanei bind to UDP socket sto zhtoumeno local addr kai proetoimazei toys buffers*/
  if (!socket || socket->sd < 0) { // elegxei egkyrotita socket
    return -1; // sfalma an den einai ok
  } 

  if (bind (socket->sd, address, address_len) < 0) { // prospathei na kanei bind sto UDP socket
    return -1;
  } 

  socket->state = LISTEN; // o server einai se listen katastasi
  socket->recvbuf = (uint8_t *) malloc (MICROTCP_RECVBUF_LEN); // desmevei buffer gia receive
  socket->buf_fill_level = 0; // midenizei to poso exei gemisei
  return 0; 
} 

int 
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) // client xtizei syndesi me 3 way handshake
{ 
  /* three-way handshake: SYN -> SYN/ACK -> ACK apo thn meria toy client */
  ssize_t received; // plithos bytes poy lhfthhkan
  uint8_t buffer[sizeof(microtcp_header_t)]; // prosorinos xwros gia header
  microtcp_header_t syn_hdr; // header gia to SYN pou tha stalthei
  microtcp_header_t *recv_hdr; // deiktis gia to header pou tha elthei

  if (!socket || socket->sd < 0) { // an to socket den einai egkyro
    return -1;
  } 

  microtcp_seed_rand (); // bebaiwnetai oti exoume randomness gia seq numbers
  socket->peer_addr_len = address_len; // apothikeuei megethos peer address
  memcpy (&socket->peer_addr, address, address_len); // apothikeuei dieuthinsi peer

  socket->seq_number = (uint32_t) rand (); // epileei arxiko seq number tyxaia
  socket->ack_number = 0; // den exoume akoma ACK

  memset (&syn_hdr, 0, sizeof(microtcp_header_t)); // mhdenizei to syn header
  syn_hdr.seq_number = socket->seq_number; // vazei to arxiko seq
  syn_hdr.ack_number = 0; // den ypologizei ack
  syn_hdr.control = MICROTCP_FLAG_SYN; // orizei to SYN flag
  syn_hdr.window = socket->curr_win_size; // dilwnei to trexwn window size
  syn_hdr.data_len = 0; // xwris payload

  /* Stelnei to arxiko Syn segment gia na jekinhsei to connection */
  if (microtcp_send_packet (socket, &syn_hdr, NULL, 0) < 0) { // stelnei to SYN
    return -1; // sfalma an apotyxei
  } 

  socket->seq_number += 1; // auksanei to seq giati stelthike SYN

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, NULL, NULL); // perimenei SYN ACK
  if (received < (ssize_t) sizeof(microtcp_header_t)) { // an elathan ligotera apo header
    return -1;
  } 

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) { // elegxei checksum tou paketou
    return -1;
  } 

  recv_hdr = (microtcp_header_t *) buffer; // kanei cast sto header pou irthe
  /* Expect a SYN+ACK response to continue the handshake. */
  if (!(recv_hdr->control & MICROTCP_FLAG_SYN) || // prepei na exei SYN flag
      !(recv_hdr->control & MICROTCP_FLAG_ACK)) { // kai ACK flag
    return -1; 
  } 

  if (recv_hdr->ack_number != socket->seq_number) { // elegxei oti ack number tairiazei
    return -1;
  } 

  socket->ack_number = recv_hdr->seq_number + 1; // etoimazei ack gia ton server
  socket->seq_number = recv_hdr->ack_number; // enhmerwnei to epomeno seq
  socket->init_win_size = recv_hdr->window; // apothikeuei arxiko window apo peer
  socket->curr_win_size = recv_hdr->window; // vazei trexwn window apo peer

  /* Stelnei to teleytaio ACK gia oristikopoihsh thn syndesh */
  memset (&syn_hdr, 0, sizeof(microtcp_header_t)); // ksanamhdenizei header gia ACK
  syn_hdr.seq_number = socket->seq_number; // stelnei me trexon seq
  syn_hdr.ack_number = socket->ack_number; // periexei ack pou perimenei peer
  syn_hdr.control = MICROTCP_FLAG_ACK; // mono ACK flag
  syn_hdr.window = socket->curr_win_size; // window pou prosferoume
  syn_hdr.data_len = 0; // xwris data

  if (microtcp_send_packet (socket, &syn_hdr, NULL, 0) < 0) { // stelnei to teliko ACK
    return -1;
  } 

  socket->state = ESTABLISHED; // o client pleon einai se established
  socket->recvbuf = (uint8_t *) malloc (MICROTCP_RECVBUF_LEN); // desmevei buffer gia lixi
  socket->buf_fill_level = 0; // midenizei gemisma buffer
  return 0;
} 

int 
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len) // server dexetai handshake apo client
{ 
  /* three-way handshake apo thn meria toy server -> wait SYN, send SYN/ACK, receive ACK. */
  ssize_t received; // poso data lavthike apo ton client
  uint8_t buffer[sizeof(microtcp_header_t)]; // buffer gia na kratisei header
  microtcp_header_t synack_hdr; // header gia SYN/ACK pou tha stelthei
  microtcp_header_t *recv_hdr; // deiktis sto header tou eisagomenou paketou

  if (!socket || socket->sd < 0) { // an to socket den einai egkyro
    return -1;
  } 

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, address, &address_len); // perimenei to prwto paketo SYN
  if (received < (ssize_t) sizeof(microtcp_header_t)) { // an elathan ligotera bytes apo header
    return -1; // sfalma giati den yparxei plires header
  } 

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) { // elegxei checksum paketou
    return -1;
  } 

  recv_hdr = (microtcp_header_t *) buffer; // kanei cast gia na diavasei to header
  /* Diavevaiwnoyme oti to prwto paketo einai SYN prin synexisoyme */
  if (!(recv_hdr->control & MICROTCP_FLAG_SYN)) { // prepei na exei SYN flag
    return -1; // alliws den proxwrame
  }  

  socket->peer_addr_len = address_len; // kratame to megethos dieuthinsis tou client
  memcpy (&socket->peer_addr, address, address_len); // apothikeuoume tin dieuthinsi tou client

  microtcp_seed_rand (); // spame rand gia to diko mas seq number
  socket->seq_number = (uint32_t) rand (); // epilegoume neo seq arxiko
  socket->ack_number = recv_hdr->seq_number + 1; // to ack number einai to epomeno tou seq tou client
  socket->init_win_size = MICROTCP_WIN_SIZE; // arxiko window pou dexomaste
  socket->curr_win_size = MICROTCP_WIN_SIZE; // trexon window pou dexomaste

  memset (&synack_hdr, 0, sizeof(microtcp_header_t)); // mhdenizei to header SYN/ACK
  synack_hdr.seq_number = socket->seq_number; // vazoume to diko mas seq
  synack_hdr.ack_number = socket->ack_number; // vazoume to ack tou client
  synack_hdr.control = MICROTCP_FLAG_SYN | MICROTCP_FLAG_ACK; // vazoume kai SYN kai ACK flags
  synack_hdr.window = socket->curr_win_size; // dilwnei to window mas
  synack_hdr.data_len = 0; // xwris payload

  if (microtcp_send_packet (socket, &synack_hdr, NULL, 0) < 0) { // stelnei to SYN/ACK
    return -1;
  }  

  socket->seq_number += 1; // auxanei seq giati stalthe SYN

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, NULL, NULL); // perimenei teliko ACK apo client
  if (received < (ssize_t) sizeof(microtcp_header_t)) { // an einai ligotero apo header
    return -1; 
  }  

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) { // elegxei checksum sto teleutaio paketo
    return -1;
  } 

  recv_hdr = (microtcp_header_t *) buffer; // kanei cast sto header tou ACK
  if (!(recv_hdr->control & MICROTCP_FLAG_ACK)) { // prepei na exei ACK flag
    return -1;
  } 

  if (recv_hdr->ack_number != socket->seq_number) { // elegxei oti ack arithmos tairiazei me to diko mas seq
    return -1; \
  } 

  socket->ack_number = recv_hdr->seq_number + 1; // enhmerwnei ack gia epomeno data
  socket->state = ESTABLISHED; // o server pleon established
  socket->recvbuf = (uint8_t *) malloc (MICROTCP_RECVBUF_LEN); // desmevei buffer gia dedomena
  socket->buf_fill_level = 0; // midenizei plirwsi buffer
  return 0;
} 

int 
microtcp_shutdown (microtcp_sock_t *socket, int how) 
{ 
  /*FIN -> FIN/ACK -> ACK. */
  uint8_t buffer[sizeof(microtcp_header_t)]; // buffer gia na lavei header apo peer
  microtcp_header_t fin_hdr; // header gia ta FIN kai ACK mas
  microtcp_header_t *recv_hdr; // deiktis sto header pou lambanoume
  ssize_t received; // posa bytes lavthikan

  (void) how; // den xrhsimopoioume thn parametro how

  if (!socket || socket->sd < 0) { //elegxei an to socket einai egkyro
    return -1;
  } 

  memset (&fin_hdr, 0, sizeof(microtcp_header_t)); // mhdenizei to header gia FIN
  fin_hdr.seq_number = socket->seq_number; // vazoume trexwn seq
  fin_hdr.ack_number = socket->ack_number; // vazoume trexwn ack
  fin_hdr.control = MICROTCP_FLAG_FIN; // vazoume FIN flag
  fin_hdr.window = socket->curr_win_size; // parathuro poy prosferoume
  fin_hdr.data_len = 0; // den exei data

  /* Stelnei Fin gia na jekinhsei to shutdown */
  if (microtcp_send_packet (socket, &fin_hdr, NULL, 0) < 0) { // stelnei to FIN
    return -1; // sfalma an apotyxei
  } 

  socket->seq_number += 1; // auksanei to seq meta to FIN

  received = recvfrom (socket->sd, buffer, sizeof(buffer), 0, NULL, NULL); // perimenei FIN ACK
  if (received < (ssize_t) sizeof(microtcp_header_t)) { // elegxei ean elathan toylaxiston header bytes
    return -1; 
  } 

  if (microtcp_validate_packet (buffer, (size_t) received) < 0) { // elegxei checksum tou paketou
    return -1;
  } 

  recv_hdr = (microtcp_header_t *) buffer; // kanei cast sto header pou irthe
  /* Expect a FIN/ACK acknowledging the FIN. */
  if (!(recv_hdr->control & MICROTCP_FLAG_FIN) || // prepei na exei FIN flag
      !(recv_hdr->control & MICROTCP_FLAG_ACK)) { // kai ACK flag
    return -1; 
  } 

  if (recv_hdr->ack_number != socket->seq_number) { // elegxei oti ack prosdiorizei to FIN mas
    return -1; 
  } 

  socket->ack_number = recv_hdr->seq_number + 1; // etoimazei ack gia epomeno vimata

  memset (&fin_hdr, 0, sizeof(microtcp_header_t)); // ksanamhdenizei header gia to teliko ACK
  fin_hdr.seq_number = socket->seq_number; // krata to trexwn seq
  fin_hdr.ack_number = socket->ack_number; // periexei ack pou perimenei peer
  fin_hdr.control = MICROTCP_FLAG_ACK; // mono ACK flag gia telos
  fin_hdr.window = socket->curr_win_size; // parathuro pou dilwnoume
  fin_hdr.data_len = 0; // den exei payload

  if (microtcp_send_packet (socket, &fin_hdr, NULL, 0) < 0) { // stelnei teliko ACK
    return -1; 
  } 

  socket->state = CLOSED; // kathorizei katastasi kleisti
  if (socket->recvbuf) { // an yparxei buffer
    free (socket->recvbuf); // eleutherwnei ton buffer
    socket->recvbuf = NULL; // mhdenizei deikti
  } 
  close (socket->sd); // kleinei to real socket
  socket->sd = -1; // markarei oti den exei socket
  return 0; 
} 

ssize_t 
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,int flags) // stelnei dedomena xwris retransmission logic
{ 
  size_t sent = 0; // posa bytes exoume steilei mexri twra
  size_t base_seq; // to arxiko seq gia auti tin apostoli

  (void) flags; // den xrisimopoioume extra flags

  if (!socket || socket->sd < 0 || socket->state != ESTABLISHED) { // prepei na einai swsto kai established
    return -1;
  } 

  base_seq = socket->seq_number; // kratame to seq apo to opoio xekiname

  while (sent < length) { // oso exoun akoma bytes na staloun
    size_t chunk = MICROTCP_MSS; // megethos kommatos na stalthei
    microtcp_header_t hdr; // header gia auto to komati

    if (length - sent < MICROTCP_MSS) { // an to ypoloipo einai mikrotero apo MSS
      chunk = length - sent; // stelnei mono to ypoloipo
    } 

    memset (&hdr, 0, sizeof(microtcp_header_t)); // mhdenizei header
    hdr.seq_number = base_seq + sent; // o seq gia auto to komati
    hdr.ack_number = socket->ack_number; // to teleutaio ack pou exoume
    hdr.control = MICROTCP_FLAG_ACK; // xrisimopoioume to ACK flag ws data segment
    hdr.window = socket->curr_win_size; // dilwnei parathuro
    hdr.data_len = (uint32_t) chunk; // megethos payload

    /* Transmit to trexwn block me ananewmena sequence numbers. */
    if (microtcp_send_packet (socket, &hdr, (const uint8_t *) buffer + sent, chunk) < 0) { // stelnei to trexon block dedomenwn
      return -1;
    } 

    sent += chunk; // enhmerwnei poso steile
    socket->bytes_send += chunk; // metrisi bytes pou exoume steilei synolika
    socket->packets_send++; // ayksanei metrisi paketwn
  } 

  socket->seq_number = base_seq + sent; // enimerwnei to epomeno seq meta ola ta bytes

  return (ssize_t) sent; // epistrefei posa bytes stalikan
} 

ssize_t 
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) // dexetai dedomena i FIN
{ 
  /* Receive data or FIN packets and validate them before updating state. */
  uint8_t *packet; // buffer gia olokliro paketo pou tha elthei
  ssize_t received; // posa bytes lavthikan
  microtcp_header_t *hdr; // deiktis sto header tou paketou

  (void) flags; // den xrisimopoioume flags edw

  if (!socket || socket->sd < 0 || socket->state == CLOSED) { // prepei na einai egkyro kai oxi closed
    return -1; // sfalma se alli periptwsi
  } 

  packet = (uint8_t *) malloc (sizeof(microtcp_header_t) + MICROTCP_RECVBUF_LEN); // desmevei buffer gia header+payload
  if (!packet) { // elegxei an petyxe
    return -1; // sfalma an den exei mnimi
  } 

  received = recvfrom (socket->sd, packet, // klisi recvfrom gia lipsi
                       sizeof(microtcp_header_t) + MICROTCP_RECVBUF_LEN, 
                       0, NULL, NULL); // diavazei mexri to megisto receive buffer
  if (received < (ssize_t) sizeof(microtcp_header_t)) { // an lavthikan ligotera apo header
    free (packet); // eleutherwnei buffer
    return -1; // sfalma
  } 

  if (microtcp_validate_packet (packet, (size_t) received) < 0) { // elegxei checksum sto paketo
    free (packet); // katharizei buffer
    return -1; // sfalma an invalid
  } 

  hdr = (microtcp_header_t *) packet; // kanei cast gia na diavasei header

  if (hdr->control & MICROTCP_FLAG_FIN) { // an to paketo periexei FIN
    microtcp_header_t finack; // header gia FIN ACK pou tha steiloume pisw

    /* After a FIN, reply with FIN/ACK and wait for the final ACK. */
    socket->ack_number = hdr->seq_number + 1; // etoimazei ack gia to FIN pou lavame

    memset (&finack, 0, sizeof(microtcp_header_t)); // mhdenizei to finack header
    finack.seq_number = socket->seq_number; // vazoume trexwn seq mas
    finack.ack_number = socket->ack_number; // vazoume ack gia to FIN
    finack.control = MICROTCP_FLAG_FIN | MICROTCP_FLAG_ACK; // stelnei FIN kai ACK mazi
    finack.window = socket->curr_win_size; // parathuro pou dilwnoume
    finack.data_len = 0; // den exei payload
    microtcp_send_packet (socket, &finack, NULL, 0); // stelnei to FIN/ACK

    socket->seq_number += 1; // auksanei seq meta to FIN/ACK mas

    // klisi recvfrom gia lipsi
    received = recvfrom (socket->sd, packet, sizeof(microtcp_header_t) + MICROTCP_RECVBUF_LEN, 0, NULL, NULL); // perimenei teliko ACK apo peer
    if (received >= (ssize_t) sizeof(microtcp_header_t) && 
        microtcp_validate_packet (packet, (size_t) received) == 0) { // elegxei oti to paketo einai egkyro
      hdr = (microtcp_header_t *) packet; // kanei cast sto header
      if ((hdr->control & MICROTCP_FLAG_ACK) && 
          hdr->ack_number == socket->seq_number) { // an einai ACK gia to FIN/ACK mas
        socket->state = CLOSED; // thewroume tin syndesi kleisti
      } 
    } 

    if (socket->recvbuf) { // an exei buffer
      free (socket->recvbuf); // eleutherwnei ton buffer
      socket->recvbuf = NULL; // mhdenizei deikti
    } 
    close (socket->sd); // kleinei to real socket
    socket->sd = -1; // markarei oti den exei socket
    free (packet); // eleutherwnei ton prosorino buffer
    return 0; // epistrefei 0 giati teleiwse i syndesi
  } 

  if (hdr->data_len > 0 && (size_t) (received - sizeof(microtcp_header_t)) 
      >= hdr->data_len) { // an yparxei payload kai to lavame olokliro
    /* antigrapse oso payload xwraei sto caller-provided buffer */
    size_t copy_bytes = hdr->data_len; // poso payload na antigrapsoume
    if (copy_bytes > length) { // an o caller edwse mikrotero buffer
      copy_bytes = length; // periorizei sto megethos pou exoume
    } 
    memcpy (buffer, packet + sizeof(microtcp_header_t), copy_bytes); // antigrafei ta data ston caller
    socket->ack_number = hdr->seq_number + hdr->data_len; // enhmerwnei ack gia ta data
    socket->bytes_received += copy_bytes; // ayksanei metrisi bytes poy lavame
    socket->packets_received++; // ayksanei metrisi paketwn poy lavame
    free (packet); // eleutherwnei buffer
    return (ssize_t) copy_bytes; // epistrefei posa bytes edwse ston caller
  } 

  free (packet); // katharizei buffer an den ipa
  return -1; // epistrefei sfalma an den katafera na diavasei dedomena
} 
