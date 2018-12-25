/* server-dtls.cpp - Simple DTLS (Datagram TLS) server
   written by Eelco Huininga - 2018                        */

#include <stdbool.h>		/* true, false */
#include <cstring>		/* strerror(), strlen() */
#include <arpa/inet.h>		/* AF_INET, AF_INET6 */
#include <openssl/ssl.h>	/* SSL*, SSL_new(), SSL_get_error(), SSL_set_fd(), SSL_accept(), SSL_get_cipher_version(), SSL_get_cipher_name(), SSL_get_cipher_bits(), SSL_get_verify_result(), SSL_get_peer_certificate(), SSL_read(), SSL_write(), SSL_ERROR_WANT_READ, SSL_ERROR_SYSCALL, SSL_shutdown() */
#include <openssl/engine.h>	/* ERR_get_error() */

#include "dtls-server.h"
#include "dtls.h"

extern bool	done;



int main(__attribute__((__unused__))int argc, __attribute__((__unused__))char** argv) {
	DTLSParams	server;				/* All variables and objects for this DTLS connection */

	/* Initialize SSL Engine and context */
	server.type		= DTLS_SERVER;		/* Initialize an OpenSSL server context */
	server.family		= AF_INET4;		/* IPv4 connection */
	server.address		= "0.0.0.0";		/* IP address to bind to */
	server.port		= 9999;			/* UDP port number */
	server.ciphers		= "ALL:kECDHE:!COMPLEMENTOFDEFAULT:!EXPORT:!EXP:!LOW:!MD5:!aNULL:!eNULL:!SSLv2:!SSLv3:!TLSv1:!ADH:!kRSA:!SHA1";
	server.sigalgs		= "ECDSA+SHA512:RSA+SHA512";
	server.dhfile		= "./dh4096.pem";
	server.ca		= NULL;
	server.cert		= "./server-cert.pem";
	server.privkey		= "./server-key.pem";
	server.rxhandler	= rxHandler;		/* Handler for received data */

	if (dtls::ssl_initialize(&server) != 0) {
		fprintf(stderr, "dtls::ssl_initialize failed\n");
		return -1;
	}

	/* Start DTLS server loop */
	dtls::server(&server);

	return 0;
}

/* A simple handler for received data over the DTLS connection */
int rxHandler(SSL *ssl, char *rx_data, size_t rx_length) {
	char tx_data[DTLS_MAXLEN];
	int result;

	sprintf(tx_data, "Message received loud 'n clear, Houston! We've received %lu bytes.\n", rx_length);
	if ((result = SSL_write(ssl, tx_data, strlen(tx_data))) < 0) {
		return result;
	} else {
		printf("Transmitted 0x%04x bytes:\n", result);
		hexdump(tx_data, result);
	}

	return result;
}

/* Print a string in hexadecimal values */
void hexdump(const char *string, int size) {
	int i, offset;

	offset = 0;
	while ((size - offset) > 0) {
		printf("%04X  ", offset);

		for (i = 0; i < 16; i++) {
			if ((offset + i) < size)
				printf("%02X ", string[offset + i]);
			else
				printf("   ");
		}
		printf(" ");
		for (i = 0; i < 16; i++) {
			if ((offset + i) < size) {
				if ((string[offset + i] > 31) && (string[offset + i] < 127))
					printf("%c", string[offset + i]);
				else
					printf(".");
			}
		}
		printf("\n");
		offset += 16;
	}
}

