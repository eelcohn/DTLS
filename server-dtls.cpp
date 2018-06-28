/* server-dtls.cpp - Simple DTLS (Datagram TLS) server
   written by Eelco Huininga - 2018                        */

#include <stdbool.h>
#include <stdio.h>
#include <cstring>		/* strerror() */
#include <arpa/inet.h>		/* inet_ntop() */
#include <openssl/ssl.h>	/* SSL*, SSL_new(), SSL_get_error(), SSL_set_fd(), SSL_accept(), SSL_get_cipher_version(), SSL_get_cipher_name(), SSL_get_cipher_bits(), SSL_get_verify_result(), SSL_get_peer_certificate(), SSL_read(), SSL_write(), SSL_ERROR_WANT_READ, SSL_ERROR_SYSCALL, SSL_shutdown(), SSL_free() */
#include <openssl/engine.h>	/* ERR_get_error() */

#include "libdtls.h"

#define PORT	33859
#define MAXLEN	4096

static bool done;		/* To handle shutdown */
struct sockaddr_in cliaddr;	/* Client'ss address */

void hexdump(const char *string, int size);

const char	*SSL_CIPHERS	= "ALL:kECDHE:!COMPLEMENTOFDEFAULT:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2:!SSLv3:!TLSv1:!kRSA:!SHA1";
const char	*SSL_SIGALGS	= "ECDSA+SHA512:RSA+SHA512";
const char	*DHFILE		= "dh4096.pem";
const char	*CA		= NULL;
const char	*CERT		= "server-cert.pem";
const char	*PRIVKEY	= "server-key.pem";
const char	reply[]		= "Message received loud 'n clear, Houston!\n";


int main(int argc, char** argv) {
	SSL_CTX*	ctx;
	ssize_t		connfd = 0;
	int		rx_length = 0;		/* length of message */
	int		sock = 0;		/* Initialize our socket */
	int		ssl_errno;		/* SSL error number */
	socklen_t	client_len;
	char		buff[MAXLEN];		/* SSL_read buffer */
	char		ipAddress[INET_ADDRSTRLEN];
	SSL		*ssl = NULL;
	X509		*cert;			/* Placeholder for peer (client) certificate */
	STACK_OF(X509)	*sk;			/* Placeholder for peer (client) certificate chain */


	/* Initialize SSL Engine and context */
	ctx = libdtls::ssl_initialize();

	/* Await Datagram */
	done = false;
	while (done != true) {
		/* Create a new socket */
		sock = libdtls::create_socket(AF_INET, NULL, PORT);
		printf("Listening on UDP port %d\n", PORT);

		client_len = sizeof(cliaddr);
		do {
			connfd = recvfrom(sock, (char *)&buff, sizeof(buff), MSG_PEEK, (struct sockaddr*)&cliaddr, &client_len);
			if (connfd < 0) {
				if (errno != EWOULDBLOCK) {
					printf("recvfrom() failed: %s\n", strerror(errno));
					libdtls::ssl_cleanup(ctx);
					exit(1);
				}
			}
			if (connfd == 0) {
				printf("Peer has performed an orderly shutdown.\n");
				libdtls::ssl_cleanup(ctx);
				exit(1);
			}
		} while (connfd < 0);

		if (connect(sock, (const struct sockaddr *)&cliaddr, sizeof(cliaddr)) != 0) {
			printf("UDP connect failed.\n");
			libdtls::ssl_cleanup(ctx);
			exit(1);
		} else {
			printf("Connected to %s:%d\n", inet_ntop(AF_INET, &(cliaddr.sin_addr), ipAddress, INET_ADDRSTRLEN), cliaddr.sin_port);

			/* Create the OpenSSL object */
			if ((ssl = SSL_new(ctx)) == NULL) {
				libdtls::ssl_print_error("SSL_new", SSL_get_error(ssl, 0));
				libdtls::ssl_cleanup(ctx);
				exit(1);
			}

			/* Set the session ssl to client connection port */
			SSL_set_fd(ssl, sock);

			/* Accept the connection */
			if (SSL_accept(ssl) != 1) {
				libdtls::ssl_print_error("SSL_accept", SSL_get_error(ssl, 0));
				libdtls::ssl_cleanup(ctx);
				exit(1);
			}

			printf("%s handshake completed; secure connection established, using cipher %s (%d bits)\n", SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl), SSL_get_cipher_bits(ssl, NULL));

			/* Verify the client certificate */
			if ((cert = SSL_get_peer_certificate(ssl)) != NULL) {
				X509_print_ex_fp(stdout, x509, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
				if (SSL_get_verify_result(ssl) == X509_V_OK) {
					printf("Client certificate is valid\n");
					sk = SSL_get_peer_cert_chain(ssl);
//					printf("Client certificate's subject: %s", X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
//					printf("Client certificate's issuer: %s", X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0));
//					printf("Client certificate's signature algorithm: %i", X509_get0_tbs_sigalg(cert));
				} else {
					printf("Client certificate is valid\n");
				}
			} else {
				printf("No client certificate received\n");
			}
			X509_free(cert);

			bool blocking  = false;
			do {
				if ((rx_length = SSL_read(ssl, buff, sizeof(buff))) > 0) {
					buff[rx_length] = 0;
					ssl_errno = SSL_get_error(ssl, 0);
					printf("rxlen:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", rx_length, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(ssl));
					printf("Received 0x%04x bytes:\n", rx_length);
					hexdump(buff, rx_length);
					if (SSL_write(ssl, reply, sizeof(reply)) < 0) {
						libdtls::ssl_print_error("SSL_write", SSL_get_error(ssl, 0));
						libdtls::ssl_cleanup(ctx);
						exit(1);
					} else {
						printf("Transmitted 0x%04x bytes:\n", (int)sizeof(reply));
						hexdump(reply, sizeof(reply));
						blocking = false;
					}
				} else {
					ssl_errno = SSL_get_error(ssl, 0);
					printf("rxlen:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", rx_length, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(ssl));
					if((ssl_errno != SSL_ERROR_WANT_READ) && ((ssl_errno == SSL_ERROR_SYSCALL) && (errno != EWOULDBLOCK))){
						libdtls::ssl_print_error("SSL_read", ssl_errno);
						libdtls::ssl_cleanup(ctx);
						exit(1);
					} else
						blocking = true;
				}
			} while (blocking == true);

			printf("Closing connection\n");
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}
	}

	libdtls::ssl_cleanup(ctx);
	return 0;
}

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

