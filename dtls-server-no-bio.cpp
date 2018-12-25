/* server-dtls.cpp - Simple DTLS (Datagram TLS) server
   written by Eelco Huininga - 2018                        */

#include <stdbool.h>
#include <stdio.h>
#include <cstring>		/* strerror() */
#include <arpa/inet.h>		/* inet_ntop() */
#include <openssl/ssl.h>	/* SSL*, SSL_new(), SSL_get_error(), SSL_set_fd(), SSL_accept(), SSL_get_cipher_version(), SSL_get_cipher_name(), SSL_get_cipher_bits(), SSL_get_verify_result(), SSL_get_peer_certificate(), SSL_read(), SSL_write(), SSL_ERROR_WANT_READ, SSL_ERROR_SYSCALL, SSL_shutdown() */
#include <openssl/engine.h>	/* ERR_get_error() */

#include "dtls.h"

#define PORT	33859
#define MAXLEN	4096

static bool done;		/* To handle shutdown */
struct sockaddr_in clientaddr;	/* Client's address */

void hexdump(const char *string, int size);

const char	*SSL_CIPHERS	= "ALL:kECDHE:!COMPLEMENTOFDEFAULT:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2:!SSLv3:!TLSv1:!kRSA:!SHA1";
const char	*SSL_SIGALGS	= "ECDSA+SHA512:RSA+SHA512";
const char	*DHFILE		= "./dh4096.pem";
const char	*CA		= NULL;
const char	*CERT		= "./server-cert.pem";
const char	*PRIVKEY	= "./server-key.pem";
const char	reply[]		= "Message received loud 'n clear, Houston!\n";


int main(__attribute__((__unused__))int argc, __attribute__((__unused__))char** argv) {
	DTLSParams	server;			/* All variables and objects for this DTLS connection */
	X509		*clientcert;		/* Placeholder for peer (client) certificate */
	STACK_OF(X509)	*clientcertchain;	/* Placeholder for peer (client) certificate chain */
	socklen_t	client_len;
	ssize_t		connfd = 0;
	char		buff[MAXLEN];		/* SSL_read buffer */
	char		ipAddress[INET6_ADDRSTRLEN];
	int		result = 0;		/* Result from SSL_read() and SSL_write(); length of message */
	int		ssl_errno;		/* SSL error number */
	bool		blocking;

	/* Needed for recvfrom */
	client_len = sizeof(clientaddr);

	/* Initialize SSL Engine and context */
	server.type = DTLS_SERVER;					// Initialize an OpenSSL server context
	if (libdtls::ssl_initialize(&server) != 0) {
		fprintf(stderr, "libdtls::ssl_initialize failed\n");
		return -1;
	}

	/* Loop while polling for UDP data */
	done = false;
	while (done != true) {
		/* Create a new socket */
		server.socket = libdtls::create_socket(AF_INET, true, NULL, PORT);
		printf("Listening on UDP port %d\n", PORT);

		/* Create a BIO and link it to the socket */
		server.bio = BIO_new_dgram(server.socket, BIO_NOCLOSE);
		if (server.bio == NULL) {
			fprintf(stderr, "error creating bio\n");
			return EXIT_FAILURE;
		}

		/* Create the OpenSSL object */
		if ((server.ssl = SSL_new(server.ctx)) == NULL) {
			libdtls::ssl_print_error("SSL_new", SSL_get_error(server.ssl, 0));
			libdtls::ssl_cleanup(&server);
			exit(1);
		}

		/* Link the BIO to the SSL object */
		SSL_set_bio(server.ssl, server.bio, server.bio);

		/* Set the SSL object to work in server mode */
		SSL_set_accept_state(server.ssl);

		do {
			connfd = recvfrom(server.socket, (char *)&buff, sizeof(buff), MSG_PEEK, (struct sockaddr*) &clientaddr, &client_len);
			if (connfd < 0) {
				if (errno != EWOULDBLOCK) {
					fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
					libdtls::ssl_cleanup(&server);
					exit(1);
				}
			}
			if (connfd == 0) {
				fprintf(stderr, "Peer has performed an orderly shutdown.\n");
				libdtls::ssl_cleanup(&server);
				exit(1);
			}
		} while (connfd < 0);

		if (connect(server.socket, (const struct sockaddr *)&clientaddr, sizeof(clientaddr)) != 0) {
			fprintf(stderr, "connect(): UDP connect failed.\n");
			libdtls::ssl_cleanup(&server);
			exit(1);
		} else {
			printf("Connected to %s:%d\n", inet_ntop(AF_INET, &(clientaddr.sin_addr), ipAddress, INET_ADDRSTRLEN), clientaddr.sin_port);

			/* Set the session ssl to client connection port */
			SSL_set_fd(server.ssl, server.socket);

			/* Accept the connection */
			if (SSL_accept(server.ssl) != 1) {
				libdtls::ssl_print_error("SSL_accept", SSL_get_error(server.ssl, 0));
				libdtls::ssl_cleanup(&server);
				exit(1);
			}

			printf("%s handshake completed; secure connection established, using cipher %s (%d bits)\n", SSL_get_cipher_version(server.ssl), SSL_get_cipher_name(server.ssl), SSL_get_cipher_bits(server.ssl, NULL));

			/* Verify the client certificate */
			if ((clientcert = SSL_get_peer_certificate(server.ssl)) != NULL) {
				X509_print_ex_fp(stdout, clientcert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
				if (SSL_get_verify_result(server.ssl) == X509_V_OK) {
					printf("Client certificate is valid\n");
					clientcertchain = SSL_get_peer_cert_chain(server.ssl);
					printf("Client certificate's subject: %s", X509_NAME_oneline(X509_get_subject_name(clientcert), NULL, 0));
					printf("Client certificate's issuer: %s", X509_NAME_oneline(X509_get_issuer_name(clientcert), NULL, 0));
					printf("Client certificate's signature algorithm: %i", X509_get0_tbs_sigalg(clientcert));
					sk_X509_free(clientcertchain);
				} else {
					printf("Client certificate is valid\n");
				}
			} else {
				printf("No client certificate received\n");
			}
			X509_free(clientcert);

			blocking  = false;
			do {
				if ((result = SSL_read(server.ssl, buff, sizeof(buff))) > 0) {
					buff[result] = 0;
					ssl_errno = SSL_get_error(server.ssl, 0);
					printf("result:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", result, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(server.ssl));
					printf("Received 0x%04x bytes:\n", result);
					hexdump(buff, result);
					if ((result = SSL_write(server.ssl, reply, sizeof(reply))) < 0) {
						libdtls::ssl_print_error("SSL_write", SSL_get_error(server.ssl, result));
						libdtls::ssl_cleanup(&server);
						exit(1);
					} else {
						printf("Transmitted 0x%04x bytes:\n", (int)sizeof(reply));
						hexdump(reply, sizeof(reply));
						blocking = false;
					}
				} else {
					ssl_errno = SSL_get_error(server.ssl, result);
					printf("result:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", result, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(server.ssl));
					if((ssl_errno != SSL_ERROR_WANT_READ) && ((ssl_errno == SSL_ERROR_SYSCALL) && (errno != EWOULDBLOCK))){
						libdtls::ssl_print_error("SSL_read", ssl_errno);
						libdtls::ssl_cleanup(&server);
						exit(1);
					} else
						blocking = true;
				}
			} while (blocking == true);

			printf("Closing connection\n");
			if ((ssl_errno = SSL_shutdown(server.ssl)) < 0) {
				libdtls::ssl_print_error("SSL_shutdown", ssl_errno);
			}
done=true;
		}
	}

	libdtls::ssl_cleanup(&server);
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

