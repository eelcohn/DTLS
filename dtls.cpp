/* dtls.cpp - DTLS (Datagram TLS) library using OpenSSL
   written by Eelco Huininga - 2018                        */

#include <cstring>		/* strerror() */
#include <unistd.h>		/* close() */
#include <arpa/inet.h>		/* sockaddr_in, AF_INET, SOCK_DGRAM, socket(), htons(), INADDR_ANY, htonl(), inet_pton(), SOL_SOCKET, SO_REUSEADDR, setsockopt(), bind() */
#include <openssl/engine.h>	/* ENGINE_cleanup(), ERR_free_strings() */
#include <openssl/conf.h>	/* CONF_modules_unload() */
#include "dtls.h"

struct sockaddr_in peeraddr;	/* Client's address */

const int		SOCKET_TIMEOUT_S = 1;
const int		SOCKET_TIMEOUT_US = 0;
const int		SSL_SECURITY_LVL = 5;
bool			done;

/*
TODO:
replace socket blocking by BIO_set_nbio()
find out how SSL_CTX_set_security_level() works
dtls::verify_certificate()
*/

namespace dtls {
	/* Initialize OpenSSL and create a new SSL context */
	int ssl_initialize(DTLSParams* params) {
		FILE	*fp_dhfile;
		int	codes;

		/* Initialize OpenSSL */
		SSL_library_init();
		SSL_load_error_strings();
		ERR_load_BIO_strings();
		OpenSSL_add_all_algorithms();

		/* Set OpenSSL context to DTLS 1.2 */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		if ((params->ctx = SSL_CTX_new(DTLSv1_2_method())) == NULL) {
			fprintf(stderr, "dtls::ssl_initialize: SSL_CTX_new(DTLSv1_2_method()) failed.\n");
			ERR_print_errors_fp(stderr);
			return(1);
		}
#else
		if ((params->ctx = SSL_CTX_new(DTLS_method())) == NULL) {
			fprintf(stderr, "dtls::ssl_initialize: SSL_CTX_new(DTLS_method) failed.\n");
			ERR_print_errors_fp(stderr);
			return(1);
		}
		if (SSL_CTX_set_min_proto_version(params->ctx, DTLS1_2_VERSION) != 1) {
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "dtls::ssl_initialize: Warning: dtls_InitContextFromKeystore() cannot set minimum supported protocol version\n");
		} 
#endif

		/* Disable SSLv2 and SSLv3 */
		SSL_CTX_set_options(params->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

		/* Set OpenSSL security level */
//		SSL_CTX_set_security_level(ctx, SSL_SECURITY_LVL);

		/* Set available ciphers */
		if (params->ciphers != NULL) {
			if ((SSL_CTX_set_cipher_list(params->ctx, params->ciphers)) != 1) {
				fprintf(stderr, "dtls::ssl_initialize: SSL_CTX_set_ciper_list() failed.\n");
				ERR_print_errors_fp(stderr);
				return(1);
			}
		}

		/* Set available signature algorithms */
		if (params->sigalgs != NULL) {
			if ((SSL_CTX_set1_sigalgs_list(params->ctx, params->sigalgs)) != 1) {
				fprintf(stderr, "dtls::ssl_initialize: SSL_CTX_set1_sigalgs_list() failed.\n");
				ERR_print_errors_fp(stderr);
				return(1);
			}
		}

		/* Set temporary DH parameters */
		SSL_CTX_set_options(params->ctx, SSL_OP_SINGLE_DH_USE);
		if ((fp_dhfile = fopen(params->dhfile, "r")) != NULL) {
			params->dh = PEM_read_DHparams(fp_dhfile, NULL, NULL, NULL);
			fclose(fp_dhfile);

			codes = 0;
			if (params->dh == NULL) {
				fprintf(stderr, "Error reading the DH file\n");
				ERR_print_errors_fp(stderr);
				return(1);
			}
			if (!DH_check(params->dh, &codes)) {
				fprintf(stderr, "dtls::ssl_initialize: DH_check() failed with code %i.\n", codes);
				ERR_print_errors_fp(stderr);
				return(1);
			}
			if (SSL_CTX_set_tmp_dh(params->ctx, params->dh) != 1) {
				fprintf(stderr, "dtls::ssl_initialize: SSL_CTX_set_tmp_dh() failed.\n");
				ERR_print_errors_fp(stderr);
				return(1);
			}
			DH_free(params->dh);
			params->dh = NULL;
		} else {
			fprintf(stderr, "Warning: cannot open Diffie-Hellman parameters: %s\n", strerror(errno));
			ERR_print_errors_fp(stderr);
		}

		/* Load CA certificates */
		if (params->ca != NULL) {
			if (SSL_CTX_load_verify_locations(params->ctx, params->ca, 0) != 1) {
				fprintf(stderr, "dtls::ssl_initialize SSL_CTX_load_verify_locations(): Error loading %s, please check the file.\n", params->ca);
				ERR_print_errors_fp(stderr);
				exit(1);
			}
		}
		/* Load server certificates */
		if (SSL_CTX_use_certificate_file(params->ctx, params->cert, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "dtls::ssl_initialize SSL_CTX_use_certificate_file(): Error loading %s, please check the file.\n", params->cert);
			ERR_print_errors_fp(stderr);
			return(1);
		}
		/* Load server Keys */
		if (SSL_CTX_use_PrivateKey_file(params->ctx, params->privkey, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr, "dtls::ssl_initialize SSL_CTX_use_PrivateKey_file(): Error loading %s, please check the file.\n", params->privkey);
			ERR_print_errors_fp(stderr);
			return(1);
		}
		if (SSL_CTX_check_private_key(params->ctx) != 1) {
			fprintf(stderr, "dtls::ssl_initialize SSL_CTX_check_private_key(): Private key %s not valid for certificate %s.\n", params->privkey, params->cert);
			ERR_print_errors_fp(stderr);
			return(1);
		}

		/* Set client certificate verification mode */
		SSL_CTX_set_verify(params->ctx, params->verify, dtls::verify_certificate);

		/* ..... */
//		SSL_CTX_set_cookie_generate_cb(params->ctx, generate_cookie);
//		SSL_CTX_set_cookie_verify_cb(params->ctx, verify_cookie);

		return 0;
	}

	/* DTLS server code */
	void server(DTLSParams *params) {
		X509		*clientcert;		/* Placeholder for peer (client) certificate */
		STACK_OF(X509)	*clientcertchain;	/* Placeholder for peer (client) certificate chain */
		char		buff[DTLS_MAXLEN];	/* SSL_read buffer */
		int		ssl_errno;		/* SSL error number */
		int		result = 0;		/* Result from SSL_read() and SSL_write(); length of message */
		socklen_t	peeraddr_len;
		int		fd = 0;
		char		ipAddress[INET6_ADDRSTRLEN];

		/* Needed for recvfrom */
		peeraddr_len = sizeof(peeraddr);

		/* Loop while polling for UDP data */
		done = false;
		while (done != true) {
			/* Create a new socket */
			params->socket = dtls::create_socket(params->family, params->blocking, NULL, params->port);
			printf("Listening on UDP port %d\n", params->port);

/*			do {
				connfd = recvfrom(params->socket, (char *)&buff, sizeof(buff), MSG_PEEK, (struct sockaddr*) &clientaddr, &client_len);
				if (connfd < 0) {
					if (errno != EWOULDBLOCK) {
						fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
						dtls::ssl_cleanup(params);
						exit(1);
					}
				}
				if (connfd == 0) {
					fprintf(stderr, "Peer has performed an orderly shutdown.\n");
					dtls::ssl_cleanup(params);
					exit(1);
				}
			} while (connfd < 0);
*/
			/* Create a BIO and link it to the socket */
			params->bio = BIO_new_dgram(params->socket, BIO_NOCLOSE);
			if (params->bio == NULL) {
				dtls::ssl_print_error("BIO_new_dgram", SSL_get_error(params->ssl, 0));
				dtls::ssl_cleanup(params);
				exit(1);
			}

			/* Set the BIO to blocking */
			BIO_set_nbio(params->bio, params->blocking);

			/* Create the OpenSSL object */
			if ((params->ssl = SSL_new(params->ctx)) == NULL) {
				dtls::ssl_print_error("SSL_new", SSL_get_error(params->ssl, 0));
				dtls::ssl_cleanup(params);
				exit(1);
			}

			/* Link the BIO to the SSL object */
			SSL_set_bio(params->ssl, params->bio, params->bio);

			/* Set the SSL object to work in server mode */
			SSL_set_accept_state(params->ssl);


			SSL_do_handshake(params->ssl);

			/* Accept the connection */
			if (SSL_accept(params->ssl) != 1) {
				dtls::ssl_print_error("SSL_accept", SSL_get_error(params->ssl, 0));
				dtls::ssl_cleanup(params);
				exit(1);
			}

			/* Get the underlying socket descriptor, so we can get the peer address */
			if ((fd = SSL_get_fd(params->ssl)) < 0) {
				dtls::ssl_print_error("SSL_get_fd", SSL_get_error(params->ssl, 0));
				dtls::ssl_cleanup(params);
				exit(1);
			}

			/* Get peer address from socket */
			getpeername(params->socket, (sockaddr *)&peeraddr, &peeraddr_len);

			printf("Connected to %s:%d\n", inet_ntop(params->family, &(peeraddr.sin_addr), ipAddress, INET_ADDRSTRLEN), ntohs(peeraddr.sin_port));

			printf("%s handshake completed; secure connection established, using cipher %s (%d bits)\n", SSL_get_cipher_version(params->ssl), SSL_get_cipher_name(params->ssl), SSL_get_cipher_bits(params->ssl, NULL));

			/* Verify the client certificate */
			if ((clientcert = SSL_get_peer_certificate(params->ssl)) != NULL) {
				X509_print_ex_fp(stdout, clientcert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
				if (SSL_get_verify_result(params->ssl) == X509_V_OK) {
					printf("Client certificate is valid\n");
					clientcertchain = SSL_get_peer_cert_chain(params->ssl);
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

			params->blocking  = false;
			do {
				if ((result = SSL_read(params->ssl, buff, sizeof(buff))) > 0) {
					buff[result] = 0;
					ssl_errno = SSL_get_error(params->ssl, 0);
					printf("result:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", result, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(params->ssl));
					printf("Received 0x%04x bytes:\n", result);
					hexdump(buff, result);
					if ((result = (*params->rxhandler)(params->ssl, buff, result)) < 0) {
						dtls::ssl_print_error("SSL_write", SSL_get_error(params->ssl, result));
						dtls::ssl_cleanup(params);
						exit(1);
					} else {
						params->blocking = false;
					}

				} else {
					ssl_errno = SSL_get_error(params->ssl, result);
					printf("result:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", result, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(params->ssl));
					printf("wantread=%i\n", SSL_ERROR_WANT_READ);
					if((ssl_errno != SSL_ERROR_WANT_READ) && ((ssl_errno == SSL_ERROR_SYSCALL) && (errno != EWOULDBLOCK))){
						dtls::ssl_print_error("SSL_read", ssl_errno);
						dtls::ssl_cleanup(params);
						exit(1);
					} else
						params->blocking = true;
				}
			} while (params->blocking == true);

			printf("Closing connection\n");
			if ((ssl_errno = SSL_shutdown(params->ssl)) < 0) {
				dtls::ssl_print_error("SSL_shutdown", ssl_errno);
			}

			dtls::ssl_cleanup(params);
			done=true;
		}
	}
		
	/* DTLS client code */
	void client(DTLSParams *params) {
		X509		*clientcert;		/* Placeholder for peer (client) certificate */
		STACK_OF(X509)	*clientcertchain;	/* Placeholder for peer (client) certificate chain */
		char		buff[DTLS_MAXLEN];	/* SSL_read buffer */
		int		ssl_errno;		/* SSL error number */
		int		result = 0;		/* Result from SSL_read() and SSL_write(); length of message */
		socklen_t	peeraddr_len;
		int		fd = 0;
		char		ipAddress[INET6_ADDRSTRLEN];

		/* Needed for recvfrom */
		peeraddr_len = sizeof(peeraddr);

		/* Create a new socket */
		params->socket = dtls::create_socket(params->family, params->blocking, NULL, params->port);

		/* Create a BIO and link it to the socket */
		params->bio = BIO_new_dgram(params->socket, BIO_NOCLOSE);
		if (params->bio == NULL) {
			dtls::ssl_print_error("BIO_new_dgram", SSL_get_error(params->ssl, 0));
			dtls::ssl_cleanup(params);
			exit(1);
		}

		/* Set the BIO to blocking */
		BIO_set_nbio(params->bio, params->blocking);

		/* Create the OpenSSL object */
		if ((params->ssl = SSL_new(params->ctx)) == NULL) {
			dtls::ssl_print_error("SSL_new", SSL_get_error(params->ssl, 0));
			dtls::ssl_cleanup(params);
			exit(1);
		}

		/* Link the BIO to the SSL object */
		SSL_set_bio(params->ssl, params->bio, params->bio);

		/* Set the hostname to connect to */
		BIO_set_conn_hostname(params->bio, params->address);

		/* Set the SSL object to work in client mode */
		SSL_set_connect_state(params->ssl);

		SSL_set_mode(params->ssl, SSL_MODE_AUTO_RETRY);


		SSL_do_handshake(params->ssl);

		/* Accept the connection */
		if (SSL_connect(params->ssl) != 1) {
			dtls::ssl_print_error("SSL_connect", SSL_get_error(params->ssl, 0));
			dtls::ssl_cleanup(params);
			exit(1);
		}

		/* Get the underlying socket descriptor, so we can get the peer address */
		if ((fd = SSL_get_fd(params->ssl)) < 0) {
			dtls::ssl_print_error("SSL_get_fd", SSL_get_error(params->ssl, 0));
			dtls::ssl_cleanup(params);
			exit(1);
		}

		/* Get peer address from socket */
		getpeername(params->socket, (sockaddr *)&peeraddr, &peeraddr_len);

		printf("Connected to %s:%d\n", inet_ntop(params->family, &(peeraddr.sin_addr), ipAddress, INET_ADDRSTRLEN), ntohs(peeraddr.sin_port));

		printf("%s handshake completed; secure connection established, using cipher %s (%d bits)\n", SSL_get_cipher_version(params->ssl), SSL_get_cipher_name(params->ssl), SSL_get_cipher_bits(params->ssl, NULL));

		/* Verify the server certificate */
		if ((clientcert = SSL_get_peer_certificate(params->ssl)) != NULL) {
			X509_print_ex_fp(stdout, clientcert, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
			if (SSL_get_verify_result(params->ssl) == X509_V_OK) {
				printf("Client certificate is valid\n");
				clientcertchain = SSL_get_peer_cert_chain(params->ssl);
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

		params->blocking  = false;
		do {
			if ((result = SSL_read(params->ssl, buff, sizeof(buff))) > 0) {
				buff[result] = 0;
				ssl_errno = SSL_get_error(params->ssl, 0);
				printf("result:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", result, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(params->ssl));
				printf("Received 0x%04x bytes:\n", result);
				hexdump(buff, result);
				if ((result = (*params->rxhandler)(params->ssl, buff, result)) < 0) {
					dtls::ssl_print_error("SSL_write", SSL_get_error(params->ssl, result));
					dtls::ssl_cleanup(params);
					exit(1);
				} else {
					params->blocking = false;
				}

			} else {
				ssl_errno = SSL_get_error(params->ssl, result);
				printf("result:%i - sslerrno:%i - ERR_get_error:%lu - errno:%i %s - SSLpending:%i\n", result, ssl_errno, ERR_get_error(), errno, strerror(errno), SSL_pending(params->ssl));
				printf("wantread=%i\n", SSL_ERROR_WANT_READ);
				if((ssl_errno != SSL_ERROR_WANT_READ) && ((ssl_errno == SSL_ERROR_SYSCALL) && (errno != EWOULDBLOCK))){
					dtls::ssl_print_error("SSL_read", ssl_errno);
					dtls::ssl_cleanup(params);
					exit(1);
				} else
					params->blocking = true;
			}
		} while (params->blocking == true);

		printf("Closing connection\n");
		if ((ssl_errno = SSL_shutdown(params->ssl)) < 0) {
			dtls::ssl_print_error("SSL_shutdown", ssl_errno);
		}

		dtls::ssl_cleanup(params);
	}

	/* Clean up the SSL context and shutdown the SSL engine */
	void ssl_cleanup(DTLSParams *params) {
		if (params->ssl) {
			SSL_free(params->ssl);
			params->ssl = NULL;
		}
//		if (params->bio) {
//			BIO_free(params->bio);
//			params->bio = NULL;
//		}
		if (params->dh) {
			DH_free(params->dh);
			params->dh = NULL;
		}
		if (params->ctx) {
			SSL_CTX_free(params->ctx);
			params->ctx = NULL;
		}
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		ERR_remove_thread_state(NULL);
#endif
		ENGINE_cleanup();
		CONF_modules_unload(1);
		ERR_free_strings();
		EVP_cleanup();				// Cleanup for OpenSSL_add_all_algorithms();
		SSL_COMP_free_compression_methods();
		CRYPTO_cleanup_all_ex_data();
		if (params->socket) {
			close(params->socket);
			params->socket = -1;
		}
	}

	int verify_certificate(int preverify_ok, X509_STORE_CTX* x509_ctx) {
		X509* cert;
		char  buf[300];

		cert = X509_STORE_CTX_get_current_cert(x509_ctx);
		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
		fprintf(stderr, "dtls::verify_certificate: subject= %s\n", buf);

		if (preverify_ok == 1) {
			fprintf(stderr, "dtls::verify_certificate: Verification passed.\n");
		} else {
			int err = X509_STORE_CTX_get_error(x509_ctx);
			fprintf(stderr, "dtls::verify_certificate: Verification failed: %s.\n", X509_verify_cert_error_string(err));
		}

		return 1;
	}

	/* Print details about a single certificate */
	void print_certificate(X509* cert) {
		const int MAX_LENGTH=1024;

		char subj[MAX_LENGTH+1];
		char issuer[MAX_LENGTH+1];
		X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
		X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
		printf("certificate: %s\n", subj);
		printf("\tissuer: %s\n\n", issuer);
	}

	/* Print details about a certificate chain */
	void print_stack(STACK_OF(X509)* stack) {
		int i, numcerts;

		numcerts = sk_X509_num(stack);
		printf("Begin Certificate Stack:\n");
		for (i = 0; i < numcerts; i++)
			print_certificate(sk_X509_value(stack, i));
		printf("End Certificate Stack\n");
	}

	/* Create a new IPv4 or IPv6 socket */
	int create_socket(const int family, const long blocking, const char *address, const unsigned short port) {
		int sock, reuseconn, result;
		struct timeval timeout;

		/* Create a UDP/IP socket */
		if ((sock = socket(family, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
			fprintf(stderr, "dtls::create_socket: socket() failed.\n");
			return(-1);
		}

		/* Set socket to allow multiple connections */
		reuseconn = 1;
		if ((result = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseconn, sizeof(reuseconn))) < 0) {
			fprintf(stderr, "dtls::create_socket: setsockopt(SO_REUSEADDR) failed.\n");
			return(-2);
		}

		/* Set timeout on socket to prevent recvfrom from blocking execution */
		if (blocking == 1) {
			timeout.tv_sec = SOCKET_TIMEOUT_S;
			timeout.tv_usec = SOCKET_TIMEOUT_US;
			if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
				fprintf(stderr, "create_socket: Error setting timeout on socket");
				return(-3);
			}
		}

		switch (family) {
			case AF_INET :
				struct sockaddr_in addr;

				/* Set IP header */
				bzero(&addr, sizeof(addr));
				addr.sin_family = AF_INET;
				addr.sin_port = htons(port);
				if (address == NULL)
					addr.sin_addr.s_addr = htonl(INADDR_ANY);
				else {
					if (inet_pton(AF_INET, address, (void *)&addr.sin_addr.s_addr) != 1) {
						fprintf(stderr, "dtls::create_socket: Invalid IPv4 address");
						return(-4);
					}
				}

				/* Bind Socket */
				if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
					fprintf(stderr, "dtls::create_socket: IPv4 Unable to bind");
					return(-5);
				}

				break;

			case AF_INET6 :
				struct sockaddr_in6 addr6;

				/* Set IP header */
				bzero(&addr6, sizeof(addr6));
				addr6.sin6_family = AF_INET6;
				addr6.sin6_port = htons(port);
				addr6.sin6_scope_id = 0;
				if (address == NULL)
					addr6.sin6_addr = in6addr_any;
				else {
					if (inet_pton(AF_INET6, address, (void *)&addr6.sin6_addr.s6_addr) != 1) {
						fprintf(stderr, "dtls::create_socket: Invalid IPv6 address");
						return(-6);
					}
				}

				/* Bind Socket */
				if (bind(sock, (struct sockaddr*) &addr6, sizeof(addr6)) < 0) {
					fprintf(stderr, "dtls::create_socket: IPv6 Unable to bind");
					return(-7);
				}

				break;

			default :
				fprintf(stderr, "dtls::create_socket: unknown family");
				exit(-8);
		}

		return(sock);
	}

	/* Close a socket */
	int close_socket(int socket) {
		return close(socket);
	}

	/* Print an user readable SSL error */
	void ssl_print_error(const char *function, int sslerrno) {
		fprintf(stderr, "%s failed with error %i\n", function, sslerrno);
		fprintf(stderr, "ERR_get_error:%lu - errno:%i %s\n", ERR_get_error(), errno, strerror(errno));
		fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
		ERR_print_errors_fp(stderr);

		switch (sslerrno) {
			case SSL_ERROR_NONE :
				fprintf(stderr, "SSL_ERROR_NONE.\n");
				break;

			case SSL_ERROR_ZERO_RETURN :
				fprintf(stderr, "SSL_ERROR_ZERO_RETURN.\n");
				break;

			case SSL_ERROR_WANT_READ :
				fprintf(stderr, "SSL_ERROR_WANT_READ.\n");
				break;

			case SSL_ERROR_WANT_WRITE :
				fprintf(stderr, "SSL_ERROR_WANT_WRITE.\n");
				break;

			case SSL_ERROR_WANT_CONNECT :
				fprintf(stderr, "SSL_ERROR_WANT_CONNECT.\n");
				break;

			case SSL_ERROR_WANT_ACCEPT :
				fprintf(stderr, "SSL_ERROR_WANT_ACCEPT.\n");
				break;

			case SSL_ERROR_WANT_X509_LOOKUP :
				fprintf(stderr, "SSL_ERROR_WANT_X509_LOOKUP.\n");
				break;

	#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
			case SSL_ERROR_WANT_ASYNC :
				fprintf(stderr, "SSL_ERROR_WANT_ASYNC.\n");
				break;
	#endif

			case SSL_ERROR_WANT_ASYNC_JOB :
				fprintf(stderr, "SSL_ERROR_WANT_ASYNC_JOB.\n");
				break;

	#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
			case SSL_ERROR_WANT_CLIENT_HELLO_CB :
				fprintf(stderr, "SSL_ERROR_WANT_CLIENT_HELLO_CB.\n");
				break;
	#endif

			case SSL_ERROR_SYSCALL :
				fprintf(stderr, "SSL_ERROR_SYSCALL.\n");
				fprintf(stderr, "errno: %s\n", strerror(errno));
				break;

			case SSL_ERROR_SSL :
				fprintf(stderr, "SSL_ERROR_SSL.\n");
				break;

			default :
				fprintf(stderr, "unknown error.\n");
				break;
		}
	}
}

