/* libdtls.cpp - DTLS (Datagram TLS) library using OpenSSL
   written by Eelco Huininga - 2018                        */

#include <cstring>		/* memset() */
#include <arpa/inet.h>		/* sockaddr_in, AF_INET, SOCK_DGRAM, socket(), htons(), INADDR_ANY, htonl(), inet_pton(), SOL_SOCKET, SO_REUSEADDR, setsockopt(), bind() */
#include <openssl/ssl.h>
#include <openssl/engine.h>	/* ENGINE_cleanup(), ERR_free_strings() */
#include <openssl/conf.h>	/* CONF_modules_unload() */

const int		SOCKET_TIMEOUT_S = 1;
const int		SOCKET_TIMEOUT_US = 0;
const int		SSL_SECURITY_LVL = 5;
extern const char	*SSL_CIPHERS;
extern const char	*SSL_SIGALGS;
extern const char	*DHFILE;
extern const char	*CA;
extern const char	*CERT;
extern const char	*PRIVKEY;
extern const char	reply[];


namespace libdtls {
	/* Initialize OpenSSL and create a new SSL context */
	SSL_CTX* ssl_initialize(void) {
		int		codes;
		FILE		*fp_dhfile;
		SSL_CTX		*ctx;
		DH		*dh;

		/* Initialize OpenSSL */
		SSL_library_init();
		SSL_load_error_strings();
		ERR_load_BIO_strings();
		OpenSSL_add_all_algorithms();

		/* Set OpenSSL security level */
		SSL_CTX_set_security_level(ctx, SSL_SECURTIY_LVL);

		/* Set OpenSSL context to DTLS 1.2 */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		if ((ctx = SSL_CTX_new(DTLSv1_2_server_method())) == NULL) {
			printf("libdtls::ssl_initialize: SSL_CTX_new failed.\n");
			exit(1);
		}
#else
		if ((ctx = SSL_CTX_new(DTLS_server_method())) == NULL) {
			printf("libdtls::ssl_initialize: SSL_CTX_new(DTLS_server_method) failed.\n");
			exit(1);
		}
		if (SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION) != 1) {
			printf("libdtls::ssl_initialize: Warning: dtls_InitContextFromKeystore() cannot set minimum supported protocol version\n");
		} 
#endif

		/* Set available ciphers */
		if (SSL_CIPHERS != NULL) {
			if ((SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS)) != 1) {
				printf("libdtls::ssl_initialize: SSL_CTX_set_ciper_list() failed.\n");
				exit(1);
			}
		}

		/* Set available signature algorithms */
		if (SSL_SIGALGS != NULL) {
			if ((SSL_CTX_set1_sigalgs_list(ctx, SSL_SIGALGS)) != 1) {
				printf("libdtls::ssl_initialize: SSL_CTX_set1_sigalgs_list() failed.\n");
				exit(1);
			}
		}

		/* Set temporary DH parameters */
		SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
		if ((fp_dhfile = fopen(DHFILE, "r")) != NULL) {
			dh = PEM_read_DHparams(fp_dhfile, NULL, NULL, NULL);
			fclose(fp_dhfile);

			codes = 0;
			if (!DH_check(dh, &codes)) {
				printf("libdtls::ssl_initialize: DH_check() failed with code %i.\n", codes);
				exit(1);
			}
			if (SSL_CTX_set_tmp_dh (ctx, dh) != 1) {
				printf("libdtls::ssl_initialize: SSL_CTX_set_tmp_dh() failed.\n");
				exit(1);
			}
			DH_free(dh);
		}

		/* Load CA certificates */
		if (CA != NULL) {
			if (SSL_CTX_load_verify_locations(ctx, CA, 0) != 1) {
				printf("libdtls::ssl_initialize: Error loading %s, please check the file.\n", CA);
				exit(1);
			}
		}
		/* Load server certificates */
		if (SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM) != 1) {
			printf("libdtls::ssl_initialize: Error loading %s, please check the file.\n", CERT);
			exit(1);
		}
		/* Load server Keys */
		if (SSL_CTX_use_PrivateKey_file(ctx, PRIVKEY, SSL_FILETYPE_PEM) != 1) {
			printf("libdtls::ssl_initialize: Error loading %s, please check the file.\n", PRIVKEY);
			exit(1);
		}
		if (SSL_CTX_check_private_key(ctx) != 1) {
			printf("libdtls::ssl_initialize: Private key %s not valid.\n", PRIVKEY);
			exit(1);
		}

//		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		return ctx;
	}

	/* Clean up the SSL context and shutdown the SSL engine */
	void ssl_cleanup(SSL_CTX *ctx) {
		SSL_CTX_free(ctx);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		ERR_remove_thread_state(NULL);
#endif
		ENGINE_cleanup();
		CONF_modules_unload(1);
		ERR_free_strings();
		EVP_cleanup();						// Cleanup for OpenSSL_add_all_algorithms();
	//	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
		CRYPTO_cleanup_all_ex_data();
	}

	/* Print an user readable SSL error */
	void ssl_print_error(const char *function, int sslerrno) {
		printf("sslerrno:%i - ERR_get_error:%lu - errno:%i %s\n", sslerrno, ERR_get_error(), errno, strerror(errno));
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		printf("%s failed with error ", function);


		switch (sslerrno) {
			case SSL_ERROR_NONE :
				printf("SSL_ERROR_NONE.\n");
				break;

			case SSL_ERROR_ZERO_RETURN :
				printf("SSL_ERROR_ZERO_RETURN.\n");
				break;

			case SSL_ERROR_WANT_READ :
				printf("SSL_ERROR_WANT_READ.\n");
				break;

			case SSL_ERROR_WANT_WRITE :
				printf("SSL_ERROR_WANT_WRITE.\n");
				break;

			case SSL_ERROR_WANT_CONNECT :
				printf("SSL_ERROR_WANT_CONNECT.\n");
				break;

			case SSL_ERROR_WANT_ACCEPT :
				printf("SSL_ERROR_WANT_ACCEPT.\n");
				break;

			case SSL_ERROR_WANT_X509_LOOKUP :
				printf("SSL_ERROR_WANT_X509_LOOKUP.\n");
				break;

	#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
			case SSL_ERROR_WANT_ASYNC :
				printf("SSL_ERROR_WANT_ASYNC.\n");
				break;
	#endif

			case SSL_ERROR_WANT_ASYNC_JOB :
				printf("SSL_ERROR_WANT_ASYNC_JOB.\n");
				break;

	#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
			case SSL_ERROR_WANT_CLIENT_HELLO_CB :
				printf("SSL_ERROR_WANT_CLIENT_HELLO_CB.\n");
				break;
	#endif

			case SSL_ERROR_SYSCALL :
				printf("SSL_ERROR_SYSCALL.\n");
				break;

			case SSL_ERROR_SSL :
				printf("SSL_ERROR_SSL.\n");
				break;

			default :
				printf("unknown error.\n");
				break;
		}
	}

	int create_socket(int family, char *address, unsigned short port) {
		int sock, reuseconn, result;
		struct timeval timeout;

		/* Create a UDP/IP socket */
		if ((sock = socket(family, SOCK_DGRAM, 0)) < 0 ) {
			printf("create_socket: socket() failed.\n");
			return(-1);
		}

		/* Set socket to allow multiple connections */
		reuseconn = 1;
		if ((result = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseconn, sizeof(reuseconn))) < 0) {
			printf("create_socket: setsockopt(SO_REUSEADDR) failed.\n");
			return(-2);
		}

		/* Set timeout on socket to prevent recvfrom from blocking execution */
		timeout.tv_sec = SOCKET_TIMEOUT_S;
		timeout.tv_usec = SOCKET_TIMEOUT_US;
		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			printf("create_socket: Error setting timeout on socket");
			return(-3);
		}

		switch (family) {
			case AF_INET :
				struct sockaddr_in addr;

				/* Set IP header */
				memset((char *)&addr, 0, sizeof(addr));
				addr.sin_family = AF_INET;
				addr.sin_port = htons(port);
				if (address == NULL)
					addr.sin_addr.s_addr = htonl(INADDR_ANY);
				else {
					if (inet_pton(AF_INET, address, (void *)&addr.sin_addr.s_addr) != 1) {
						printf("create_socket: Invalid IPv4 address");
						return(-4);
					}
				}

				/* Bind Socket */
				if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
					printf("create_socket: IPv4 Unable to bind");
					return(-5);
				}

				break;

			case AF_INET6 :
				struct sockaddr_in6 addr6;

				/* Set IP header */
				memset((char *)&addr6, 0, sizeof(addr6));
				addr6.sin6_family = AF_INET6;
				addr6.sin6_port = htons(port);
				addr6.sin6_scope_id = 0;
				if (address == NULL)
					addr6.sin6_addr = in6addr_any;
				else {
					if (inet_pton(AF_INET6, address, (void *)&addr6.sin6_addr.s6_addr) != 1) {
						printf("create_socket: Invalid IPv6 address");
						return(-6);
					}
				}

				/* Bind Socket */
				if (bind(sock, (struct sockaddr*) &addr6, sizeof(addr6)) < 0) {
					printf("ccreate_socket: IPv6 Unable to bind");
					return(-7);
				}

				break;

			default :
				printf("ccreate_socket: unknown family");
				exit(-8);
		}

		return(sock);
	}
}
