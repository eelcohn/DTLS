/* libdtls.h - DTLS (Datagram TLS) library using OpenSSL */

namespace libdtls {
	SSL_CTX* ssl_initialize(void);
	void ssl_cleanup(SSL_CTX *ctx);
	void ssl_print_error(const char *function, int sslerrno);
	int create_socket(int family, char *address, unsigned short port);
}

