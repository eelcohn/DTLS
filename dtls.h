/* libdtls.h - DTLS (Datagram TLS) library using OpenSSL */

#include <openssl/ssl.h>			/* SSL_VERIFY_NONE */
#include <openssl/x509.h>			/* X509*, STACK_OF(X509)* */

#define DTLS_MAXLEN	4096

enum {DTLS_SERVER, DTLS_CLIENT};

extern bool done;

typedef struct {
	SSL_CTX		*ctx		= NULL;			/* OpenSSL context object */
	SSL		*ssl		= NULL;			/* OpenSSL object */
	DH		*dh		= NULL;			/* OpenSSL Diffie-Hellman object */
	BIO		*bio		= NULL;			/* OpenSSL BIO object */
	long		blocking	= 0;			/* Define if socket is blocking or not */
	int		socket		= -1;			/* Socket identifier */
	int		type		= -1;			/* DTLS_SERVER=server, DTLS_CLIENT=client */
	int		verify		= SSL_VERIFY_NONE;	/* OpenSSL verification mode for verifying certificates (see SSL_CTX_set_verify) */
	int		family		= 0;			/* Protocol family: either AF_INET or AF_INET6 */
	const char	*address	= NULL;			/* Server: Address to bind to, Client: Address to connect to */
	unsigned short	port		= 0;			/* UDP port */
	const char	*ciphers	= NULL;
	const char	*sigalgs	= NULL;
	const char	*dhfile		= NULL;
	const char	*ca		= NULL;
	const char	*cert		= NULL;
	const char	*privkey	= NULL;
	int	(*rxhandler)(SSL *, char *, size_t);		/* Callback for received data handler */
} DTLSParams;

namespace dtls {
	int ssl_initialize(DTLSParams *params);
	void ssl_cleanup(DTLSParams *params);
	void server(DTLSParams *params);
	void client(DTLSParams *params);
	int verify_certificate(int preverify_ok, X509_STORE_CTX* x509_ctx);
	void ssl_print_error(const char *function, int sslerrno);
	void print_certificate(X509* cert);
	void print_stack(STACK_OF(X509)* stack);
	int create_socket(const int family, const long blocking, const char *address, const unsigned short port);
}
void hexdump(const char *string, int size);

