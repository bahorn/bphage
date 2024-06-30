#include <unistd.h>
#include <openssl/ssl.h>

#define HOSTNAME "binary.golf:443"
#define REQ "GET /5/5 HTTP/1.1\r\nHost: " HOSTNAME "\r\n\r\n"

#define SYS_write 0x1
#define BUFLEN 1024


int main()
{
    BIO *sbio = NULL;
    char tmpbuf[BUFLEN];
    SSL_CTX *ctx;
    SSL_CONF_CTX *cctx;
    SSL *ssl;
    
    const void *m = TLS_client_method();
    ctx = SSL_CTX_new(m);
    sbio = BIO_new_ssl_connect(ctx);
    BIO_ctrl(sbio, BIO_C_SET_CONNECT, 0, HOSTNAME);
    BIO_puts(sbio, REQ);
    BIO_read(sbio, tmpbuf, BUFLEN);
    size_t len = BIO_read(sbio, tmpbuf, BUFLEN);
    write(1, tmpbuf, len);
}
