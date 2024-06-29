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
    
    ctx = SSL_CTX_new(TLS_client_method());
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    BIO_set_conn_hostname(sbio, HOSTNAME);

    BIO_puts(sbio, REQ);
    BIO_read(sbio, tmpbuf, BUFLEN);
    size_t len = BIO_read(sbio, tmpbuf, BUFLEN);

    register int64_t rax __asm__ ("rax") = SYS_write;
    register int rdi __asm__ ("rdi") = 1;
    register const void *rsi __asm__ ("rsi") = tmpbuf;
    register size_t rdx __asm__ ("rdx") = len;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx)
        : "rcx", "r11", "memory"
    );
    while (1) {}
    __builtin_unreachable();
}
