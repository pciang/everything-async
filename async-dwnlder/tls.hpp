#ifndef DWNLDER_TLS_HPP
#define DWNLDER_TLS_HPP

#include <cstdio>

#include "uv.h"

#include "openssl/ssl.h"
#include "openssl/bio.h"

namespace dwnlder
{
    struct tls_ctx_t
    {
        SSL *tls;
        SSL_CTX *tlsctx;
        BIO *rbio,
            *wbio;
    };

    const int SERVICE_HTTPS = 443;
};

void on_keylog_cb(const SSL *ssl, const char *line)
{
    FILE *outfile = fopen("/Users/p.peter/ssl-key.log", "a");
    fprintf(outfile, "%s\n", line);
    fclose(outfile);
}

dwnlder::tls_ctx_t *init_tls(const char *hostname)
{
    int _;

    dwnlder::tls_ctx_t *tls_ctx = (dwnlder::tls_ctx_t *)malloc(sizeof(dwnlder::tls_ctx_t));
    tls_ctx->tlsctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(tls_ctx->tlsctx, SSL_VERIFY_PEER, NULL);
    _ = SSL_CTX_set_min_proto_version(tls_ctx->tlsctx, TLS1_2_VERSION);
    _ = SSL_CTX_set_max_proto_version(tls_ctx->tlsctx, TLS1_3_VERSION);
    _ = SSL_CTX_set_default_verify_paths(tls_ctx->tlsctx);
    SSL_CTX_set_keylog_callback(tls_ctx->tlsctx, on_keylog_cb);
    tls_ctx->rbio = BIO_new(BIO_s_mem());
    tls_ctx->wbio = BIO_new(BIO_s_mem());
    tls_ctx->tls = SSL_new(tls_ctx->tlsctx);
    SSL_set_bio(tls_ctx->tls, tls_ctx->rbio, tls_ctx->wbio);
    _ = SSL_set1_host(tls_ctx->tls, hostname);
    SSL_set_connect_state(tls_ctx->tls);

    return tls_ctx;
}

uv_buf_t *flush_wbio(SSL *tls)
{
    BIO *wbio = SSL_get_wbio(tls);

    uv_buf_t *uvbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));
    uvbuf->len = BIO_ctrl_pending(wbio);
    uvbuf->base = (char *)malloc(uvbuf->len);

    int _ = BIO_read(wbio, uvbuf->base, uvbuf->len);

    return uvbuf;
}

void dbg_show_ctrl_pending(SSL *tls, const char *prefix)
{
    BIO *rbio = SSL_get_rbio(tls),
        *wbio = SSL_get_wbio(tls);
    fprintf(stderr, "%s: rbio = %d, wbio = %d\n", prefix, BIO_ctrl_pending(rbio), BIO_ctrl_pending(wbio));
}

uv_buf_t *ssl_prepare_write(SSL *tls, const char *raw, size_t rawlen)
{
    int offset = 0, retval;
    while (offset < rawlen)
    {
        retval = SSL_write(tls, raw + offset, rawlen - offset);

        if (0 > retval)
        {
            return NULL;
        }
        offset += retval;
    }

    BIO *wbio = SSL_get_wbio(tls);

    uv_buf_t *uvbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));
    uvbuf->base = (char *)malloc(uvbuf->len = BIO_pending(wbio));

    int _ = BIO_read(wbio, uvbuf->base, uvbuf->len);

    return uvbuf;
}

void peek_buf(const char *buf, size_t len, const char *prefix)
{
    for (int offset = 0, framelen; offset + 4 < len && 20 <= *(buf + offset) && 24 >= *(buf + offset); offset += framelen + 5)
    {
        framelen = (((int)*(buf + offset + 3)) << 8) + (unsigned char)*(buf + offset + 4);
        fprintf(stderr, "%s: %u %u %u %d\n", prefix, (unsigned char)*(buf + offset), (unsigned char)*(buf + offset + 1), (unsigned char)*(buf + offset + 2), framelen);
    }
}

void peek_buf(const uv_buf_t *buf, const char *prefix)
{
    peek_buf(buf->base, buf->len, prefix);
}

#endif
