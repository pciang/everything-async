#ifndef ARELAY_MAIN_HPP
#define ARELAY_MAIN_HPP

#include "uv.h"

namespace arelay
{
    struct prog_t // holds important info for the program
    {
        addrinfo *res;
    };

    struct cnx_t // holds important info for a tcp connection
    {
        uv_tcp_t *otherend;
        void *pfreeable_pair,
            *pfreeable_data;
        int flag;
    };
};

uv_tcp_t *make_pair()
{
    uv_tcp_t *ppair = (uv_tcp_t *)malloc(2 * sizeof(uv_tcp_t));

    int _;
    _ = uv_tcp_init(uv_default_loop(), &ppair[0]);
    _ = uv_tcp_init(uv_default_loop(), &ppair[1]);

    arelay::cnx_t *pcnx = (arelay::cnx_t *)malloc(2 * sizeof(arelay::cnx_t));
    pcnx[0].otherend = &ppair[1];
    pcnx[1].otherend = &ppair[0];

    pcnx[0].pfreeable_pair = pcnx[1].pfreeable_pair = ppair;
    pcnx[0].pfreeable_data = pcnx[1].pfreeable_data = pcnx;

    ppair[0].data = &pcnx[0];
    ppair[1].data = &pcnx[1];

    return ppair;
}

void cleanup_bothends(uv_handle_t *handle)
{
    arelay::cnx_t *pcnx = (arelay::cnx_t *)handle->data;

    free(pcnx->pfreeable_data);
    free(pcnx->pfreeable_pair);
}

uv_stream_t *get_otherend(uv_stream_t *stream)
{
    arelay::cnx_t *pcnx = (arelay::cnx_t *)stream->data;
    return (uv_stream_t *)pcnx->otherend;
}

uv_handle_t *get_otherend(uv_handle_t *handle)
{
    arelay::cnx_t *pcnx = (arelay::cnx_t *)handle->data;
    return (uv_handle_t *)pcnx->otherend;
}

void cascading_cleanup(uv_handle_t *handle)
{
    uv_close(get_otherend(handle), cleanup_bothends);
}

void common_alloc(uv_handle_t *_, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void destruct_shutdown_request(uv_shutdown_t *req, int status)
{
    switch (status)
    {
    case 0:
        // when both ends have sent EOF, it's time to close them
        if (!uv_is_writable(req->handle) && !uv_is_writable(get_otherend(req->handle)))
        {
            uv_close((uv_handle_t *)req->handle, cleanup_bothends);
        }
        break;
    case UV_ECANCELED:
        break;
    default:
        fprintf(stderr, "error after shutdown attempt: %s\n", uv_strerror(status));
        break;
    }

    free(req);
}

uv_write_t *make_write_request(char *base, ssize_t nread)
{
    uv_buf_t *pwbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));
    pwbuf->base = base;
    pwbuf->len = nread;

    uv_write_t *pwreq = (uv_write_t *)malloc(sizeof(uv_write_t));
    pwreq->data = pwbuf;

    return pwreq;
}

void destruct_write_request(uv_write_t *pwreq)
{
    uv_buf_t *pwbuf = (uv_buf_t *)pwreq->data;
    free(pwbuf->base);
    free(pwbuf);

    free(pwreq);
}

#endif
