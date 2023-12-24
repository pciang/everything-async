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

uv_tcp_t *get_otherend(uv_stream_t *stream)
{
    arelay::cnx_t *pcnx = (arelay::cnx_t *)stream->data;
    return pcnx->otherend;
}

void cascading_cleanup(uv_handle_t *handle)
{
    uv_close((uv_handle_t *)get_otherend((uv_stream_t *)handle), cleanup_bothends);
}

void common_alloc(uv_handle_t *_, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

#endif
