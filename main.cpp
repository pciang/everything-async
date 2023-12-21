#include <cstdio>
#include "uv.h"
#include "opts.hpp"

void alloc_read_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void read_indefinitely(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{

}

void on_new_connection(uv_stream_t *server, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "new connection error: %s\n", uv_strerror(status));
        return;
    }

    uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    if (NULL == client)
    {
        fprintf(stderr, "error malloc-ing new client: %d", errno);
        return;
    }

    if (0 != uv_tcp_init(uv_default_loop(), client))
    {
        fprintf(stderr, "error initialising a new tcp client\n");
        return;
    }

    if (0 != uv_accept(server, (uv_stream_t *)client))
    {
        fprintf(stderr, "error accepting a new tcp client\n");
        return;
    }

    // if (0 != uv_read_start((uv_stream_t*) client, alloc_read_buffer, ))
}

int main(int argc, char *argv[])
{
    uv_tcp_t server;

    bkc::parse_err_t parse_err = bkc::parse_opts(argc, argv);
    if (bkc::parse_success != parse_err)
    {
        return -1;
    }

    sockaddr_in listen_addr;
    if (0 != uv_ip4_addr("0.0.0.0", bkc::opts.port, &listen_addr))
    {
        fprintf(stderr, "couldn't prepare listen address\n");
        return -1;
    }

    if (0 != uv_tcp_init(uv_default_loop(), &server))
    {
        fprintf(stderr, "couldn't init a tcp server\n");
        return -1;
    }

    if (0 != uv_tcp_bind(&server, (const struct sockaddr *)&listen_addr, 0))
    {
        fprintf(stderr, "couldn't bind the listening address\n");
        return -1;
    }

    // uv_listen((uv_stream_t *)&server, SOMAXCONN, nullptr);

    return 0;
}
