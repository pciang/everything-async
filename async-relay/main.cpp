#include <cstdio>
#include <cstring>
#include <string>

#include "uv.h"

#include "main.hpp"
#include "opts.hpp"

void on_attempted_write(uv_write_t *pwreq, int status)
{
    if (0 != status)
    {
        // ensure that subsequent cancelled write_cb(s) don't repeat this
        if (UV_ECANCELED != status)
        {
            int _;

            // immediately prevent read_cb from being invoked;
            _ = uv_read_stop(pwreq->handle);
            _ = uv_read_stop(get_otherend(pwreq->handle));

            uv_close((uv_handle_t *)pwreq->handle, cascading_cleanup);
        }

        fprintf(stderr, "error after write attempt %p: %s\n", (void *)pwreq->handle, uv_strerror(status));
    }

    destruct_write_request(pwreq);
}

void on_data_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    int _;

    if (0 >= nread)
    {
        switch (nread)
        {
        case 0: // EAGAIN or EWOULDBLOCK
            break;

        default:
        {
            _ = uv_read_stop(stream);

            uv_shutdown_t *pshutreq = (uv_shutdown_t *)malloc(sizeof(uv_shutdown_t));
            _ = uv_shutdown(pshutreq, get_otherend(stream), destruct_shutdown_request);

            if (UV_EOF != nread)
            {
                fprintf(stderr, "error while reading %p: %s\n", (void *)stream, uv_strerror(nread));
            }

            break;
        }
        }

        if (NULL != buf->base)
        {
            free(buf->base);
        }

        return;
    }

    int retval;

    uv_stream_t *otherend = get_otherend(stream);

    uv_write_t *pwreq = make_write_request(buf->base, nread);
    uv_buf_t *pbuf = (uv_buf_t *)pwreq->data;

    if (0 != (retval = uv_write(pwreq, otherend, pbuf, 1, on_attempted_write)))
    {
        _ = uv_read_stop(stream);
        _ = uv_read_stop(otherend);

        uv_close((uv_handle_t *)stream, cascading_cleanup);

        destruct_write_request(pwreq);

        fprintf(stderr, "error while attempting to write %p -> %p: %s\n", (void *)stream, (void *)otherend, uv_strerror(retval));
        return;
    }
}

void on_otherend_connected(uv_connect_t *req, int status)
{
    int _;

    if (0 != status)
    {
        // close client and cleanup both sockets
        uv_close((uv_handle_t *)get_otherend(req->handle), cleanup_bothends);

        fprintf(stderr, "couldn't connect to the other end: %s\n", uv_strerror(status));

        free(req);
        return;
    }

    int retval;

    uv_stream_t *otherend = req->handle,
                *client = get_otherend(otherend);

    if (0 != (retval = uv_read_start(client, common_alloc, on_data_read)))
    {
        uv_close((uv_handle_t *)client, cascading_cleanup);

        fprintf(stderr, "couldn't start reading from client %p: %s\n", (void *)client, uv_strerror(retval));

        free(req);
        return;
    }

    if (0 != (retval = uv_read_start(otherend, common_alloc, on_data_read)))
    {
        _ = uv_read_stop(client);

        uv_close((uv_handle_t *)otherend, cascading_cleanup);

        fprintf(stderr, "couldn't start reading from otherend %p: %s\n", (void *)otherend, uv_strerror(retval));

        free(req);
        return;
    }

    free(req);
}

void on_new_client(uv_stream_t *server, int status)
{
    if (0 != status)
    {
        fprintf(stderr, uv_strerror(status));
        return;
    }

    uv_tcp_t *client = make_pair(),
             *otherend = &client[1];
    uv_loop_t *loop = server->loop;
    arelay::prog_t *pprog = (arelay::prog_t *)loop->data;

    int _, retval;

    _ = uv_accept(server, (uv_stream_t *)client);

    uv_connect_t *connreq = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    if (0 != (retval = uv_tcp_connect(connreq, otherend, pprog->res->ai_addr, on_otherend_connected)))
    {
        uv_close((uv_handle_t *)client, cleanup_bothends);

        fprintf(stderr, "couldn't connect to the other end: %s\n", uv_strerror(retval));
        return;
    }
}

void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    if (0 != status)
    {
        fprintf(stderr, "couldn't resolve destination address: %s\n", uv_strerror(status));
        return;
    }

    arelay::prog_t *pprog = (arelay::prog_t *)req->loop->data;

    uv_freeaddrinfo(pprog->res); // NULL is no-op

    pprog->res = res;
}

int main(int argc, char *argv[])
{
    arelay::parse_errcode_t parse_err = arelay::parse_opts(argc, argv);

    if (arelay::parse_success != parse_err)
    {
        fprintf(stderr, "%s\n", arelay::parse_errstr(parse_err));
        return -1;
    }

    uv_loop_t *loop = uv_default_loop();

    arelay::prog_t *pprog = (arelay::prog_t *)malloc(sizeof(arelay::prog_t));

    memset(pprog, 0, sizeof(arelay::prog_t));

    loop->data = pprog;

    int retval;

    sockaddr_in destin_addr;
    if (0 != (retval = uv_ip4_addr(arelay::opts.destination_host.c_str(), arelay::opts.destination_port, &destin_addr)))
    {
        fprintf(stderr, "invalid destination address: %s\n", uv_strerror(retval));
        return -1;
    }

    addrinfo hint;
    memset(&hint, 0, sizeof(addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;

    uv_getaddrinfo_t *addrreso_req = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));

    std::string destination_port = std::to_string(arelay::opts.destination_port);

    if (0 != (retval = uv_getaddrinfo(loop, addrreso_req, on_resolved, arelay::opts.destination_host.c_str(), destination_port.c_str(), &hint)))
    {
        fprintf(stderr, "error while invoking uv_getaddrinfo: %s\n", uv_strerror(retval));
        return -1;
    }

    sockaddr_in listen_addr;
    if (0 != (retval = uv_ip4_addr("0.0.0.0", arelay::opts.port, &listen_addr)))
    {
        fprintf(stderr, "invalid listen address: %s\n", uv_strerror(retval));
        return -1;
    }

    int _;

    uv_tcp_t server;

    _ = uv_tcp_init(loop, &server);

    if (0 != (retval = uv_tcp_bind(&server, (const sockaddr *)&listen_addr, 0)))
    {
        fprintf(stderr, "couldn't bind server to the address: %s\n", uv_strerror(retval));
        return -1;
    }

    if (0 != (retval = uv_listen((uv_stream_t *)&server, 4096, on_new_client)))
    {
        fprintf(stderr, "couldn't listen on that port: %s\n", uv_strerror(retval));
        return -1;
    }

    return uv_run(loop, UV_RUN_DEFAULT);
}
