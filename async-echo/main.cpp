#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include "uv.h"

int get_port_from_opts(int argc, char *argv[])
{
    int port = 0,
        retval;
    do
    {
        retval = getopt(argc, argv, "p:h");

        switch (retval)
        {
        case 'p':
            port = std::atoi(optarg);
            break;
        case 'h':
        case '?':
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "  [-h]  show help\n");
            fprintf(stderr, "  (-p)  listen on a port number (e.g. 8080)\n");
        }

    } while (-1 != retval && '?' != retval);

    // if port is unassigned or getopt gone wrong
    if (0 == port || '?' == retval)
    {
        return -1;
    }

    // NOTE: only MacOS
    // this resets, just good to know
    optreset = optind = 1;

    return port;
}

void close_handle(uv_handle_t *handle)
{
    free(handle);
}

void allocate_buffer(uv_handle_t *_, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

uv_write_t *new_write_request(const uv_buf_t *buf)
{
    uv_write_t *pwreq = (uv_write_t *)malloc(sizeof(uv_write_t));

    pwreq->data = buf->base;

    return pwreq;
}

void destruct_write_request(uv_write_t *pwreq)
{
    free((char *)pwreq->data);
    free(pwreq);
}

void after_write_attempt(uv_write_t *pwreq, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "write error: %s\n", uv_err_name(status));
    }

    destruct_write_request(pwreq);
}

void on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    if (0 > nread)
    {
        if (UV_EOF != nread)
        {
            fprintf(stderr, "read error: %s\n", uv_err_name(nread));
        }

        uv_close((uv_handle_t *)client, close_handle);

        if (UV_ENOBUFS != nread)
        {
            free(buf->base);
        }
    }

    else if (0 < nread)
    {
        uv_write_t *pwreq = new_write_request(buf);

        int retval;
        if (0 != (retval = uv_write(pwreq, client, buf, 1, after_write_attempt)))
        {
            destruct_write_request(pwreq);

            fprintf(stderr, "couldn't write to client: %s\n", uv_err_name(retval));
        }
    }
}

void on_new_connection(uv_stream_t *server, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "couldn't accept a new connection\n");
        return;
    }

    int _;

    uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));

    _ = uv_tcp_init(uv_default_loop(), client);

    // guaranteed success every time this cb is invoked
    _ = uv_accept(server, (uv_stream_t *)client);

    int retval;
    if (0 != (retval = uv_read_start((uv_stream_t *)client, allocate_buffer, on_read)))
    {
        fprintf(stderr, "couldn't start reading: %s\n", uv_err_name(retval));

        uv_close((uv_handle_t *)client, close_handle);
    }
}

int main(int argc, char *argv[])
{
    int port = get_port_from_opts(argc, argv);
    if (1023 >= port)
    {
        fprintf(stderr, "please pick a port number >= 1024\n");
        return -1;
    }

    int _; // for ignored return value
    uv_tcp_t server;

    _ = uv_tcp_init(uv_default_loop(), &server);

    int retval;
    sockaddr_in listen_addr;
    if (0 != (retval = uv_ip4_addr("0.0.0.0", port, &listen_addr)))
    {
        fprintf(stderr, "%s\n", uv_err_name(retval));
        return -1;
    }

    if (0 != (retval = uv_tcp_bind(&server, (const sockaddr *)&listen_addr, 0)))
    {
        fprintf(stderr, "couldn't bind: %s\n", uv_err_name(retval));
        return -1;
    }

    if (0 != (retval = uv_listen((uv_stream_t *)&server, 4096, on_new_connection)))
    {
        fprintf(stderr, "server couldn't listen: %s\n", uv_err_name(retval));
        return -1;
    }

    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
