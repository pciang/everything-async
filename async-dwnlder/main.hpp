#ifndef DWNLDER_MAIN_HPP
#define DWNLDER_MAIN_HPP

#include <cstdio>
#include <cstring>
#include <string>
#include <map>
#include <utility>

#include "getopt.h"

#include "uv.h"
#include "llhttp.h"

#include "tls.hpp"

typedef std::map<std::string, std::string> header_t;

namespace dwnlder
{

    const char *TEMPLATE_GET = "GET {path} HTTP/1.1\r\n"
                               "Host: {host}\r\n"
                               "User-Agent: async-dwnlder\r\n"
                               "Accept: */*\r\n"
                               "Accept-Encoding: identity\r\n"
                               "Connection: close\r\n"
                               "\r\n";

    struct opts_t
    {
        int port;
        std::string host, path, outfile;
    } opts;

    const char *OPTSTRING = "H:p:P:o:h";

    const char *HELPSTR =
        "[-h]  display help\n"
        "(-H)  host (e.g.: upload.wikimedia.org)\n"
        "(-p)  port (e.g.: 80)\n"
        "(-P)  resource path (e.g.: /somewhere/afile.txt)\n"
        "(-o)  saved file name (e.g.: ./afile.txt)\n";

    int parse_opts(int argc, char *argv[])
    {
        // TODO: maybe use a url parser

        int retval;

        do
        {
            retval = getopt(argc, argv, OPTSTRING);

            switch (retval)
            {
            case 'H':
                opts.host = optarg;
                break;
            case 'p':
                opts.port = std::stoi(std::string(optarg));
                break;
            case 'P':
                opts.path = optarg;
                break;
            case 'o':
                opts.outfile = optarg;
                break;
            case 'h':
            case '?':
                fprintf(stderr, HELPSTR);
                break;
            }

        } while (-1 != retval && '?' != retval);

        if ('?' == retval)
        {
            return -1;
        }

        if (0 == opts.port || opts.host.empty() || opts.path.empty() || opts.outfile.empty())
        {
            fprintf(stderr, "missing required arguments\n\n");
            fprintf(stderr, HELPSTR);
            return -1;
        }

        return 0;
    }

    std::string prepare_httpreq()
    {
        std::string getreq = TEMPLATE_GET;

        return std::move(getreq.replace(getreq.find("{host}"), 6, opts.host)
                             .replace(getreq.find("{path}"), 6, opts.path));
    }

    struct composite_parser_t
    {
        llhttp_t parser;
        std::string partial;
        header_t headers;
        header_t::iterator pheader;
        int64_t filewr_offset;
    };

    struct prog_t
    {
        addrinfo *res;
        tls_ctx_t *tls_ctx;
        composite_parser_t *composite;
        uv_file outfile;
        addrinfo hint;
        llhttp_settings_t settings;
    };
};

void on_stream_close(uv_handle_t *handle)
{
    free(handle);
}

bool ishttps()
{
    return dwnlder::SERVICE_HTTPS == dwnlder::opts.port;
}

void destruct_quick_write(uv_write_t *req)
{
    uv_buf_t *uvbuf = (uv_buf_t *)req->data;

    free(uvbuf->base);
    free(uvbuf);
    free(req);
}

void on_quick_write(uv_write_t *req, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "error quick write %p: %s\n", (void *)req->handle, uv_err_name(status));
        uv_close((uv_handle_t *)req->handle, on_stream_close);
    }

    destruct_quick_write(req);
}

int uv_quick_write(uv_stream_t *stream, uv_buf_t *uvbuf)
{
    uv_write_t *wreq = (uv_write_t *)malloc(sizeof(uv_write_t));
    wreq->data = uvbuf;

    int retval = uv_write(wreq, stream, uvbuf, 1, on_quick_write);

    if (0 != retval)
        destruct_quick_write(wreq);

    return retval;
}

int uv_quick_write(uv_stream_t *stream)
{
    std::string httpreq = dwnlder::prepare_httpreq();

    uv_buf_t *uvbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));
    uvbuf->base = (char *)malloc(httpreq.length());
    uvbuf->len = httpreq.length();

    uv_write_t *wreq = (uv_write_t *)malloc(sizeof(uv_write_t));
    wreq->data = uvbuf;

    memcpy(uvbuf->base, httpreq.c_str(), httpreq.length());

    int retval = uv_write(wreq, stream, uvbuf, 1, on_quick_write);

    if (0 != retval)
        destruct_quick_write(wreq);

    return retval;
}

dwnlder::prog_t *get_prog()
{
    return (dwnlder::prog_t *)uv_default_loop()->data;
}

dwnlder::prog_t *get_prog(uv_loop_t *loop)
{
    return (dwnlder::prog_t *)loop->data;
}

dwnlder::composite_parser_t *make_composite(const llhttp_settings_t *settings)
{
    void *composite_raw = malloc(sizeof(dwnlder::composite_parser_t));
    dwnlder::composite_parser_t *composite = new (composite_raw) dwnlder::composite_parser_t;
    composite->pheader = composite->headers.begin();
    llhttp_init(&composite->parser, HTTP_RESPONSE, settings);
    composite->filewr_offset = 0LL;
    return composite;
}

dwnlder::composite_parser_t *get_composite(llhttp_t *parser)
{
    return (dwnlder::composite_parser_t *)parser;
}

dwnlder::composite_parser_t *get_composite(uv_stream_t *stream)
{
    return (dwnlder::composite_parser_t *)stream->data;
}

int on_header_field(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_header_field_complete(llhttp_t *parser)
{
    dwnlder::composite_parser_t *composite = get_composite(parser);
    std::pair<header_t::iterator, bool> retval = composite->headers.emplace(header_t::value_type(std::move(composite->partial), ""));
    composite->pheader = retval.first;
    return 0;
}

int on_header_value(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_header_value_complete(llhttp_t *parser)
{
    dwnlder::composite_parser_t *composite = get_composite(parser);
    composite->pheader->second = std::move(composite->partial);
    fprintf(stderr, "header %s: %s\n", composite->pheader->first.c_str(), composite->pheader->second.c_str());
    return 0;
}

int on_headers_complete(llhttp_t *parser)
{
    if (HTTP_STATUS_OK != llhttp_get_status_code(parser))
    {
        fprintf(stderr, "response is not OK\n");
        return -1;
    }

    return 0;
}

void destruct_fs_wreq(uv_fs_t *req)
{
    uv_buf_t *wbuf = (uv_buf_t *)req->data;

    free(wbuf->base);
    free(wbuf);
    free(req);
}

void on_fs_written(uv_fs_t *req)
{
    if (0 > req->result)
    {
        fprintf(stderr, "error writing into outfile: %s\n", uv_err_name(req->result));
    }

    destruct_fs_wreq(req);
}

int on_body(llhttp_t *parser, const char *at, size_t length)
{
    int retval;

    dwnlder::prog_t *prog = get_prog();

    uv_buf_t *filewbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));
    filewbuf->base = (char *)malloc(length);
    filewbuf->len = length;
    memcpy(filewbuf->base, at, length);

    uv_fs_t *filewreq = (uv_fs_t *)malloc(sizeof(uv_fs_t));
    filewreq->data = filewbuf;

    int64_t &filewr_offset = get_composite(parser)->filewr_offset;
    if (0 != (retval = uv_fs_write(uv_default_loop(), filewreq, prog->outfile, filewbuf, 1, filewr_offset, on_fs_written)))
    {
        fprintf(stderr, "error attempting to write into outfile: %s\n", uv_err_name(retval));

        destruct_fs_wreq(filewreq);
        return -1;
    }

    filewr_offset += length;
    return 0;
}

void common_alloc(uv_handle_t *_, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_shutdown(uv_shutdown_t *req, int status)
{
    if (0 != status && UV_ECANCELED != status)
    {
        fprintf(stderr, "error shutting down for some reason: %s\n", uv_err_name(status));
    }

    free(req->handle);
    free(req);
}

void on_data_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    int retval, _;

    if (0 >= nread)
    {
        switch (nread)
        {
        case 0: // do nothing
            break;
        case UV_EOF:
        {
            uv_shutdown_t *shutreq = (uv_shutdown_t *)malloc(sizeof(uv_shutdown_t));

            if (0 != (retval = uv_shutdown(shutreq, stream, on_shutdown)))
            {
                fprintf(stderr, "error couldn't initiate shutdown %p: %s\n", (void *)stream, uv_err_name(retval));
                free(shutreq);
            }

            break;
        }
        default:
            fprintf(stderr, "error reading stream %p: %s\n", (void *)stream, uv_err_name(nread));

            uv_close((uv_handle_t *)stream, on_stream_close);
            break;
        }

        if (NULL != buf->base)
        {
            free(buf->base);
        }

        return;
    }

    dwnlder::prog_t *prog = get_prog(stream->loop);
    dwnlder::composite_parser_t *composite = get_composite(stream);

    char *raw = buf->base;
    ssize_t rawlen = nread;

    if (ishttps())
    {
        int sslerr;

        _ = BIO_write(prog->tls_ctx->rbio, buf->base, nread);
        if (!SSL_is_init_finished(prog->tls_ctx->tls))
        {
            _ = SSL_do_handshake(prog->tls_ctx->tls);

            _ = uv_quick_write(stream, flush_wbio(prog->tls_ctx->tls));

            if (SSL_is_init_finished(prog->tls_ctx->tls))
            {
                std::string httpreq = dwnlder::prepare_httpreq();

                _ = uv_quick_write(stream, ssl_prepare_write(prog->tls_ctx->tls, httpreq.c_str(), httpreq.length()));
            }

            free(buf->base);
            return;
        }

        raw = (char *)malloc(rawlen = 4096);
        retval = SSL_read(prog->tls_ctx->tls, raw, rawlen);

        if (0 >= retval)
        {
            sslerr = SSL_get_error(prog->tls_ctx->tls, retval);
            fprintf(stderr, "error (possibly) SSL_read: %d\n", sslerr);

            return;
        }
        rawlen = retval;
    }

    if (0 != (retval = llhttp_execute(&composite->parser, raw, rawlen)))
    {
        fprintf(stderr, "error parsing http response: %d\n", retval);
        uv_close((uv_handle_t *)stream, on_stream_close);
    }

    if (ishttps())
        free(raw);

    free(buf->base);
}

void destruct_httpreq_wreq(uv_write_t *req)
{
    uv_buf_t *wbuf = (uv_buf_t *)req->data;

    free(wbuf->base);
    free(wbuf);
    free(req);
}

void on_tcp_connect(uv_connect_t *req, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "couldn't connect: %s\n", uv_err_name(status));

        free(req);
        return;
    }

    int retval, _;

    uv_stream_t *stream = req->handle;
    dwnlder::prog_t *prog = get_prog(stream->loop);

    _ = uv_read_start(req->handle, common_alloc, on_data_read);

    if (ishttps())
    {
        retval = SSL_connect(prog->tls_ctx->tls);

        if (0 != (retval = uv_quick_write(stream, flush_wbio(prog->tls_ctx->tls))))
        {
            fprintf(stderr, "error couldn't initiate write %p: %s\n", (void *)stream, uv_err_name(retval));

            uv_close((uv_handle_t *)stream, on_stream_close);
        }
    }
    else if (0 != (retval = uv_quick_write(stream)))
    {
        fprintf(stderr, "error couldn't initiate write %p: %s\n", (void *)stream, uv_err_name(retval));

        uv_close((uv_handle_t *)stream, on_stream_close);
    }

    free(req);
}

void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    get_prog(req->loop)->res = res;

    int retval;

    uv_connect_t *connreq = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    uv_tcp_t *client = (uv_tcp_t *)req->data;

    if (0 != (retval = uv_tcp_connect(connreq, client, res->ai_addr, on_tcp_connect)))
    {
        fprintf(stderr, "couldn't initiate tcp connection: %s\n", uv_err_name(retval));
    }

    free(req);
}

void on_attempted_fs_open(uv_fs_t *req)
{
    if (0 > req->result)
    {
        fprintf(stderr, "couldn't open the file: %s\n", uv_err_name(req->result));

        free(req);
        return;
    }

    dwnlder::prog_t *prog = get_prog(req->loop);
    prog->outfile = req->result;

    free(req);

    int retval, _;

    std::string destin_port = std::to_string(dwnlder::opts.port);

    uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));

    _ = uv_tcp_init(uv_default_loop(), client);
    client->data = prog->composite;

    uv_getaddrinfo_t *getaddrinfo_req = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));
    getaddrinfo_req->data = client;

    if (0 != (retval = uv_getaddrinfo(uv_default_loop(), getaddrinfo_req, on_resolved, dwnlder::opts.host.c_str(), destin_port.c_str(), &prog->hint)))
    {
        fprintf(stderr, "error invoking uv_getaddrinfo: %s\n", uv_err_name(retval));

        free(getaddrinfo_req);
        free(client);
        return;
    }
}

#endif
