## Description

A hands-on attempt to better understand asynchronous I/O with TCP sockets. Attempts to read ([recv](https://man7.org/linux/man-pages/man2/recv.2.html)) from a TCP socket usually block until data is available. Similarly, attempts to write ([send](https://man7.org/linux/man-pages/man2/send.2.html)) into a TCP socket usually block until the remaining message fits in the send buffer. There have been several options (non-exhaustive) to get notified when a TCP socket is ready for I/O:

* [poll](https://man7.org/linux/man-pages/man2/poll.2.html)
* [select](https://man7.org/linux/man-pages/man2/select.2.html)
* [SOCK_NONBLOCK](https://man7.org/linux/man-pages/man2/socket.2.html)

This silly repository explores and utilises [libuv](https://github.com/libuv/libuv) which abstracts away the heavy-lifting work of setting up an asynchronous I/O, which varies greatly from one OS to another. The mini projects found in this repository are:

1. `async-echo` (asynchronous echo server), repeats what was received from the client
2. `async-dwnlder` (asynchronous downloader): it's like `wget` but only HTTP/1.1 without TLS and `Transfer-Encoding` at the moment.
3. `async-relay` (asynchronous relay): it's like `socat` but only TCP

Been coding this entirely on VS Code with the C/C++ extension. The project settings in `./vscode` is not generalised at the moment, so it works only on my Macbook (unless you already have installed `libuv` and `openssl`, and their header files and libraries are available in `/usr/local/include` and `/usr/local/lib`). For `llhttp`, you'll have to build them manually.

Also, coding this in C/C++ because it brings me closer to the machine language.
