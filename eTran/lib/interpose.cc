#include <dlfcn.h>
#include <unistd.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

#include <eTran_posix.h>

static bool initialized = false;

int (*libc_socket)(int, int, int) = nullptr;
int (*libc_close)(int sockfd) = nullptr;
int (*libc_bind)(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen) = nullptr;
int (*libc_connect)(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen) = nullptr;
int (*libc_listen)(int sockfd, int backlog) = nullptr;
int (*libc_accept)(int sockfd, struct sockaddr *addr,
    socklen_t *addrlen) = nullptr;
int (*libc_accept4)(int sockfd, struct sockaddr *addr,
    socklen_t *addrlen, int flags) = nullptr;
int (*libc_getpeername)(int fd, struct sockaddr *addr, socklen_t *addrlen) = nullptr;
int (*libc_getsockname)(int fd, struct sockaddr *addr, socklen_t *addrlen) = nullptr;
ssize_t (*libc_read)(int fd, void *buf, size_t count) = nullptr;
ssize_t (*libc_write)(int fd, const void *buf, size_t count) = nullptr;
ssize_t (*libc_writev)(int fd, const struct iovec *iov, int iovcnt) = nullptr;
int (*libc_setsockopt)(int socket, int level, int option_name,
           const void *option_value, socklen_t option_len);
int (*libc_getsockopt)(int socket, int level, int option_name,
              void *option_value, socklen_t *option_len);
int (*libc_fcntl)(int fd, int cmd, ...);

int (*libc_epoll_create1)(int flags) = nullptr;
int (*libc_epoll_create)(int size) = nullptr;
int (*libc_epoll_ctl)(int epfd, int op, int fd,
    struct epoll_event *event) = nullptr;
int (*libc_epoll_wait)(int epfd, struct epoll_event *events,
    int maxevents, int timeout) = nullptr;
int (*libc_select)(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout) = nullptr;

#define INTERCEPT_FUNCTION(func) \
    libc_##func = (typeof(libc_##func)) dlsym(RTLD_NEXT, #func); \
    if (!libc_##func) \
        fprintf(stderr, "Error in dlsym: %s\n", dlerror()); \

static inline void init_socket() {

    INTERCEPT_FUNCTION(socket);

    INTERCEPT_FUNCTION(connect);

    INTERCEPT_FUNCTION(bind);

    INTERCEPT_FUNCTION(listen);

    INTERCEPT_FUNCTION(accept);

    INTERCEPT_FUNCTION(accept4);

    INTERCEPT_FUNCTION(getpeername);
    INTERCEPT_FUNCTION(getsockname);
    
    INTERCEPT_FUNCTION(close);

    INTERCEPT_FUNCTION(read);
    
    INTERCEPT_FUNCTION(write);
    INTERCEPT_FUNCTION(writev);

    INTERCEPT_FUNCTION(setsockopt);

    INTERCEPT_FUNCTION(getsockopt);

    INTERCEPT_FUNCTION(fcntl);

    INTERCEPT_FUNCTION(epoll_create1);

    INTERCEPT_FUNCTION(epoll_create);

    INTERCEPT_FUNCTION(epoll_ctl);

    INTERCEPT_FUNCTION(epoll_wait);
}

static inline void ensure_init(void) 
{
    if (unlikely(!initialized)) {
        init_socket();
        initialized = true;
    }
}


int socket(int domain, int type, int protocol) {
    
    int cond1, cond2;
    ensure_init();

    if (domain != AF_INET)
        return libc_socket(domain, type, protocol);
    
    cond1 = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM && protocol != IPPROTO_HOMA;
    cond2 = (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_DGRAM && protocol == IPPROTO_HOMA;

    if (cond1 || cond2) {
        if (cond1) protocol = IPPROTO_TCP;
        return eTran_socket(domain, type, protocol);
    }
    
    return libc_socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    ensure_init();
    if (unlikely(sockfd < 0))
        return -EINVAL;
    if (eTran_connect(sockfd, addr, addrlen))
        return libc_connect(sockfd, addr, addrlen);
    return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    ensure_init();
    if (unlikely(sockfd < 0))
        return -EINVAL;
    if (eTran_bind(sockfd, addr, addrlen))
        return libc_bind(sockfd, addr, addrlen);
    return 0;
}

int listen(int sockfd, int backlog) {
    ensure_init();
    if (unlikely(sockfd < 0))
        return -EINVAL;
    if (eTran_listen(sockfd, backlog))
        return libc_listen(sockfd, backlog);
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    ensure_init();
    int newfd;
    if (unlikely(sockfd < 0))
        return -EINVAL;
    newfd = eTran_accept(sockfd, addr, addrlen);
    if (newfd < 0)
        return libc_accept(sockfd, addr, addrlen);
    return newfd;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    ensure_init();
    int newfd;
    if (unlikely(sockfd < 0))
        return -EINVAL;
    /* HookShift: Redis (and any epoll-driven server) calls accept4 with
     * SOCK_NONBLOCK in a loop until EWOULDBLOCK. eTran_accept blocks (poll
     * timeout -1) unless the LISTENER carries SOF_NONBLOCK, which hangs the
     * whole event loop. Honor the accept4 flag by marking the listener
     * non-blocking so eTran_accept polls non-blocking and returns EAGAIN. */
    if (flags & SOCK_NONBLOCK)
        eTran_fcntl(sockfd, F_SETFL, O_NONBLOCK);
    newfd = eTran_accept(sockfd, addr, addrlen);
    if (newfd == -EAGAIN) { errno = EAGAIN; return -1; }
    if (newfd < 0)
        return libc_accept4(sockfd, addr, addrlen, flags);
    if (flags & SOCK_NONBLOCK)
        eTran_fcntl(newfd, F_SETFL, O_NONBLOCK);
    return newfd;
}

/* HookShift: eTran socket fds are eventfd-backed, so libc getpeername/getsockname
 * return ENOTSOCK. Apps (Redis createClient) call these on accepted conns; fake a
 * sockaddr_in success so they proceed. Real kernel fds fall through to libc. */
static int fake_sockname(struct sockaddr *addr, socklen_t *addrlen)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    if (addr && addrlen) {
        socklen_t n = *addrlen < (socklen_t)sizeof(sin) ? *addrlen : (socklen_t)sizeof(sin);
        memcpy(addr, &sin, n);
        *addrlen = sizeof(sin);
    }
    return 0;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    ensure_init();
    int r = libc_getpeername(fd, addr, addrlen);
    if (r < 0 && errno == ENOTSOCK)
        return fake_sockname(addr, addrlen);
    return r;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    ensure_init();
    int r = libc_getsockname(fd, addr, addrlen);
    if (r < 0 && errno == ENOTSOCK)
        return fake_sockname(addr, addrlen);
    return r;
}

int close(int sockfd) {
    ensure_init();
    if (unlikely(sockfd < 0))
        return -EINVAL;
    if (eTran_close(sockfd)) {
        return libc_close(sockfd);
    }
    return 0;
}

ssize_t read(int fd, void *buf, size_t count)
{
    ensure_init();
    ssize_t ret;
    if (unlikely(fd < 0))
        return -EINVAL;
    ret = eTran_read(fd, buf, count);
    if (ret < 0) {
        return libc_read(fd, buf, count);
    }
    return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    ensure_init();
    ssize_t ret;
    if (unlikely(fd < 0))
        return -EINVAL;
    ret = eTran_writev(fd, iov, iovcnt);
    if (ret == -EBADF)
        return libc_writev(fd, iov, iovcnt);
    if (ret < 0) { errno = -ret; return -1; }
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    ensure_init();
    ssize_t ret;
    if (unlikely(fd < 0))
        return -EINVAL;
    ret = eTran_write(fd, buf, count);
    if (ret < 0) {
        return libc_write(fd, buf, count);
    }
    return ret;
}

int setsockopt(int socket, int level, int option_name,
           const void *option_value, socklen_t option_len)
{
    ensure_init();
    if (unlikely(socket < 0))
        return -EINVAL;
    if (eTran_setsockopt(socket, level, option_name, option_value, option_len))
        return libc_setsockopt(socket, level, option_name, option_value, option_len);
    return 0;
}

int getsockopt(int socket, int level, int option_name,
           void *option_value, socklen_t *option_len)
{
    ensure_init();
    if (unlikely(socket < 0))
        return -EINVAL;
    if (eTran_getsockopt(socket, level, option_name, option_value, option_len))
        return libc_getsockopt(socket, level, option_name, option_value, option_len);
    return 0;
}

// FIXME: fcntl is not fully implemented
int fcntl(int fd, int cmd, ...)
{
    ensure_init();
    if (cmd != F_SETFL && cmd != F_GETFL)
        return libc_fcntl(fd, cmd);
    va_list args;
    va_start(args, cmd);
    int flags = va_arg(args, int);
    va_end(args);
    if (unlikely(fd < 0))
        return -EINVAL;
    if (eTran_fcntl(fd, cmd, flags) < 0) {
        return libc_fcntl(fd, cmd, flags);
    }
    return 0;
}

int epoll_create1(int flags)
{
    int epfd;
    ensure_init();

    epfd = eTran_epoll_create1(flags);
    if (epfd <= 0)
        return libc_epoll_create1(flags);
    return epfd;
}

int epoll_create(int size)
{
    int epfd;
    ensure_init();

    epfd = eTran_epoll_create1(0);
    if (epfd <= 0)
        return libc_epoll_create(size);
    return epfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    ensure_init();
    if (unlikely(epfd < 0))
        return -EINVAL;
    int r = eTran_epoll_ctl(epfd, op, fd, event);
    if (r)
        return libc_epoll_ctl(epfd, op, fd, event);
    return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    int nfds;
    ensure_init();
    if (unlikely(epfd < 0))
        return -EINVAL;
    nfds = eTran_epoll_wait(epfd, events, maxevents, timeout);
    if (nfds < 0)
        return libc_epoll_wait(epfd, events, maxevents, timeout);
    return nfds;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout)
{
    int ret_nfds;
    ensure_init();
    ret_nfds = eTran_select(nfds, readfds, writefds, exceptfds, timeout);
    if (ret_nfds < 0)
        return libc_select(nfds, readfds, writefds, exceptfds, timeout);
    return ret_nfds;
}