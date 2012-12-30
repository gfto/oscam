#include "globals.h"
#include "oscam-lock.h"
#include "oscam-net.h"

extern CS_MUTEX_LOCK gethostbyname_lock;

#ifndef IPV6SUPPORT
static int32_t inet_byteorder = 0;

static in_addr_t cs_inet_order(in_addr_t n)
{
	if (!inet_byteorder)
		inet_byteorder= (inet_addr("1.2.3.4") + 1 == inet_addr("1.2.3.5")) ? 1 : 2;
	switch (inet_byteorder) {
	case 1: break;
	case 2:
		n = ((n & 0xff000000) >> 24 ) |
		    ((n & 0x00ff0000) >>  8 ) |
		    ((n & 0x0000ff00) <<  8 ) |
		    ((n & 0x000000ff) << 24 );
		break;
	}
	return n;
}
#endif

char *cs_inet_ntoa(IN_ADDR_T addr)
{
#ifdef IPV6SUPPORT
	static char buff[INET6_ADDRSTRLEN];
	if (IN6_IS_ADDR_V4MAPPED(&addr) || IN6_IS_ADDR_V4COMPAT(&addr)) {
		snprintf(buff, sizeof(buff), "%d.%d.%d.%d",
			addr.s6_addr[12], addr.s6_addr[13], addr.s6_addr[14], addr.s6_addr[15]);
	} else {
		inet_ntop(AF_INET6, &(addr.s6_addr), buff, INET6_ADDRSTRLEN);
	}
	return buff;
#else
	struct in_addr in;
	in.s_addr = addr;
	return (char *)inet_ntoa(in);
#endif
}

void cs_inet_addr(char *txt, IN_ADDR_T *out)
{
#ifdef IPV6SUPPORT
	static char buff[INET6_ADDRSTRLEN];
	//trying as IPv6 address
	if (inet_pton(AF_INET6, txt, out->s6_addr) == 0) {
		//now trying as mapped IPv4
		snprintf(buff, sizeof(buff), "::ffff:%s", txt);
		inet_pton(AF_INET6, buff, out->s6_addr);
	}
#else
	*out = inet_addr(txt);
#endif
}

void cs_resolve(const char *hostname, IN_ADDR_T *ip, struct SOCKADDR *sock, socklen_t *sa_len)
{
#ifdef IPV6SUPPORT
	cs_getIPv6fromHost(hostname, ip, sock, sa_len);
#else
	*ip = cs_getIPfromHost(hostname);
	if (sa_len)
		*sa_len = sizeof(*sock);
#endif
}

#ifdef IPV6SUPPORT
int32_t cs_in6addr_equal(struct in6_addr *a1, struct in6_addr *a2)
{
	return memcmp(a1, a2, 16) == 0;
}

int32_t cs_in6addr_lt(struct in6_addr *a, struct in6_addr *b)
{
	int i;
	for (i=0; i<4; i++) {
		if ((i == 2) && ((IN6_IS_ADDR_V4COMPAT(a) && IN6_IS_ADDR_V4MAPPED(b)) ||
				 (IN6_IS_ADDR_V4COMPAT(b) && IN6_IS_ADDR_V4MAPPED(a))))
			continue;	//skip comparing this part

		if (a->s6_addr32[i] != b->s6_addr32[i])
			return ntohl(a->s6_addr32[i]) < ntohl(b->s6_addr32[i]);
	}

	return 0;
}

int32_t cs_in6addr_isnull(struct in6_addr *addr)
{
	int i;
	for (i=0; i<16; i++)
		if (addr->s6_addr[i])
			return 0;
	return 1;
}

void cs_in6addr_copy(struct in6_addr *dst, struct in6_addr *src)
{
	memcpy(dst, src, 16);
}

void cs_in6addr_ipv4map(struct in6_addr *dst, in_addr_t src)
{
	memset(dst->s6_addr, 0, 16);
	dst->s6_addr[10] = 0xff;
	dst->s6_addr[11] = 0xff;
	memcpy(dst->s6_addr + 12, &src, 4);
}
#endif

IN_ADDR_T get_null_ip(void)
{
	IN_ADDR_T ip;
#ifdef IPV6SUPPORT
	cs_inet_addr("::", &ip);
#else
	ip = 0;
#endif
	return ip;
}

void set_null_ip(IN_ADDR_T *ip)
{
#ifdef IPV6SUPPORT
	cs_inet_addr("::", ip);
#else
	*ip = 0;
#endif
}

void set_localhost_ip(IN_ADDR_T *ip)
{
#ifdef IPV6SUPPORT
	cs_inet_addr("::1", ip);
#else
	cs_inet_addr("127.0.0.1", ip);
#endif
}

int32_t check_ip(struct s_ip *ip, IN_ADDR_T n)
{
	struct s_ip *p_ip;
	int32_t ok = 0;
#ifdef IPV6SUPPORT
	for (p_ip=ip; (p_ip) && (!ok); p_ip=p_ip->next) {
		ok  = cs_in6addr_lt(&n, &p_ip->ip[0]);
		ok |= cs_in6addr_lt(&p_ip->ip[1], &n);
		ok = !ok;
	}
#else
	for (p_ip=ip; (p_ip) && (!ok); p_ip=p_ip->next)
		ok=((cs_inet_order(n)>=cs_inet_order(p_ip->ip[0])) && (cs_inet_order(n)<=cs_inet_order(p_ip->ip[1])));
#endif
	return ok;
}

/* Returns the ip from the given hostname. If gethostbyname is configured in the config file, a lock
   will be held until the ip has been resolved. */
uint32_t cs_getIPfromHost(const char *hostname)
{
	uint32_t result = 0;
	//Resolve with gethostbyname:
	if (cfg.resolve_gethostbyname) {
		cs_writelock(&gethostbyname_lock);
		struct hostent *rht = gethostbyname(hostname);
		if (!rht)
			cs_log("can't resolve %s", hostname);
		else
			result=((struct in_addr*)rht->h_addr)->s_addr;
		cs_writeunlock(&gethostbyname_lock);
	} else { //Resolve with getaddrinfo:
		struct addrinfo hints, *res = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;
		hints.ai_protocol = IPPROTO_TCP;

		int32_t err = getaddrinfo(hostname, NULL, &hints, &res);
		if (err != 0 || !res || !res->ai_addr) {
			cs_log("can't resolve %s, error: %s", hostname, err ? gai_strerror(err) : "unknown");
		} else {
			result=((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		}
		if (res) freeaddrinfo(res);
	}
	return result;
}

#ifdef IPV6SUPPORT
void cs_getIPv6fromHost(const char *hostname, struct in6_addr *addr, struct sockaddr_storage *sa, socklen_t *sa_len)
{
	uint32_t ipv4addr = 0;
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	int32_t err = getaddrinfo(hostname, NULL, &hints, &res);
	if (err != 0 || !res || !res->ai_addr) {
		cs_log("can't resolve %s, error: %s", hostname, err ? gai_strerror(err) : "unknown");
	} else {
		ipv4addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		if (res->ai_family == AF_INET)
			cs_in6addr_ipv4map(addr, ipv4addr);
		else
			IP_ASSIGN(*addr, SIN_GET_ADDR(*res->ai_addr));
		if (sa)
			memcpy(sa, res->ai_addr, res->ai_addrlen);
		if (sa_len)
			*sa_len = res->ai_addrlen;
	}
	if (res)
		freeaddrinfo(res);
}
#endif

int set_socket_priority(int fd, int priority)
{
#ifdef SO_PRIORITY
	return priority ? setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (void *)&priority, sizeof(int *)) : -1;
#else
	(void)fd; (void)priority;
	return -1;
#endif
}

void setTCPTimeouts(int32_t sock)
{
	int32_t flag = 1;
	// this is not only for a real keepalive but also to detect closed connections so it should not be configurable
	if(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) && errno != EBADF){
		cs_log("Setting SO_KEEPALIVE failed, errno=%d, %s", errno, strerror(errno));
	}
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	flag = 10;
	if(setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, &flag, sizeof(flag)) && errno != EBADF){	//send first keepalive packet after 10 seconds of last package received (keepalive packets included)
		cs_log("Setting TCP_KEEPIDLE failed, errno=%d, %s", errno, strerror(errno));
	}
	flag = 3;
	if(setsockopt(sock, SOL_TCP, TCP_KEEPCNT, &flag, sizeof(flag)) && errno != EBADF){		//send up to 3 keepalive packets out (in interval TCP_KEEPINTVL), then disconnect if no response
		cs_log("Setting TCP_KEEPCNT failed, errno=%d, %s", errno, strerror(errno));
	}
	flag = 1;
	if(setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, &flag, sizeof(flag)) && errno != EBADF){;		//send a keepalive packet out every second (until answer has been received or TCP_KEEPCNT has been reached)
		cs_log("Setting TCP_KEEPINTVL failed, errno=%d, %s", errno, strerror(errno));
	}
#endif
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) && errno != EBADF){;
		cs_log("Setting SO_SNDTIMEO failed, errno=%d, %s", errno, strerror(errno));
	}
	tv.tv_sec = 600;
	tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) && errno != EBADF){;
		cs_log("Setting SO_RCVTIMEO failed, errno=%d, %s", errno, strerror(errno));
	}
}

int8_t check_fd_for_data(int32_t fd)
{
	int32_t rc;
	struct pollfd pfd[1];

	pfd[0].fd = fd;
	pfd[0].events = POLLIN | POLLPRI | POLLHUP;
	rc = poll(pfd, 1, 0);

	if (rc == -1)
		cs_log("check_fd_for_data(fd=%d) failed: (errno=%d %s)", fd, errno, strerror(errno));

	if (rc == -1 || rc == 0)
		return rc;

	if (pfd[0].revents & POLLHUP)
		return -2;

	return 1;
}
