/*
 * socket_ce.c
 *
 * Copyright (C) 2016 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

#define CF_SOCKET_PRIVATE
#include "socket.h"

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "fault.h"

#include "citrusleaf/alloc.h"

bool advertise_ipv6 = false;

static char *
safe_strndup(const char *string, size_t length)
{
	char *res = cf_strndup(string, length);

	if (res == NULL) {
		cf_crash(CF_SOCKET, "Out of memory");
	}

	return res;
}

void
cf_socket_set_advertise_ipv6(bool advertise)
{
	//cf_warning(CF_SOCKET, "'advertise-ipv6' is relevant for enterprise only");
	advertise_ipv6 = true;
}

bool
cf_socket_advertises_ipv6(void)
{
	return advertise_ipv6;
}

// AB fixed for IPv6
int32_t
cf_ip_addr_from_string_multi(const char *string, cf_ip_addr *addrs, uint32_t *n_addrs)
{
	if (strcmp(string, "any") == 0) {
		if (*n_addrs < 1) {
			cf_warning(CF_SOCKET, "Too many IP addresses");
			return -1;
		}

		cf_ip_addr_set_any(&addrs[0]);
		*n_addrs = 1;
		return 0;
	}

	if (strcmp(string, "local") == 0) {
		if (*n_addrs < 1) {
			cf_warning(CF_SOCKET, "Too many IP addresses");
			return -1;
		}

		cf_ip_addr_set_local(&addrs[0]);
		*n_addrs = 1;
		return 0;
	}

	if (cf_inter_is_inter_name(string)) {
		cf_ip_addr if_addrs[CF_SOCK_CFG_MAX];
		uint32_t n_if_addrs = CF_SOCK_CFG_MAX;

		if (cf_inter_get_addr_name(if_addrs, &n_if_addrs, string) < 0) {
			cf_warning(CF_SOCKET, "Error while getting interface addresses for '%s'", string);
			return -1;
		}

		if (n_if_addrs == 0) {
			cf_warning(CF_SOCKET, "Interface %s does not have any IP addresses", string);
			return -1;
		}

		if (n_if_addrs > *n_addrs) {
			cf_warning(CF_SOCKET, "Too many IP addresses");
			return -1;
		}

		for (uint32_t i = 0; i < n_if_addrs; ++i) {
			cf_ip_addr_copy(&if_addrs[i], &addrs[i]);
		}

		*n_addrs = n_if_addrs;
		return 0;
	}

	int32_t res = -1;
	struct addrinfo *info = NULL;
	static struct addrinfo hints = {
		.ai_flags = 0,
		// .ai_family = AF_INET       AB hah.. we don't want this hint
	};

	if (!cf_socket_advertises_ipv6())
		hints.ai_family = AF_INET;

	int32_t x = getaddrinfo(string, NULL, &hints, &info);

	if (x != 0) {
		cf_warning(CF_SOCKET, "Error while converting address '%s': %s", string, gai_strerror(x));
		goto cleanup0;
	}

	uint32_t i = 0;

	for (struct addrinfo *walker = info; walker != NULL; walker = walker->ai_next) {
		if (walker->ai_socktype == SOCK_STREAM) {
			if (i >= *n_addrs) {
				cf_warning(CF_SOCKET, "Too many IP addresses");
				goto cleanup1;
			}

			if (walker->ai_family == AF_INET) {
				struct sockaddr_in *sai = (struct sockaddr_in *)walker->ai_addr;
				addrs[i].family = AF_INET;
				addrs[i].v4 = sai->sin_addr;
			}
			else {
				struct sockaddr_in6 *sai = (struct sockaddr_in6 *)walker->ai_addr;
				addrs[i].family = AF_INET6;
				addrs[i].v6 = sai->sin6_addr;
			}
			++i;
		}
	}

	cf_ip_addr_sort(addrs, i);
	*n_addrs = i;
	res = 0;

cleanup1:
	freeaddrinfo(info);

cleanup0:
	return res;
}

bool
cf_ip_addr_str_is_legacy(const char *string)
{
	(void)string;

	// TODO: determine whether this can be called with a hostname
	
	return strchr(string, ':') == NULL;
}

// AB fixed for IPv6
bool
cf_ip_addr_is_legacy(const cf_ip_addr* addr)
{
	return addr->family == AF_INET;
}

// AB fixed for IPv6
bool
cf_ip_addr_legacy_only(void)
{
	return false; // or should we return advertise_ipv6 value?
}

// AB fixed for IPv6
int32_t
cf_ip_addr_to_string(const cf_ip_addr *addr, char *string, size_t size)
{
	int af = addr->family;

	//cf_warning(CF_SOCKET, "addr_to_string: af: %d, 1: %0x", af, htonl(*(int *)&addr->v4));

	if (af != AF_INET6) af=AF_INET;

	if (inet_ntop(af, &addr->v4, string, size) == NULL) {
		if (errno == ENOSPC)
			cf_warning(CF_SOCKET, "Output buffer overflow");
		else
			cf_warning(CF_SOCKET, "Address family not supported");
		return -1;
	}

	return strlen(string);
}

// AB fixed for IPv6
int32_t
cf_ip_addr_from_binary(const uint8_t *binary, size_t size, cf_ip_addr *addr)
{
	if (size == 4) {
		addr->family = AF_INET;
		memcpy(&addr->v4, binary, 4);
		return 4;
	}
	else if (size == sizeof(struct in6_addr)) {
		addr->family = AF_INET6;
		memcpy(&addr->v6, binary, sizeof(struct in6_addr));
		return sizeof(struct in6_addr);
	}
	else {
		cf_debug(CF_SOCKET, "Input buffer size incorrect.");
		return -1;
	}
}

// AB fixed for IPv6
int32_t
cf_ip_addr_to_binary(const cf_ip_addr *addr, uint8_t *binary, size_t size)
{
	
	if (addr->family != AF_INET6) {
		if (size < 4) {
			cf_warning(CF_SOCKET, "Output buffer overflow");
			return -1;
		}

		memcpy(binary, &addr->v4, 4);
		return 4;
	}
	
	// else: ipv6
	if (size < sizeof(struct in6_addr)) {
		cf_warning(CF_SOCKET, "Output buffer overflow");
		return -1;
	}

	memcpy(binary, &addr->v6, sizeof(struct in6_addr));
	return sizeof(struct in6_addr);
}

void
cf_ip_addr_to_rack_aware_id(const cf_ip_addr *addr, uint32_t *id)
{
	cf_crash(CF_SOCKET, "NON_FIXED FUNCTION: rack_aware_id");
	*id = ntohl(addr->v4.s_addr);
}

// AB fixed for IPv6
int32_t
cf_ip_addr_compare(const cf_ip_addr *lhs, const cf_ip_addr *rhs)
{
	if (lhs->family == AF_INET)
		return memcmp(&lhs->v4, &rhs->v4, 4);
	return memcmp(&lhs->v6, &rhs->v6, sizeof(struct in6_addr));
}

// AB fixed for IPv6
void
cf_ip_addr_copy(const cf_ip_addr *from, cf_ip_addr *to)
{
	to->family = from->family;
	if (to->family == AF_INET)
		to->v4 = from->v4;	
	else
		to->v6 = from->v6;

	// char f[64], t[64];

	// int r = cf_ip_addr_to_string(from, f, 64);
	// r = cf_ip_addr_to_string(to, t, 64);
	

	// cf_warning(CF_SOCKET, "addr_copy: from=%s, to=%s r=%d", f, t, r);

	
}

void
cf_ip_addr_set_local(cf_ip_addr *addr)
{
	addr->v4.s_addr = htonl(0x7f000001);
}

// AB fixed for IPv6
bool
cf_ip_addr_is_local(const cf_ip_addr *addr)
{
	if (addr->family != AF_INET6) 
		return (ntohl(addr->v4.s_addr) & 0xff000000) == 0x7f000000;
	else
		// for now I will only match the true loopback address ::1/128
		return (addr->v6.s6_addr32[0] == 0 && addr->v6.s6_addr32[1] == 0 &&
				addr->v6.s6_addr32[2] == 0 && ntohl(addr->v6.s6_addr32[3]) == 1);
}

void
cf_ip_addr_set_any(cf_ip_addr *addr)
{
	if (addr->family == AF_INET6)
		memset(addr->v6.s6_addr, 0, sizeof(struct in6_addr));
	else
		addr->v4.s_addr = 0;
}

// AB fixed for IPv6
bool
cf_ip_addr_is_any(const cf_ip_addr *addr)
{
	if (addr->family == AF_INET)
		return addr->v4.s_addr == 0;
	else
		return addr->v6.s6_addr == 0;
}

// AB fixed for IPv6
int32_t
cf_sock_addr_to_string(const cf_sock_addr *addr, char *string, size_t size)
{
	int32_t total = 0;
	int32_t count = 0;
	
	if (addr->addr.family == AF_INET6) {
		string[0] = '[';
		total += 1;
	}
	
	count = cf_ip_addr_to_string(&addr->addr, string+total, size-total);

	if (count < 0) {
		return -1;
	}

	total += count;

	if (size - total < 2) {
		cf_warning(CF_SOCKET, "Output buffer overflow");
		return -1;
	}

	if (addr->addr.family == AF_INET6)
		string[total++] = ']';
	string[total++] = ':';
	string[total] = 0;

	count = cf_ip_port_to_string(addr->port, string + total, size - total);

	if (count < 0) {
		return -1;
	}

	total += count;
	return total;
}

int32_t
cf_sock_addr_from_string(const char *string, cf_sock_addr *addr)
{
	int32_t res = -1;
	const char *colon = strchr(string, ':');

	cf_crash(CF_SOCKET, "NON FIXED FUNCTION: sock_addr_from_string");

	if (colon == NULL) {
		cf_warning(CF_SOCKET, "Missing ':' in socket address '%s'", string);
		goto cleanup0;
	}

	const char *host = safe_strndup(string, colon - string);

	if (cf_ip_addr_from_string(host, &addr->addr) < 0) {
		cf_warning(CF_SOCKET, "Invalid host address '%s' in socket address '%s'", host, string);
		goto cleanup1;
	}

	if (cf_ip_port_from_string(colon + 1, &addr->port) < 0) {
		cf_warning(CF_SOCKET, "Invalid port '%s' in socket address '%s'", colon + 1, string);
		goto cleanup1;
	}

	res = 0;

cleanup1:
	cf_free((void *)host);

cleanup0:
	return res;
}

//fixed AB for IPv6
void
cf_sock_addr_from_native(const struct sockaddr *native, cf_sock_addr *addr)
{
	if (native->sa_family != AF_INET && native->sa_family != AF_INET6) {
		cf_crash(CF_SOCKET, "Invalid address family: %d", native->sa_family);
	}

	if (native->sa_family != AF_INET6) {
		struct sockaddr_in *sai = (struct sockaddr_in *)native;
		addr->addr.family = AF_INET;
		addr->addr.v4 = sai->sin_addr;
		addr->port = ntohs(sai->sin_port);
	}
	else {
		struct sockaddr_in6 *sai = (struct sockaddr_in6 *)native;
		addr->addr.family = AF_INET6;
		addr->addr.v6 = sai->sin6_addr;
		addr->port = ntohs(sai->sin6_port);
	}
}


// AB fixed for IPv6
void
cf_sock_addr_to_native(const cf_sock_addr *addr, struct sockaddr *native)
{
	
	if (addr->addr.family != AF_INET6) {
		struct sockaddr_in *sai = (struct sockaddr_in *)native;
		memset(sai, 0, sizeof(struct sockaddr_in));
		sai->sin_family = AF_INET;
		sai->sin_addr = addr->addr.v4;
		sai->sin_port = htons(addr->port);
	}
	else {
		struct sockaddr_in6 *sai = (struct sockaddr_in6 *)native;
		memset(sai, 0, sizeof(struct sockaddr_in6));
		sai->sin6_family = AF_INET6;
		sai->sin6_addr = addr->addr.v6;
		sai->sin6_port = htons(addr->port);
	}
}

int32_t
cf_mserv_cfg_add_combo(cf_mserv_cfg *serv_cfg, cf_sock_owner owner, cf_ip_port port,
		cf_ip_addr *addr, cf_ip_addr *if_addr, uint8_t ttl)
{
	cf_msock_cfg sock_cfg;
	cf_msock_cfg_init(&sock_cfg, owner);
	sock_cfg.port = port;
	cf_ip_addr_copy(addr, &sock_cfg.addr);
	cf_ip_addr_copy(if_addr, &sock_cfg.if_addr);
	sock_cfg.ttl = ttl;

	return cf_mserv_cfg_add_msock_cfg(serv_cfg, &sock_cfg);
}

int32_t
cf_socket_mcast_set_inter(cf_socket *sock, const cf_ip_addr *iaddr)
{
	struct ip_mreqn mr;
	memset(&mr, 0, sizeof(mr));
	mr.imr_address = iaddr->v4;

	if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_IF, &mr, sizeof(mr)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IP_MULTICAST_IF) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}

	return 0;
}

int32_t
cf_socket_mcast_set_ttl(cf_socket *sock, int32_t ttl)
{
	if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IP_MULTICAST_TTL) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}

	return 0;
}

int32_t
cf_socket_mcast_join_group(cf_socket *sock, const cf_ip_addr *iaddr, const cf_ip_addr *gaddr)
{
	struct ip_mreqn mr;
	memset(&mr, 0, sizeof(mr));

	if (!cf_ip_addr_is_any(iaddr)) {
		mr.imr_address = iaddr->v4;
	}

	mr.imr_multiaddr = gaddr->v4;

	if (setsockopt(sock->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IP_ADD_MEMBERSHIP) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}

#ifdef IP_MULTICAST_ALL
	// Only receive traffic from multicast groups this socket actually joins.
	// Note: Bind address filtering takes precedence, so this is simply an extra level of
	// restriction.
	static const int32_t no = 0;

	if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_ALL, &no, sizeof(no)) < 0) {
		cf_warning(CF_SOCKET, "setsockopt(IP_MULTICAST_ALL) failed on FD %d: %d (%s)",
				sock->fd, errno, cf_strerror(errno));
		return -1;
	}
#endif

	return 0;
}

// AB fixed for IPv6
size_t
cf_socket_addr_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		cf_crash(CF_SOCKET, "Invalid address family: %d", sa->sa_family);
		return 0;
	}
}

int32_t
cf_socket_parse_netlink(bool allow_ipv6, uint32_t family, uint32_t flags,
		const void *data, size_t len, cf_ip_addr *addr)
{
	(void)allow_ipv6;
	(void)flags;

	if (!allow_ipv6 && (family != AF_INET || len != 4)) {
		return -1;
	}

	if (family != AF_INET6)
		memcpy(&addr->v4, data, 4);
	else
	    memcpy(&addr->v6, data, sizeof(struct in6_addr));
	return 0;
}

void
cf_socket_fix_client(cf_socket *sock)
{
	(void)sock;
}

void
cf_socket_fix_bind(cf_serv_cfg *serv_cfg)
{
	(void)serv_cfg;
}

void
cf_socket_fix_server(cf_socket *sock)
{
	(void)sock;
}
