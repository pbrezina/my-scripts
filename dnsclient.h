 /*
  * Copyright 2001 Red Hat, Inc.
  *
  * This is free software; you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published by
  * the Free Software Foundation; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  *
  */

#ifndef dnsclient_h
#define dnsclient_h

#include <sys/types.h>

typedef enum dns_class {
	DNS_C_IN = 1,
	DNS_C_CS = 2,
	DNS_C_CHAOS = 3,
	DNS_C_HS = 4,
	DNS_C_ANY = 255,
} dns_class_t;

typedef enum dns_type {
	DNS_T_A = 1,
	DNS_T_NS = 2,
	DNS_T_CNAME = 5,
	DNS_T_SOA = 6,
	DNS_T_NULL = 10,
	DNS_T_WKS = 11,
	DNS_T_PTR = 12,
	DNS_T_HINFO = 13,
	DNS_T_MX = 15,
	DNS_T_TXT = 16,
	DNS_T_SRV = 33,
	DNS_T_ANY = 255,
} dns_type_t;

typedef struct dns_rr_a {
	u_int32_t address;
} dns_rr_a_t;

typedef struct dns_rr_cname {
	const char *cname;
} dns_rr_cname_t;

typedef struct dns_rr_hinfo {
	const char *cpu, *os;
} dns_rr_hinfo_t;

typedef struct dns_rr_mx {
	u_int16_t preference;
	const char *exchange;
} dns_rr_mx_t;

typedef struct dns_rr_null {
	unsigned const char *data;
} dns_rr_null_t;

typedef struct dns_rr_ns {
	const char *nsdname;
} dns_rr_ns_t;

typedef struct dns_rr_ptr {
	const char *ptrdname;
} dns_rr_ptr_t;

typedef struct dns_rr_soa {
	const char *mname;
	const char *rname;
	u_int32_t serial;
	int32_t refresh;
	int32_t retry;
	int32_t expire;
	int32_t minimum;
} dns_rr_soa_t;

typedef struct dns_rr_txt {
	const char *data;
} dns_rr_txt_t;

typedef struct dns_rr_srv {
	const char *server;
	u_int16_t priority;
	u_int16_t weight;
	u_int16_t port;
} dns_rr_srv_t;

typedef struct dns_rr {
	const char *dns_name;
	u_int16_t dns_type;
	u_int16_t dns_class;
	int32_t dns_ttl;
	u_int16_t dns_rlength;
	union {
		struct dns_rr_a a;
		struct dns_rr_cname cname;
		struct dns_rr_hinfo hinfo;
		struct dns_rr_mx mx;
		struct dns_rr_null null;
		struct dns_rr_ns ns;
		struct dns_rr_ptr ptr;
		struct dns_rr_soa soa;
		struct dns_rr_txt txt;
		struct dns_rr_srv srv;
	} dns_rdata;
} dns_rr_t;

typedef struct dns_client_context {
	const char *domain;
	const char **search;
	struct sockaddr_in **nameservers;
} dns_client_context_t;

size_t dns_format_query(const char *query, u_int16_t qclass, u_int16_t qtype,
			unsigned char *qbuf, size_t qbuf_len);
struct dns_rr *dns_parse_results(const unsigned char *results, size_t length);
struct dns_client_context *dns_client_init(void);

#endif
