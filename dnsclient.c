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

#include "config.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dnsclient.h"

#define DOMAIN_MAX	256
#define SEARCH_MAX	6
#define SERVER_MAX	3
#define RESOLV_CONF	"/etc/resolv.conf"
#define WHITESPACE	" \t\r\n"
#define PORT		53
#define TIMEOUT		5

typedef struct dns_query_header {
	u_int16_t dns_id;
	struct {
		unsigned char dns_bits_rd: 1;
		unsigned char dns_bits_tc: 1;
		unsigned char dns_bits_aa: 1;
		unsigned char dns_bits_opcode: 4;
		unsigned char dns_bits_qr: 1;
	} dns_bits1;
	struct {
		unsigned char dns_bits_rcode: 4;
		unsigned char dns_bits_z: 3;
		unsigned char dns_bits_ra: 1;
	} dns_bits2;
	u_int16_t dns_qdcount;
	u_int16_t dns_ancount;
	u_int16_t dns_nscount;
	u_int16_t dns_arcount;
} dns_query_header_t;

#define dns_qr dns_bits1.dns_bits_qr
#define dns_opcode dns_bits1.dns_bits_opcode
#define dns_aa dns_bits1.dns_bits_aa
#define dns_tc dns_bits1.dns_bits_tc
#define dns_rd dns_bits1.dns_bits_rd
#define dns_ra dns_bits2.dns_bits_ra
#define dns_z dns_bits2.dns_bits_z
#define dns_rcode dns_bits2.dns_bits_rcode

static size_t
dns_name_to_label(const char *name, unsigned char *label, size_t size)
{
	const char *p, *q;
	unsigned char length, *out;

	if(strlen(name) + 1 >= size - 1) {
		return 0;
	}

	p = name;
	out = label;
	while(p && (*p != '\0')) {
		int more;
		q = strchr(p, '.');

		if(q == NULL) {
			more = 0;
			length = strlen(p);
		} else {
			more = 1;
			length = q - p;
		}

		*out++ = length;
		memmove(out, p, length);
		out += length;

		p = q + more;
	}
	*out++ = 0;

	return (out - label);
}

size_t
dns_format_query(const char *query, u_int16_t qclass, u_int16_t qtype,
		 unsigned char *qbuf, size_t qbuf_len)
{
	size_t length = 0;
	struct dns_query_header header;
	unsigned char qlabel[qbuf_len];

	memset(&header, 0, sizeof(header));
	header.dns_id = 0; /* FIXME: id = 0 */
	header.dns_qr = 0; /* query */
	header.dns_opcode = 0; /* standard query */
	header.dns_qdcount = 1; /* single query */

	memset(&qlabel, 0, sizeof(qlabel));
	length = dns_name_to_label(query, qlabel, sizeof(qlabel));
	if(length == 0) {
		return 0;
	}

	if(length + sizeof(header) > qbuf_len) {
		return 0;
	}

	header.dns_id = htons(header.dns_id);
	header.dns_qdcount = htons(header.dns_qdcount);
	header.dns_ancount = htons(header.dns_ancount);
	header.dns_nscount = htons(header.dns_nscount);
	header.dns_arcount = htons(header.dns_arcount);

	memcpy(qbuf, &header, sizeof(header));
	memcpy(qbuf + sizeof(header), qlabel, length);
	qbuf[sizeof(header) + length] = qtype >> 8;
	qbuf[sizeof(header) + length + 1] = qtype & 0xff;
	qbuf[sizeof(header) + length + 2] = qclass >> 8;
	qbuf[sizeof(header) + length + 3] = qclass & 0xff;

	return sizeof(header) + length + 4;
}

static size_t
dns_parse_label(const unsigned char *label, size_t length,
		const unsigned char *base,
		unsigned char *output, size_t output_length,
		const unsigned char **next)
{
	size_t ret = 0;
	int update = 0;
	const unsigned char *p;

	if(label == NULL) {
		if(next) {
			*next = NULL;
		}
		return 0;
	}

	p = label;
	update = 1;
	while(p && *p) {
		if(*p & 0xc0) {
			p = base + ((p[0] & 0x3f) << 8) + p[1];
			continue;
		}
		ret += (*p + 1);
		p += (*p + 1);
	}

	if((p == NULL) || (ret >= output_length)) {
		*next = NULL;
		return 0;
	}

	ret = 0;
	update = 1;
	p = label;
	memset(output, '\0', output_length);
	while(p && *p) {
		if(*p & 0xc0) {
			p = base + ((p[0] & 0x3f) << 8) + p[1];
			ret += 2;
			if(update) {
				update = 0;
			}
			continue;
		}
		if(update) {
			ret += (*p + 1);
		}
		strncat(output, p + 1, *p);
		strcat(output, ".");
		p += (*p + 1);
	}

	if(next) {
		*next = label + (update ? ret + 1 : ret);
	}

	return update ? ret + 1 : ret;
}

static void
dns_parse_a(const unsigned char *rr, const unsigned char *base,
	    struct dns_rr *res)
{
	res->dns_rdata.a.address = (rr[0] << 24) |
				   (rr[1] << 16) |
				   (rr[2] <<  8) |
				   (rr[3] <<  0);
#ifdef DEBUG_DNSCLIENT
	printf("A = %d.%d.%d.%d.\n", rr[0], rr[1], rr[2], rr[3]);
#endif
}

static void
dns_parse_domain(const unsigned char *rr, const unsigned char *base,
		 struct dns_rr *res, const char **ret)
{
	unsigned char buf[DOMAIN_MAX];
	if(dns_parse_label(rr, res->dns_rlength, base,
			   buf, sizeof(buf), NULL)) {
		*ret = strdup(buf);
	}
}

static const unsigned char *
dns_parse_text(const unsigned char *rr, const unsigned char *base,
	       struct dns_rr *res, const char **ret)
{
	unsigned char buf[DOMAIN_MAX];
	if(*rr) {
		if(*rr < res->dns_rlength) {
			memset(buf, '\0', sizeof(buf));
			strncpy(buf, rr + 1, *rr);
			*ret = strdup(buf);
			return rr + 1 + (*rr);
		}
	}
	return NULL;
}

static void
dns_parse_ns(const unsigned char *rr, const unsigned char *base,
	     struct dns_rr *res)
{
	dns_parse_domain(rr, base, res, &res->dns_rdata.ns.nsdname);
#ifdef DEBUG_DNSCLIENT
	printf("NS DNAME = \"%s\".\n", res->dns_rdata.ns.nsdname);
#endif
}

static void
dns_parse_cname(const unsigned char *rr, const unsigned char *base,
		struct dns_rr *res)
{
	dns_parse_domain(rr, base, res, &res->dns_rdata.cname.cname);
#ifdef DEBUG_DNSCLIENT
	printf("CNAME = \"%s\".\n", res->dns_rdata.cname.cname);
#endif
}

static void
dns_parse_soa(const unsigned char *rr, const unsigned char *base,
	      struct dns_rr *res)
{
	char buf[2048];

	if(dns_parse_label(rr, 20, base, buf, sizeof(buf), &rr)) {
		res->dns_rdata.soa.mname = strdup(buf);
	}
	if(dns_parse_label(rr, 20, base, buf, sizeof(buf), &rr)) {
		res->dns_rdata.soa.rname = strdup(buf);
	}
	if(rr) {
		res->dns_rdata.soa.serial = (rr[0] << 24) + (rr[1] << 16) + (rr[2] << 8) + rr[3];
		res->dns_rdata.soa.refresh = (rr[4] << 24) + (rr[5] << 16) + (rr[6] << 8) + rr[7];
		res->dns_rdata.soa.retry = (rr[8] << 24) + (rr[9] << 16) + (rr[10] << 8) + rr[11];
		res->dns_rdata.soa.expire = (rr[12] << 24) + (rr[13] << 16) + (rr[14] << 8) + rr[15];
		res->dns_rdata.soa.minimum = (rr[16] << 24) + (rr[17] << 16) + (rr[18] << 8) + rr[19];
	}
#ifdef DEBUG_DNSCLIENT
	printf("SOA(mname) = \"%s\".\n", res->dns_rdata.soa.mname);
	printf("SOA(rname) = \"%s\".\n", res->dns_rdata.soa.rname);
	printf("SOA(serial) = %d.\n", res->dns_rdata.soa.serial);
	printf("SOA(refresh) = %d.\n", res->dns_rdata.soa.refresh);
	printf("SOA(retry) = %d.\n", res->dns_rdata.soa.retry);
	printf("SOA(expire) = %d.\n", res->dns_rdata.soa.expire);
	printf("SOA(minimum) = %d.\n", res->dns_rdata.soa.minimum);
#endif
}

static void
dns_parse_null(const unsigned char *rr, const unsigned char *base,
	       struct dns_rr *res)
{
	/* um, yeah */
}

static void
dns_parse_wks(const unsigned char *rr, const unsigned char *base,
	      struct dns_rr *res)
{
}

static void
dns_parse_hinfo(const unsigned char *rr, const unsigned char *base,
		struct dns_rr *res)
{
	rr = dns_parse_text(rr, base, res, &res->dns_rdata.hinfo.cpu);
	if(rr) {
		dns_parse_text(rr, base, res, &res->dns_rdata.hinfo.os);
	}
#ifdef DEBUG_DNSCLIENT
	printf("HINFO(cpu) = \"%s\".\n", res->dns_rdata.hinfo.cpu);
	printf("HINFO(os) = \"%s\".\n", res->dns_rdata.hinfo.os);
#endif
}

static void
dns_parse_mx(const unsigned char *rr, const unsigned char *base,
	     struct dns_rr *res)
{
	res->dns_rdata.mx.preference = (rr[0] << 8) | rr[1];
	dns_parse_domain(rr + 2, base, res, &res->dns_rdata.mx.exchange);
#ifdef DEBUG_DNSCLIENT
	printf("MX(exchanger) = \"%s\".\n", res->dns_rdata.mx.exchange);
	printf("MX(preference) = %d.\n", res->dns_rdata.mx.preference);
#endif
}

static void
dns_parse_txt(const unsigned char *rr, const unsigned char *base,
	      struct dns_rr *res)
{
	dns_parse_text(rr, base, res, &res->dns_rdata.txt.data);
#ifdef DEBUG_DNSCLIENT
	printf("TXT = \"%s\".\n", res->dns_rdata.txt.data);
#endif
}

static void
dns_parse_ptr(const unsigned char *rr, const unsigned char *base,
	      struct dns_rr *res)
{
	dns_parse_domain(rr, base, res, &res->dns_rdata.ptr.ptrdname);
#ifdef DEBUG_DNSCLIENT
	printf("PTR = \"%s\".\n", res->dns_rdata.ptr.ptrdname);
#endif
}

static void
dns_parse_srv(const unsigned char *rr, const unsigned char *base,
	      struct dns_rr *res)
{
	res->dns_rdata.srv.priority = (rr[0] << 8) + rr[1];
	res->dns_rdata.srv.weight = (rr[2] << 8) + rr[3];
	res->dns_rdata.srv.port = (rr[4] << 8) + rr[5];
	dns_parse_domain(rr + 6, base, res, &res->dns_rdata.srv.server);
#ifdef DEBUG_DNSCLIENT
	printf("SRV(server) = \"%s\".\n", res->dns_rdata.srv.server);
	printf("SRV(weight) = %d.\n", res->dns_rdata.srv.weight);
	printf("SRV(priority) = %d.\n", res->dns_rdata.srv.priority);
	printf("SRV(port) = %d.\n", res->dns_rdata.srv.port);
#endif
}

struct dns_rr *
dns_parse_results(const unsigned char *results, size_t length)
{
	struct dns_rr *res = NULL;
	struct dns_query_header header;
	unsigned char buf[length];
	const unsigned char *p, *rr;
	size_t skip;
	int i;

	if(length < sizeof(header)) {
		return NULL;
	}

	memcpy(&header, results, sizeof(header));
	header.dns_id = ntohs(header.dns_id);
	header.dns_qdcount = ntohs(header.dns_qdcount);
	header.dns_ancount = ntohs(header.dns_ancount);
	header.dns_nscount = ntohs(header.dns_nscount);
	header.dns_arcount = ntohs(header.dns_arcount);

	if(header.dns_qr != 1) { /* should be a response */
		return NULL;
	}
	if(header.dns_rcode != 0) { /* should be no error */
		return NULL;
	}

	res = malloc(sizeof(struct dns_rr) * (header.dns_ancount + 1));
	if(res == NULL) {
		return NULL;
	}
	memset(res, 0, sizeof(struct dns_rr) * (header.dns_ancount + 1));

	p = results + sizeof(header);

	for(i = 0; i < header.dns_qdcount; i++) {
		char *tmp;

		skip = dns_parse_label(p, results + length - p, results,
				       buf, sizeof(buf), NULL);
		if(skip == 0) {
			free(res);
			return NULL;
		}

		tmp = strdup(buf);
		p += skip;
		res[0].dns_type = (*p << 8) + *(p + 1);
		p += 2;
		res[0].dns_class = (*p << 8) + *(p + 1);
		p += 2;

#ifdef DEBUG_DNSCLIENT
		fprintf(stderr, "Queried for '%s', class = %d, type = %d.\n",
			tmp, res[0].dns_class, res[0].dns_type);
#endif

		memset(&res[0], 0, sizeof(res[0]));
		free(tmp);
	}

	for(i = 0; i < header.dns_ancount; i++) {
		skip = dns_parse_label(p, results + length - p, results,
				       buf, sizeof(buf), NULL);
		if(skip == 0) {
			free(res);
			return NULL;
		}

		res[i].dns_name = strdup(buf);
		p += skip;
		res[i].dns_type = (p[0] << 8) + p[1];
		p += 2;
		res[i].dns_class = (p[0] << 8) + p[1];
		p += 2;
		res[i].dns_ttl = (p[0] << 24) + (p[1] << 16) +
				 (p[2] <<  8) +  p[3];
		p += 4;
		res[i].dns_rlength = (p[0] << 8) + p[1];
		p += 2;

#ifdef DEBUG_DNSCLIENT
		fprintf(stderr, "Answer for '%s', class = %d, type = %d, "
			"ttl = %d.\n",
			res[i].dns_name, res[i].dns_class, res[i].dns_type,
			res[i].dns_ttl);
#endif

		rr = p;
		switch(res[i].dns_type) {
			case DNS_T_A:
				dns_parse_a(rr, results, &res[i]);
				break;
			case DNS_T_NS:
				dns_parse_ns(rr, results, &res[i]);
				break;
			case DNS_T_CNAME:
				dns_parse_cname(rr, results, &res[i]);
				break;
			case DNS_T_SOA:
				dns_parse_soa(rr, results, &res[i]);
				break;
			case DNS_T_NULL:
				dns_parse_null(rr, results, &res[i]);
				break;
			case DNS_T_WKS:
				dns_parse_wks(rr, results, &res[i]);
				break;
			case DNS_T_PTR:
				dns_parse_ptr(rr, results, &res[i]);
				break;
			case DNS_T_HINFO:
				dns_parse_hinfo(rr, results, &res[i]);
				break;
			case DNS_T_MX:
				dns_parse_mx(rr, results, &res[i]);
				break;
			case DNS_T_TXT:
				dns_parse_txt(rr, results, &res[i]);
				break;
			case DNS_T_SRV:
				dns_parse_srv(rr, results, &res[i]);
				break;
			case DNS_T_ANY:
			default:
#ifdef DEBUG_DNSCLIENT
				printf("Don't know how to parse RR type %d!\n",
				       res[i].dns_type);
#endif
				break;
		}

		p += res[i].dns_rlength;
	}

	return res;
}

struct dns_client_context *
dns_client_init()
{
	struct dns_client_context *ret = NULL;
	char buf[LINE_MAX], *p, *q;
	FILE *fp;
	int tokens, ns;

	ret = malloc(sizeof(struct dns_client_context));
	if(ret == NULL) {
		return NULL;
	}
	memset(ret, 0, sizeof(struct dns_client_context));

	ret->nameservers = malloc(sizeof(struct sockaddr_in*) * (SERVER_MAX + 1));
	if(ret->nameservers == NULL) {
		free(ret);
		return NULL;
	}
	ns = 0;
	memset(ret->nameservers, 0, sizeof(struct sockaddr_in*) * (SERVER_MAX + 1));

	fp = fopen(RESOLV_CONF, "r");
	if(fp == NULL) {
		free(ret);
		return NULL;
	}

	memset(buf, '\0', sizeof(buf));
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		if((p = strchr(buf, '#')) != NULL) {
			*p = '\0';
		}

		p = strtok_r(buf, WHITESPACE, &q);
		if(p) {
			if(!strcmp(p, "domain")) {
				p = strtok_r(NULL, WHITESPACE, &q);
				ret->domain = strdup(p);
			} else
			if(!strcmp(p, "search")) {
				ret->search = malloc(sizeof(char*) * (SEARCH_MAX + 1));
				if(ret->search == NULL) {
					return NULL;
				}
				for(tokens = 0; tokens < (SEARCH_MAX + 1); tokens++) {
					p = strtok_r(NULL, WHITESPACE, &q);
					if(p) {
						ret->search[tokens] = strdup(p);
					} else {
						ret->search[tokens] = NULL;
						break;
					}
				}
			} else
			if((!strcmp(p, "nameserver")) && (ns < SERVER_MAX)) {
				struct in_addr addr;
				p = strtok_r(NULL, WHITESPACE, &q);
				if(inet_aton(p, &addr) != 0) {
					struct sockaddr_in *sin;
					sin = malloc(sizeof(struct sockaddr_in));
					if(sin == NULL) {
						return NULL;
					}
					memset(sin, 0, sizeof(struct sockaddr_in));
					sin->sin_family = AF_INET;
					memcpy(&sin->sin_addr, &addr, sizeof(addr));
					sin->sin_port = htons(PORT);
					ret->nameservers[ns++] = sin;
#if 0
				} else {
					struct sockaddr_in6 *sin6;
					/* Try ipv6.  Don't know how to parse those just yet. */
					sin6 = malloc(sizeof(struct sockaddr_in6));

					if(sin6 == NULL) {
						return NULL;
					}
					memset(sin6, 0, sizeof(struct sockaddr_in6));

					sin6->sin6_family = AF_INET6;
					sin6->sin6_port = htons(PORT);
					ret->nameservers[ns++] = sin6;
#endif
				}
			}
		}

		memset(buf, '\0', sizeof(buf));
	}

	fclose(fp);

	return ret;
}

#ifdef DNSCLIENT_IS_MAIN
int
main(int argc, char **argv)
{
	unsigned char buf[2048];
	unsigned char answer[2048];
	struct dns_rr *rr;
	int ret;

	memset(&buf, 0, sizeof(buf));
	ret = dns_format_query(argc > 1 ? argv[1] : "devserv.devel.redhat.com.",
			       DNS_C_ANY, DNS_T_ANY, buf, sizeof(buf));
	printf("Sending query.\n");
	ret = res_send(buf, ret, answer, sizeof(answer));
	printf("Response was %d bytes long.\n", ret);

	rr = dns_parse_results(answer, ret);
	return 0;
}
#endif
