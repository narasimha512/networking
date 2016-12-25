/*
 * ss.c		"sockstat", socket statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>

#include "utils.h"
#include "rt_names.h"
#include "ll_map.h"
#include "libnetlink.h"
#include "namespace.h"
#include "SNAPSHOT.h"

#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>
#include <linux/netdevice.h>	/* for MAX_ADDR_LEN */
#include <linux/filter.h>
#include <linux/packet_diag.h>
#include <linux/netlink_diag.h>
#include <linux/sctp.h>

#define MAGIC_SEQ 123456

#define DIAG_REQUEST(_req, _r)						    \
	struct {							    \
		struct nlmsghdr nlh;					    \
		_r;							    \
	} _req = {							    \
		.nlh = {						    \
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,		    \
			.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST,\
			.nlmsg_seq = MAGIC_SEQ,				    \
			.nlmsg_len = sizeof(_req),			    \
		},							    \
	}

int resolve_hosts;
int preferred_family = AF_UNSPEC;
int sctp_ino;

int addr_width;

static const char *TCP_PROTO = "tcp";

enum {
        TCP_DB,
        DCCP_DB,
        UDP_DB,
        RAW_DB,
        UNIX_DG_DB,
        UNIX_ST_DB,
        UNIX_SQ_DB,
        PACKET_DG_DB,
        PACKET_R_DB,
        NETLINK_DB,
        SCTP_DB,
        MAX_DB
};

#define PACKET_DBM ((1<<PACKET_DG_DB)|(1<<PACKET_R_DB))
#define UNIX_DBM ((1<<UNIX_DG_DB)|(1<<UNIX_ST_DB)|(1<<UNIX_SQ_DB))
#define ALL_DB ((1<<MAX_DB)-1)
#define INET_L4_DBM ((1<<TCP_DB)|(1<<UDP_DB)|(1<<DCCP_DB)|(1<<SCTP_DB))
#define INET_DBM (INET_L4_DBM | (1<<RAW_DB))


enum {
        SS_UNKNOWN,
        SS_ESTABLISHED,
        SS_SYN_SENT,
        SS_SYN_RECV,
        SS_FIN_WAIT1,
        SS_FIN_WAIT2,
        SS_TIME_WAIT,
        SS_CLOSE,
        SS_CLOSE_WAIT,
        SS_LAST_ACK,
        SS_LISTEN,
        SS_CLOSING,
        SS_MAX
};

#define SS_ALL ((1 << SS_MAX) - 1)
#define SS_CONN (SS_ALL & ~((1<<SS_LISTEN)|(1<<SS_CLOSE)|(1<<SS_TIME_WAIT)|(1<<SS_SYN_RECV)))

#include "ssfilter.h"

struct filter {
	int dbs;
	int states;
	int families;
	struct ssfilter *f;
};

static const struct filter default_dbs[MAX_DB] = {
	[TCP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[SCTP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
};

static const struct filter default_afs[AF_MAX] = {
	[AF_INET] = {
		.dbs    = INET_DBM,
		.states = SS_CONN,
	},
	[AF_INET6] = {
		.dbs    = INET_DBM,
		.states = SS_CONN,
	},
};

static struct filter current_filter;

static void filter_db_set(struct filter *f, int db)
{
	f->states   |= default_dbs[db].states;
	f->dbs	    |= 1 << db;
}

static void filter_af_set(struct filter *f, int af)
{
	f->states	   |= default_afs[af].states;
	f->families	   |= 1 << af;
	preferred_family    = af;
}

static void filter_states_set(struct filter *f, int states)
{
	if (states)
		f->states = states;
}


static unsigned long long cookie_sk_get(const uint32_t *cookie)
{
	return (((unsigned long long)cookie[1] << 31) << 1) | cookie[0];
}

struct sockstat {
	struct sockstat	   *next;
	unsigned int	    type;
	uint16_t	    prot;
	uint16_t	    raw_prot;
	inet_prefix	    local;
	inet_prefix	    remote;
	int		    lport;
	int		    rport;
	int		    state;
	int		    rq, wq;
	unsigned int ino;
	unsigned int uid;
	int		    refcnt;
	unsigned int	    iface;
	unsigned long long  sk;
	char *name;
	char *peer_name;
	__u32		    mark;
};

struct dctcpstat {
	unsigned int	ce_state;
	unsigned int	alpha;
	unsigned int	ab_ecn;
	unsigned int	ab_tot;
	bool		enabled;
};

static void sock_addr_print_width(int addr_len, const char *addr, char *delim,
	 int port, const char *ifname)
{
	if (ifname) {
		printf("%*s%%%s%s%d ", addr_len, addr, ifname, delim,
				 port);
	} else {
		printf("%*s%s%d ", addr_len, addr, delim, port);
	}
}

struct scache {
	struct scache *next;
	int port;
	char *name;
	const char *proto;
};

struct scache *rlist;

static void inet_addr_print(const inet_prefix *a, int port, unsigned int ifindex)
{
	char buf[1024];
	const char *ap = buf;
	int est_len = addr_width;
	const char *ifname = NULL;

	if (a->family == AF_INET) {
		if (a->data[0] == 0) {
			buf[0] = '*';
			buf[1] = 0;
		} else {
			ap = format_host(AF_INET, 4, a->data);
		}
	} else {
		ap = format_host(a->family, 16, a->data);
		est_len = strlen(ap);
		if (est_len <= addr_width)
			est_len = addr_width;
		else
			est_len = addr_width + ((est_len-addr_width+3)/4)*4;
	}

	if (ifindex) {
		ifname   = ll_index_to_name(ifindex);
		est_len -= strlen(ifname) + 1;  /* +1 for percent char */
		if (est_len < 0)
			est_len = 0;
	}

	sock_addr_print_width(est_len, ap, ":",  port,
			ifname);
}

struct aafilter {
	inet_prefix	addr;
	int		port;
	unsigned int	iface;
	__u32		mark;
	__u32		mask;
	struct aafilter *next;
};

/* Relocate external jumps by reloc. */
static void ssfilter_patch(char *a, int len, int reloc)
{
	while (len > 0) {
		struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)a;

		if (op->no == len+4)
			op->no += reloc;
		len -= op->yes;
		a += op->yes;
	}
	if (len < 0)
		abort();
}

static int ssfilter_bytecompile(struct ssfilter *f, char **bytecode)
{
	switch (f->type) {
		case SSF_S_AUTO:
	{
		if (!(*bytecode = malloc(4))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_AUTO, 4, 8 };
		return 4;
	}
		case SSF_DCOND:
		case SSF_SCOND:
	{
		struct aafilter *a = (void *)f->pred;
		struct aafilter *b;
		char *ptr;
		int  code = (f->type == SSF_DCOND ? INET_DIAG_BC_D_COND : INET_DIAG_BC_S_COND);
		int len = 0;

		for (b = a; b; b = b->next) {
			len += 4 + sizeof(struct inet_diag_hostcond);
			if (a->addr.family == AF_INET6)
				len += 16;
			else
				len += 4;
			if (b->next)
				len += 4;
		}
		if (!(ptr = malloc(len))) abort();
		*bytecode = ptr;
		for (b = a; b; b = b->next) {
			struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)ptr;
			int alen = (a->addr.family == AF_INET6 ? 16 : 4);
			int oplen = alen + 4 + sizeof(struct inet_diag_hostcond);
			struct inet_diag_hostcond *cond = (struct inet_diag_hostcond *)(ptr+4);

			*op = (struct inet_diag_bc_op){ code, oplen, oplen+4 };
			cond->family = a->addr.family;
			cond->port = a->port;
			cond->prefix_len = a->addr.bitlen;
			memcpy(cond->addr, a->addr.data, alen);
			ptr += oplen;
			if (b->next) {
				op = (struct inet_diag_bc_op *)ptr;
				*op = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, len - (ptr-*bytecode)};
				ptr += 4;
			}
		}
		return ptr - *bytecode;
	}
		case SSF_D_GE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_GE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_D_LE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_LE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_S_GE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_GE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_S_LE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_LE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}

		case SSF_AND:
	{
		char *a1 = NULL, *a2 = NULL, *a;
		int l1, l2;

		l1 = ssfilter_bytecompile(f->pred, &a1);
		l2 = ssfilter_bytecompile(f->post, &a2);
		if (!l1 || !l2) {
			free(a1);
			free(a2);
			return 0;
		}
		if (!(a = malloc(l1+l2))) abort();
		memcpy(a, a1, l1);
		memcpy(a+l1, a2, l2);
		free(a1); free(a2);
		ssfilter_patch(a, l1, l2);
		*bytecode = a;
		return l1+l2;
	}
		case SSF_OR:
	{
		char *a1 = NULL, *a2 = NULL, *a;
		int l1, l2;

		l1 = ssfilter_bytecompile(f->pred, &a1);
		l2 = ssfilter_bytecompile(f->post, &a2);
		if (!l1 || !l2) {
			free(a1);
			free(a2);
			return 0;
		}
		if (!(a = malloc(l1+l2+4))) abort();
		memcpy(a, a1, l1);
		memcpy(a+l1+4, a2, l2);
		free(a1); free(a2);
		*(struct inet_diag_bc_op *)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, l2+4 };
		*bytecode = a;
		return l1+l2+4;
	}
		case SSF_NOT:
	{
		char *a1 = NULL, *a;
		int l1;

		l1 = ssfilter_bytecompile(f->pred, &a1);
		if (!l1) {
			free(a1);
			return 0;
		}
		if (!(a = malloc(l1+4))) abort();
		memcpy(a, a1, l1);
		free(a1);
		*(struct inet_diag_bc_op *)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, 8 };
		*bytecode = a;
		return l1+4;
	}
		case SSF_DEVCOND:
	{
		/* bytecompile for SSF_DEVCOND not supported yet */
		return 0;
	}
		case SSF_MARKMASK:
	{
		struct aafilter *a = (void *)f->pred;
		struct instr {
			struct inet_diag_bc_op op;
			struct inet_diag_markcond cond;
		};
		int inslen = sizeof(struct instr);

		if (!(*bytecode = malloc(inslen))) abort();
		((struct instr *)*bytecode)[0] = (struct instr) {
			{ INET_DIAG_BC_MARK_COND, inslen, inslen + 4 },
			{ a->mark, a->mask},
		};

		return inslen;
	}
		default:
		abort();
	}
}

static void inet_stats_print(struct sockstat *s)
{
	printf("Rq:%d\t",s->rq);
	printf("Sq:%d\t",s->wq);
	inet_addr_print(&s->local, s->lport, s->iface);
	inet_addr_print(&s->remote, s->rport, 0);

}

static void parse_diag_msg(struct nlmsghdr *nlh, struct sockstat *s)
{
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	s->state	= r->idiag_state;
	s->local.family	= s->remote.family = r->idiag_family;
	s->lport	= ntohs(r->id.idiag_sport);
	s->rport	= ntohs(r->id.idiag_dport);
	s->wq		= r->idiag_wqueue;
	s->rq		= r->idiag_rqueue;
	s->ino		= r->idiag_inode;
	s->uid		= r->idiag_uid;
	s->iface	= r->id.idiag_if;
	s->sk		= cookie_sk_get(&r->id.idiag_cookie[0]);

	s->mark = 0;
	if (tb[INET_DIAG_MARK])
		s->mark = *(__u32 *) RTA_DATA(tb[INET_DIAG_MARK]);
	if (tb[INET_DIAG_PROTOCOL])
		s->raw_prot = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);
	else
		s->raw_prot = 0;

	if (s->local.family == AF_INET)
		s->local.bytelen = s->remote.bytelen = 4;
	else
		s->local.bytelen = s->remote.bytelen = 16;

	memcpy(s->local.data, r->id.idiag_src, s->local.bytelen);
	memcpy(s->remote.data, r->id.idiag_dst, s->local.bytelen);
}

static int inet_show_sock(struct nlmsghdr *nlh,
			  struct sockstat *s)
{
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[INET_DIAG_PROTOCOL])
		s->type = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);

	inet_stats_print(s);

	sctp_ino = s->ino;

	printf("\n");
	return 0;
}

static int sockdiag_send(int family, int fd, int protocol, struct filter *f)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	DIAG_REQUEST(req, struct inet_diag_req_v2 r);
	char    *bc = NULL;
	int	bclen;
	struct msghdr msg;
	struct rtattr rta;
	struct iovec iov[3];
	int iovlen = 1;

	memset(&req.r, 0, sizeof(req.r));
	req.r.sdiag_family = family;
	req.r.sdiag_protocol = protocol;
	req.r.idiag_states = f->states;

	iov[0] = (struct iovec){
		.iov_base = &req,
		.iov_len = sizeof(req)
	};
	if (f->f) {
		bclen = ssfilter_bytecompile(f->f, &bc);
		if (bclen) {
			rta.rta_type = INET_DIAG_REQ_BYTECODE;
			rta.rta_len = RTA_LENGTH(bclen);
			iov[1] = (struct iovec){ &rta, sizeof(rta) };
			iov[2] = (struct iovec){ bc, bclen };
			req.nlh.nlmsg_len += RTA_LENGTH(bclen);
			iovlen = 3;
		}
	}

	msg = (struct msghdr) {
		.msg_name = (void *)&nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};

	if (sendmsg(fd, &msg, 0) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

struct inet_diag_arg {
	struct filter *f;
	int protocol;
	struct rtnl_handle *rth;
};

static int show_one_inet_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *h, void *arg)
{
	int err;
	struct inet_diag_arg *diag_arg = arg;
	struct inet_diag_msg *r = NLMSG_DATA(h);
	struct sockstat s = {};

	if (!(diag_arg->f->families & (1 << r->idiag_family)))
		return 0;

	parse_diag_msg(h, &s);
	s.type = diag_arg->protocol;


	err = inet_show_sock(h, &s);
	if (err < 0)
		return err;

	return 0;
}

static int inet_show_netlink(struct filter *f, FILE *dump_fp, int protocol)
{
        int err = 0;
        struct rtnl_handle rth;
        int family = PF_INET;
        struct inet_diag_arg arg = { .f = f, .protocol = protocol };

        if (rtnl_open_byproto(&rth, 0, NETLINK_SOCK_DIAG))
                return -1;

        rth.dump = MAGIC_SEQ;
        rth.dump_fp = dump_fp;
        if (preferred_family == PF_INET6)
                family = PF_INET6;

        if ((err = sockdiag_send(family, rth.fd, protocol, f)))
                goto Exit;

        if ((err = rtnl_dump_filter(&rth, show_one_inet_sock, &arg))) {
                goto Exit;
        }

Exit:
        rtnl_close(&rth);
        if (arg.rth)
                rtnl_close(arg.rth);
        return err;
}


static int tcp_show(struct filter *f, int socktype)
{

	 return inet_show_netlink(f, NULL, socktype);
}

static struct ssfilter * alloc_node(int type, void *pred)
{
        struct ssfilter *n = malloc(sizeof(*n));
        if (n == NULL)
                abort();
        n->type = type;
        n->pred = pred;
        n->post = NULL;
        return n;
}

static int remember_he(struct aafilter *a, struct hostent *he)
{
	char **ptr = he->h_addr_list;
	int cnt = 0;
	int len;

	if (he->h_addrtype == AF_INET)
		len = 4;
	else if (he->h_addrtype == AF_INET6)
		len = 16;
	else
		return 0;

	while (*ptr) {
		struct aafilter *b = a;

		if (a->addr.bitlen) {
			if ((b = malloc(sizeof(*b))) == NULL)
				return cnt;
			*b = *a;
			b->next = a->next;
			a->next = b;
		}
		memcpy(b->addr.data, *ptr, len);
		b->addr.bytelen = len;
		b->addr.bitlen = len*8;
		b->addr.family = he->h_addrtype;
		ptr++;
		cnt++;
	}
	return cnt;
}

static int get_dns_host(struct aafilter *a, const char *addr, int fam)
{
	static int notfirst;
	int cnt = 0;
	struct hostent *he;

	a->addr.bitlen = 0;
	if (!notfirst) {
		sethostent(1);
		notfirst = 1;
	}
	he = gethostbyname2(addr, fam == AF_UNSPEC ? AF_INET : fam);
	if (he)
		cnt = remember_he(a, he);
	if (fam == AF_UNSPEC) {
		he = gethostbyname2(addr, AF_INET6);
		if (he)
			cnt += remember_he(a, he);
	}
	return !cnt;
}

static int xll_initted;

static void xll_init(void)
{
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	ll_init_map(&rth);
	rtnl_close(&rth);
	xll_initted = 1;
}

static int xll_name_to_index(const char *dev)
{
	if (!xll_initted)
		xll_init();
	return ll_name_to_index(dev);
}

void *parse_hostcond(char *addr, bool is_port)
{
	char *port = NULL;
	struct aafilter a = { .port = -1 };
	struct aafilter *res;
	int fam = preferred_family;
	struct filter *f = &current_filter;

	if (fam == AF_UNIX || strncmp(addr, "unix:", 5) == 0) {
		char *p;

		a.addr.family = AF_UNIX;
		if (strncmp(addr, "unix:", 5) == 0)
			addr += 5;
		p = strdup(addr);
		a.addr.bitlen = 8*strlen(p);
		memcpy(a.addr.data, &p, sizeof(p));
		fam = AF_UNIX;
		goto out;
	}

	if (fam == AF_PACKET || strncmp(addr, "link:", 5) == 0) {
		a.addr.family = AF_PACKET;
		a.addr.bitlen = 0;
		if (strncmp(addr, "link:", 5) == 0)
			addr += 5;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if ((a.port = xll_name_to_index(port+1)) <= 0)
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			unsigned short tmp;

			a.addr.bitlen = 32;
			if (ll_proto_a2n(&tmp, addr))
				return NULL;
			a.addr.data[0] = ntohs(tmp);
		}
		fam = AF_PACKET;
		goto out;
	}

	if (fam == AF_NETLINK || strncmp(addr, "netlink:", 8) == 0) {
		a.addr.family = AF_NETLINK;
		a.addr.bitlen = 0;
		if (strncmp(addr, "netlink:", 8) == 0)
			addr += 8;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if (strcmp(port+1, "kernel") == 0)
						a.port = 0;
					else
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			a.addr.bitlen = 32;
			if (nl_proto_a2n(&a.addr.data[0], addr) == -1)
				return NULL;
		}
		fam = AF_NETLINK;
		goto out;
	}

	if (fam == AF_INET || !strncmp(addr, "inet:", 5)) {
		fam = AF_INET;
		if (!strncmp(addr, "inet:", 5))
			addr += 5;
	} else if (fam == AF_INET6 || !strncmp(addr, "inet6:", 6)) {
		fam = AF_INET6;
		if (!strncmp(addr, "inet6:", 6))
			addr += 6;
	}

	/* URL-like literal [] */
	if (addr[0] == '[') {
		addr++;
		if ((port = strchr(addr, ']')) == NULL)
			return NULL;
		*port++ = 0;
	} else if (addr[0] == '*') {
		port = addr+1;
	} else {
		port = strrchr(strchr(addr, '/') ? : addr, ':');
	}

	if (is_port)
		port = addr;

	if (port && *port) {
		if (*port == ':')
			*port++ = 0;

		if (*port && *port != '*') {
			if (get_integer(&a.port, port, 0)) {
				struct servent *se1 = NULL;
				struct servent *se2 = NULL;

				if (current_filter.dbs&(1<<TCP_DB))
					se2 = getservbyname(port, TCP_PROTO);
				if (se1 && se2 && se1->s_port != se2->s_port) {
					fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
					return NULL;
				}
				if (!se1)
					se1 = se2;
				if (se1) {
					a.port = ntohs(se1->s_port);
				} else {
					struct scache *s;

					for (s = rlist; s; s = s->next) {
						if ((s->proto == TCP_PROTO &&
						     (current_filter.dbs&(1<<TCP_DB)))) {
							if (s->name && strcmp(s->name, port) == 0) {
								if (a.port > 0 && a.port != s->port) {
									fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
									return NULL;
								}
								a.port = s->port;
							}
						}
					}
					if (a.port <= 0) {
						fprintf(stderr, "Error: \"%s\" does not look like a port.\n", port);
						return NULL;
					}
				}
			}
		}
	}
	if (!is_port && addr && *addr && *addr != '*') {
		if (get_prefix_1(&a.addr, addr, fam)) {
			if (get_dns_host(&a, addr, fam)) {
				fprintf(stderr, "Error: an inet prefix is expected rather than \"%s\".\n", addr);
				return NULL;
			}
		}
	}

out:
	if (fam != AF_UNSPEC) {
		int states = f->states;
		f->families = 0;
		filter_af_set(f, fam);
		filter_states_set(f, states);
	}

	res = malloc(sizeof(*res));
	if (res)
		memcpy(res, &a, sizeof(a));
	return res;
}

int main(int argc, char *argv[])
{
	int state_filter = 0;
	resolve_hosts = 0;
	struct ssfilter * dport_filter;
	struct ssfilter * sport_filter;

	filter_db_set(&current_filter, TCP_DB);
	filter_af_set(&current_filter, AF_INET);
	//filter_af_set(&current_filter, AF_INET6);

	filter_states_set(&current_filter, state_filter);
    
	struct aafilter *port_filter = parse_hostcond(argv[1],true);
	dport_filter = alloc_node(SSF_DCOND,port_filter);
	sport_filter = alloc_node(SSF_SCOND,port_filter);
	current_filter.f = alloc_node(SSF_OR,dport_filter);
        current_filter.f->post = sport_filter;


        tcp_show(&current_filter, IPPROTO_TCP);


	fflush(stdout);

	return 0;
}
