/* $Id: dnsreflector.c,v 1.10 2003/04/27 13:22:13 armin Exp $ */
/*
 * Copyright (c) 2003 Armin Wolfermann.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/*
 * ;; ANSWER SECTION:
 * name.from.query.	86400	IN	A	127.0.0.1
 */

#define ANSWER_A "\300\014\000\001\000\001\000\001\121\200\000\004\177\000\000\001"

/*
 * ;; ANSWER SECTION:
 * name.from.query.	86400	IN	AAAA	::1
 */

#define ANSWER_AAAA "\300\014\000\034\000\001\000\001\121\200\000\020\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001"

/*
 * ;; ANSWER SECTION:
 * name.from.query.	86400	IN	MX	10 localhost.
 */

#define ANSWER_MX "\300\014\000\017\000\001\000\001\121\200\000\015\000\012\011localhost\000"

/*
 * ;; AUTHORITY SECTION:
 * name.from.query.	86400	IN	NS	localhost.
 */

#define AUTHORITY "\300\014\000\002\000\001\000\001\121\200\000\013\011localhost\000"

/*
 * ;; ADDITIONAL SECTION
 * localhost.		86400	IN	A	127.0.0.1
 */

#define ADDITIONAL "\011localhost\000\000\001\000\001\000\001\121\200\000\004\177\000\000\001"

#define PUTSTRING(msg, n, s) { \
	memcpy((void *)&msg[n], (s), sizeof(s) - 1); \
	n += sizeof(s) - 1; }

#define HDR(m) ((HEADER *)(m))

#define MAXQUERY (PACKETSZ - sizeof(ADDITIONAL) - sizeof(AUTHORITY) - sizeof(ANSWER_AAAA))

static struct syslog_data sdata = SYSLOG_DATA_INIT;

static void
logit(int level, const char *fmt, ...)
{
	va_list ap;
	extern char *__progname;

	va_start(ap, fmt);

	if (sdata.opened) {
		vsyslog_r(level, &sdata, fmt, ap);
	} else {
		fprintf(stderr, "%s: ", __progname);
		vfprintf(stderr, fmt, ap);
		if (strchr(fmt, '\n') == NULL)
			fprintf(stderr, "\n");
	}

	va_end(ap);
}

static int
dnstoa(char *pkt, char *string)
{
	u_char len;
	int i, result = 0;

	while (((len = *pkt) != 0) && (len < MAXLABEL)) {
		++pkt;

		if (result + len > MAXDNAME)
			break;

		for (i=0; i < len; i++) {
			*string++ = *pkt++;
		}
		*string++ = '.';

		result += (len + 1);
	}
	*string = 0;

	return (result);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in laddr;
	struct sockaddr_in raddr;
	socklen_t socklen = sizeof(struct sockaddr_in);
	struct passwd *pw;
	int ch, s, n;
	char msg[PACKETSZ];
	char name[MAXDNAME];
	char *data;
	u_short type;

	/* Options and their defaults */
	char *address = NULL;
	int daemonize = 0;
	int port = 53000;

	/* Process commandline arguments */
	while ((ch = getopt(argc, argv, "a:dp:h")) != -1) {
		switch (ch) {
		case 'a':
			address = optarg;
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'p':
			port = strtol(optarg, NULL, 10);
			break;
		case 'h':
		default:
			fprintf(stderr,
			    "Usage: %s -a address -d -p port\n", argv[0]);
			exit(1);
		}
	}

	/* Prepare and bind our socket */
	bzero((char *)&laddr, sizeof(struct sockaddr_in));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = inet_addr(address ? address : "127.0.0.1");
	laddr.sin_port = htons(port);

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		err(1, "socket");

	if (bind(s, (struct sockaddr *)&laddr, socklen) == -1)
		err(1, "bind");

	/* Use syslog if daemonized */
	if (daemonize) {
		tzset();
		openlog_r("dnsreflector", LOG_PID | LOG_NDELAY, LOG_DAEMON,
		    &sdata);
	}

	/* Daemonize if requested */
	if (daemonize && (daemon(0, 0) == -1))
		err(1, "daemon");

	/* Find less privileged user */
	pw = getpwnam("_spamd");
	if (!pw)
		pw = getpwnam("nobody");

	/* Chroot to /var/empty */
	if (chroot("/var/empty") == -1 || chdir("/") == -1) {
		logit(LOG_ERR, "cannot chroot to /var/empty");
		exit(1);
	}

	/* Drop privileges */
	if (pw) {
		if ((setgroups(1, &pw->pw_gid) == -1) ||
		    (setegid(pw->pw_gid) == -1) ||
		    (setgid(pw->pw_gid) == -1) ||
		    (seteuid(pw->pw_uid) == -1) ||
		    (setuid(pw->pw_uid) == -1)) {
			logit(LOG_ERR, "cannot drop privileges");
			exit(1);
		}
	}

	/* Main loop: receive queries and send answers */
	for(;;) {
		n = recvfrom(s, &msg, PACKETSZ, 0,
		    (struct sockaddr *)&raddr, &socklen);

		/* Drop short packets */
		if (n < sizeof(HEADER))
			continue;

		/* Drop large packets */
		if (n > MAXQUERY)
			continue;

		/* We process only queries */
		if (HDR(&msg)->opcode != htons(QUERY))
			continue;

		/* We want a single query */
		if (HDR(&msg)->qdcount != htons(1))
			continue;

		/* Drop packets with additional payload */
		if (HDR(&msg)->ancount || HDR(&msg)->nscount ||
		    HDR(&msg)->arcount)
			continue;

		/* Set answer flags */
		HDR(&msg)->qr = 1;
		HDR(&msg)->ra = 1;
		HDR(&msg)->aa = 1;

		/* Set number of records in each section */
		HDR(&msg)->ancount = htons(1);
		HDR(&msg)->nscount = htons(1);
		HDR(&msg)->arcount = htons(1);

		/* Get type of query */
		data = (char *)&msg[n - 4];
		GETSHORT(type, data);

		/* Append rdata depending on type of query */
		switch (type) {
		case T_A:
			PUTSTRING(msg, n, ANSWER_A);
			break;
		case T_AAAA:
			PUTSTRING(msg, n, ANSWER_AAAA);
			break;
		case T_NS:
			PUTSTRING(msg, n, AUTHORITY);
			break;
		case T_MX:
			PUTSTRING(msg, n, ANSWER_MX);
			break;
		default:
			/* Drop any other query */
			continue;
		}

		/* Append authority section */
		PUTSTRING(msg, n, AUTHORITY);

		/* Append additional section */
		PUTSTRING(msg, n, ADDITIONAL);

		/* Send answer back to sender */
		if (sendto(s, &msg, (size_t)n, 0, (struct sockaddr *)&raddr,
			    socklen) == -1) {
			logit(LOG_WARNING, "sendto");
		}

		/* Log this query */
		dnstoa((char *)&msg[HFIXEDSZ], (char *)&name);
		logit(LOG_INFO, "%s %s? %s", inet_ntoa(raddr.sin_addr),
			type == T_A ? "A" :
			type == T_AAAA ? "AAAA" :
			type == T_NS ? "NS" :
			type == T_MX ? "MX" : NULL, (char *)&name);
	}

	return (0);
}
