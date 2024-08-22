# $FreeBSD$

.PATH:  /usr/src/sys/netinet
KMOD=	siftr2
SRCS=	siftr2.c opt_kern_tls.h

.include <bsd.kmod.mk>
