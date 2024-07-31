# $FreeBSD$

.PATH:  /usr/src/sys/netinet
KMOD=	siftr
SRCS=	siftr.c opt_kern_tls.h

.include <bsd.kmod.mk>
