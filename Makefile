# $FreeBSD$

.PATH: /usr/src/sys/netinet
KMOD= siftr
SRCS= siftr.c
CFLAGS+=-D VIMAGE

# Uncomment to add IPv6 support
#CFLAGS+=-DSIFTR_IPV6

.include <bsd.kmod.mk>
