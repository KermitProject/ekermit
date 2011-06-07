#Makefile for embedded Kermit.
#
# Copyright (C) 1995, 2004,
#  Trustees of Columbia University in the City of New York.
#  All Rights Reserved.
#  For license see kermit.c

OBJS= main.o kermit.o unixio.o
EK = makewhat
ALL = $(EK)

all: $(ALL)

ema:
	cp kermit.h-emapex kermit.h
	cp kermit.c-emapex kermit.c

lin:
	cp kermit.h-linux kermit.h
	cp kermit.c-linux kermit.c

eksw: $(OBJS)
	$(CC) $(CFLAGS) -o eksw $(OBJS)

#Dependencies

main.o: main.c cdefs.h debug.h kermit.h platform.h

kermit.o: kermit.c cdefs.h debug.h kermit.h

unixio.o: unixio.c cdefs.h debug.h platform.h kermit.h

#Targets

#Build with cc.
cc:
	make eksw

#Build with gcc.
gccwhat:
#	@UNAME=`uname` ; make "CC=gcc" "CC2=gcc" "CFLAGS=-D$$UNAME -O2" eksw
#	@UNAME=`uname` ; make "CC=gcc" "CC2=gcc" "CFLAGS=-D$$UNAME -O2 -DP_PKTLEN=1024" eksw
#	make "CC=gcc" "CC2=gcc" "CFLAGS=-DFN_MAX=16 -DIBUFLEN=256 -DOBUFLEN=256 -DNO_LP -DNO_AT -DNO_SSW -DNO_SCAN" eksw
#	make "CC=gcc" "CC2=gcc" "CFLAGS=-DDEBUG -DFN_MAX=16 -DIBUFLEN=256 -DOBUFLEN=256 -DNO_LP -DNO_SSW -DNO_SCAN" eksw
	make "CC=gcc" "CC2=gcc" "CFLAGS=-Wall -DDEBUG -DSTATIC=static -g" eksw
#	make "CC=gcc" "CC2=gcc" "CFLAGS=-Wall -DDEBUG -DSTATIC=static" eksw
#	make "CC=gcc" "CC2=gcc" "CFLAGS=-Wall -DDEBUG -DP_PKTLEN=1024 -DOBUFLEN=10240" eksw
#	make "CC=gcc" "CC2=gcc" "CFLAGS=-Wall -DDEBUG -DP_PKTLEN=1024 -DOBUFLEN=512 -DIBUFLEN=512 -DP_WSLOTS=3" eksw
#	make "CC=gcc" "CC2=gcc" "CFLAGS=-Wall -DDEBUG" eksw

#Ditto but no debugging.
gccnd:
	make "CC=gcc" "CC2=gcc" "CFLAGS=-Wall -DNODEBUG -O2" eksw

#Build with gcc, Receive-Only, minimum size and features.
gccmin:
	make "CC=gcc" "CC2=gcc" \
	"CFLAGS=-DMINSIZE -DOBUFLEN=256 -DFN_MAX=16 -O2" eksw

#Ditto but Receive-Only:
gccminro:
	make "CC=gcc" "CC2=gcc" \
	"CFLAGS=-DMINSIZE -DOBUFLEN=256 -DFN_MAX=16 -DRECVONLY -O2" eksw

#Minimum size, receive-only, but with debugging:
gccminrod:
	make "CC=gcc" "CC2=gcc" \
	"CFLAGS=-DMINSIZE -DOBUFLEN=256 -DFN_MAX=16 -DRECVONLY -DDEBUG -O2" eksw

#HP-UX 9.0 or higher with ANSI C.
hp:
	make "SHELL=/usr/bin/sh" CC=/opt/ansic/bin/cc CC2=/opt/ansic/bin/cc \
	eksw "CFLAGS=-DHPUX -Aa"

#To get profile, build this target, run it, then "gprof ./eksw > file".
gprof:
	make "CC=gcc" "CC2=gcc" eksw "CFLAGS=-DNODEBUG -pg" "LNKFLAGS=-pg"

clean:
	rm -f $(OBJS) core

makewhat:
	@echo 'Defaulting to gcc...'
	make gccwhat

test_snd:
	make gccwhat
	rm -f ../tmp/snd
	eksw /dev/ttyR7 9600 -w 3 -d -s snd
	cmp snd ../tmp/snd

test_rcv:
	make gccwhat
	rm -f rcv
	eksw /dev/ttyR7 9600 -w 3 -d -g rcv
	ls -l rcv ../tmp/rcv
	cmp rcv ../tmp/rcv

tar:
	tar cfz eksw.tgz *.h *.c makefile \
	eksw-rcv.run eksw-snd.run eksw-sr.run indent.run \
	kermit.h-linux kermit.c-linux

pub:
	cp -p eksw.tgz /home/dunlap/public_html/kermit

#End of Makefile

