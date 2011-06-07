// todo:
// 1. should we send an I packet before the R-00 packet?
// 2. commands to exit the server and/or logout from the session

#define KERMIT_C
/*
 * EKSW: Embedded Kermit with true sliding windows 
 * protocol module Version: 0.94
 * Most Recent Update: March 30, 2010
 * John Dunlap
 * 
 * Author: Frank da Cruz. Copyright (C) 1995, 2004, Trustees of Columbia
 * University in the City of New York. All rights reserved.
 * 
 * No stdio or other runtime library calls, no system calls, no system
 * includes, no static data, and no global variables in this module.
 * 
 * Warning: you cannot use debug() in any routine whose argument list does
 * not include "struct k_data *k".  Thus most routines in this module
 * include this arg, even if they don't use it. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of Columbia University nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *  
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

# if DEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
# ifndef __linux
# include "../include/snprintf.h"
# endif
# endif

#include "cdefs.h"              /* C language defs for all modules */
#include "debug.h"              /* Debugging */
#include "kermit.h"             /* Kermit protocol definitions */

#define USE_ZGETC_MACRO
#ifdef USE_ZGETC_MACRO
#define zgetc() \
((--(k->zincnt))>=0)?((int)(*(k->zinptr)++)&0xff):(*(k->readf))(k)
#else // USE_ZGETC_MACRO
STATIC int
zgetc (struct k_data *k)
{
   UCHAR *ptr;
   int kar;

   k->zincnt--;
   if (k->zincnt >= 0)
   {
      ptr = k->zinptr;
      k->zinptr++;
      kar = (*ptr) & 0xFF;
   }
   else
   {
      kar = (*(k->readf)) (k);
   }
   return (kar);
}
#endif // USE_ZGETC_MACRO

/*
 * See cdefs.h for meaning of STATIC, ULONG, and UCHAR 
 */

STATIC ULONG stringnum (UCHAR *, struct k_data *);
STATIC UCHAR *numstring (ULONG, UCHAR *, int, struct k_data *);
STATIC int spkt (char, short, int, UCHAR *, struct k_data *);
STATIC int ack (struct k_data *, short, UCHAR * text);
STATIC int nak (struct k_data *, short, short);
STATIC int chk1 (UCHAR *, struct k_data *);
STATIC USHORT chk2 (UCHAR *, struct k_data *);
STATIC USHORT chk3 (UCHAR *, struct k_data *);

STATIC void spar (struct k_data *, UCHAR *, int);
STATIC int rpar (struct k_data *, char);
STATIC int decode (struct k_data *, struct k_response *, short, UCHAR *,
                   int rslot);

STATIC int gattr (struct k_data *, UCHAR *, struct k_response *);
STATIC int sattr (struct k_data *, struct k_response *);

STATIC int sdata (struct k_data *, struct k_response *);

STATIC void epkt (char *, struct k_data *);
STATIC int getpkt (struct k_data *, struct k_response *);
STATIC int encstr (UCHAR *, struct k_data *, struct k_response *);
STATIC void encode (int, int, struct k_data *);
STATIC short nxtpkt (struct k_data *);
STATIC int resend (struct k_data *, short seq);
STATIC int nused_sslots (struct k_data *);
STATIC int nused_rslots (struct k_data *);

#if 0
STATIC void decstr (UCHAR *, struct k_data *, struct k_response *);
STATIC short prevpkt (struct k_data *);
#endif

STATIC short earliest_sseq (struct k_data *k);

#ifdef DEBUG
int xerror (void);
STATIC void show_sslots (struct k_data *);
STATIC void show_rslots (struct k_data *);
#endif /* DEBUG */

STATIC int test_rslots (struct k_data *);

STATIC short
earliest_rseq (struct k_data *k)
{
   short slot;
   short seq;
   short seq_ref = -1;
   short seq_rot;
   short seq_rot_oldest = -1;
   short seq_oldest = -1;

   for (slot = 0; slot < k->wslots; slot++)
   {
      seq = k->ipktinfo[slot].seq;
      if (seq >= 0 && seq < 64)
      {
         seq_ref = seq;
         seq_oldest = seq;
         seq_rot_oldest = 0;
      }
   }

   if (seq_ref != -1)
   {
      for (slot = 0; slot < k->wslots; slot++)
      {
         seq = k->ipktinfo[slot].seq;
         if (seq >= 0 && seq < 64)
         {
            seq_rot = seq - seq_ref;
            if (seq_rot < -31)
               seq_rot += 64;
            if (seq_rot > 31)
               seq_rot -= 64;

            if (seq_rot < seq_rot_oldest)
            {
               seq_rot_oldest = seq_rot;
               seq_oldest = seq;
            }
         }
      }
   }

   debug (DB_LOG, "EARLIEST_RSEQ", 0, seq_oldest);
   return (seq_oldest);
}

STATIC short
latest_rseq (struct k_data *k)
{
   short slot;
   short seq;
   short seq_ref = -1;
   short seq_rot;
   short seq_rot_newest = -1;
   short seq_newest = -1;

   for (slot = 0; slot < k->wslots; slot++)
   {
      seq = k->ipktinfo[slot].seq;
      if (seq >= 0 && seq < 64)
      {
         seq_ref = seq;
         seq_newest = seq;
         seq_rot_newest = 0;
      }
   }

   if (seq_ref != -1)
   {
      for (slot = 0; slot < k->wslots; slot++)
      {
         seq = k->ipktinfo[slot].seq;
         if (seq >= 0 && seq < 64)
         {
            seq_rot = seq - seq_ref;
            if (seq_rot < -31)
               seq_rot += 64;
            if (seq_rot > 31)
               seq_rot -= 64;

            if (seq_rot > seq_rot_newest)
            {
               seq_rot_newest = seq_rot;
               seq_newest = seq;
            }
         }
      }
   }

   debug (DB_LOG, "LATEST_RSEQ", 0, seq_newest);
   return (seq_newest);
}

// nak_oldest_unacked() never finds anything because
// we ACK as soon as we put each packet into its slot.
// Also, rseq for short packets is unvetted and for long packets
// the only test is a simple checksum so it's safer
// to time out.  For Iridium, there are no bad bytes so
// the point is moot.
#undef USE_NAK_OLDEST_UNACKED
#ifdef USE_NAK_OLDEST_UNACKED
STATIC int
nak_oldest_unacked (struct k_data *k, short rseq)
{
   short slot;
   short seq;
   short age;
   short oldest_seq = -1;
   short oldest_age = -99;
   short oldest_rslot = -1;
   int flg;

   for (slot = 0; slot < k->wslots; slot++)
   {
      seq = k->ipktinfo[slot].seq;
      flg = k->ipktinfo[slot].flg;
      if (seq >= 0 && seq < 64 && flg == 0)
      {
         age = k->s_seq - seq;
         if (age < 0)
            age += 64;
         if (age > 63)
            age -= 64;

         if (age > oldest_age)
         {
            oldest_rslot = slot;
            oldest_age = age;
            oldest_seq = seq;
         }
      }
   }

   debug (DB_LOG, "NAK_OLDEST_UNACKED oldest_seq", 0, oldest_seq);
   debug (DB_LOG, "NAK_OLDEST_UNACKED rseq", 0, rseq);

   if (oldest_seq != -1)
   {
      nak (k, oldest_seq, oldest_rslot);
//    k->anseq = oldest_seq;
      return (X_OK);
   }
   else
   {
//    nak (k, (k->anseq+1)&63, -1);
//    nak (k, k->anseq, -1);
//    nak (k, rseq, -1);
      return (X_OK);
   }
}
#endif /* USE_NAK_OLDEST_UNACKED */

STATIC int
handle_good_rpkt (struct k_data *k, struct k_response *r,
                  short rseq, UCHAR * pbuf)
{
   // true sliding windows for receive see p. 292
   short wsize = k->wslots;     // negotiated window size
   short high = -1;             // latest table entry (chronlogically)
   short low = -1;              // earliest possible table entry
   short eseq = -1;             // expected sequence number
// short psn = rseq;            // just-arrived packet sequence number

   short rslot;
   short nused;
   int isnxt = 0;
   int isgap = 0;
   int isold = 0;
   int rc;
   int i;
   short iseq;
   short dseq;
   short nnak;
   int do_add_pkt;

   nused = nused_rslots (k);

   if (nused == 0)
   {
      eseq = rseq;              // for first time
   }
   else
   {
      high = latest_rseq (k);
      low = high - wsize + 1;
      if (low < 0)
         low += 64;

      eseq = (high + 1) & 63;

      if (rseq != eseq)
      {
         for (i = 2; i <= wsize; i++)
         {
            iseq = (high + i) & 63;
            if (rseq == iseq)
            {
               isgap = 1;
               break;
            }
         }
      }

      if (rseq != eseq && !isgap)
      {
         short hp = (high + 1) & 63;
         for (i = low; i != hp; i++)
         {
            iseq = i & 63;
            if (rseq == iseq)
            {
               isold = 1;
               break;
            }
         }
      }
   }

   if (rseq == eseq)
      isnxt = 1;
   else
      isnxt = 0;

   debug (DB_LOG, "HANDLE_RPKT rseq", 0, rseq);
   debug (DB_LOG, "  high", 0, high);
   debug (DB_LOG, "  low", 0, low);
   debug (DB_LOG, "  eseq", 0, eseq);
   debug (DB_LOG, "  nused", 0, nused);
   debug (DB_LOG, "  isnxt", 0, isnxt);
   debug (DB_LOG, "  isgap", 0, isgap);
   debug (DB_LOG, "  isold", 0, isold);

#ifdef DEBUG
   show_rslots (k);
#endif

   // write old packets to file in order to keep
   // our receive window aligned with sender's window
   if (isnxt || isgap)
   {
      debug (DB_LOG, "HANDLE_RPKT align our recv window with sender rseq",
             0, rseq);
      for (i = 0; i < wsize; i++)
      {
         iseq = earliest_rseq (k);
         debug (DB_LOG, "HANDLE_RPKT iseq", 0, iseq);
         if (iseq < 0 || iseq >= 64)
            break;

         dseq = rseq - iseq;
         if (dseq < 0)
            dseq += 64;
         debug (DB_LOG, "HANDLE_RPKT dseq", 0, dseq);
         if (dseq < wsize)
            continue;

         rslot = k->r_pw[iseq];
         debug (DB_LOG, "HANDLE_RPKT rslot", 0, rslot);
         if (rslot < 0 || rslot >= wsize)
         {
            debug (DB_LOG, "HANDLE_RPKT error 1, rslot", 0, rslot);
            debug (DB_LOG, "HANDLE_RPKT iseq", 0, iseq);
            return (X_ERROR);
         }

         if (k->ipktinfo[rslot].flg == 0)
         {
            debug (DB_MSG, "HANDLE_RPKT error 2, flg", 0,
                   k->ipktinfo[rslot].flg);
            debug (DB_LOG, "  rslot", 0, rslot);
            return (X_ERROR);
         }

         /* Decode pkt and write file */
         rc = decode (k, r, 1, k->ipktinfo[rslot].buf, rslot);
         debug (DB_LOG, "HANDLE_RPKT decode rc", 0, rc);
         if (rc != X_OK)
         {
            debug (DB_LOG, "decode failed rc", 0, rc);
#ifdef DEBUG
            show_rslots (k);
#endif
//          exit (1);
            epkt ("EKSW decode failed", k);
            return (rc);
         }
         free_rslot (k, rslot);
#ifdef DEBUG
         show_rslots (k);
#endif
      }
   }

   do_add_pkt = 0;

   if (isnxt)
   {
      // 1. PSN = SEQ = HIGH + 1, the usual case
      debug (DB_LOG, "HANDLE_RPKT usual rseq", 0, rseq);

      // acknowledge incoming packet
      ack (k, rseq, (UCHAR *) 0);

      do_add_pkt = 1;
   }
   else if (isgap)
   {
      // 2. PSN != SEQ, a new packet, but not the next sequential one
      debug (DB_LOG, "HANDLE_RPKT isgap rseq", 0, rseq);

      nnak = rseq - high - 1;
      if (nnak < 0)
         nnak += 64;

      debug (DB_LOG, "  nnak", 0, nnak);

      // acknowledge incoming packet
      ack (k, rseq, (UCHAR *) 0);

      // send NAKs for whole gap: HIGH+1 to PSN-1
      for (i = 0; i < nnak; i++)
      {
         iseq = (high + 1 + i) & 63;
         rslot = k->r_pw[iseq];
         debug (DB_LOG, "HANDLE_RPKT isgap nak iseq", 0, iseq);
         debug (DB_LOG, "  rslot", 0, rslot);
         nak (k, iseq, rslot);
      }

      do_add_pkt = 2;
   }
   else if (isold)
   {
      // 3. LOW <= PSN <= HIGH, old, possibly missing pkt arrived
      debug (DB_LOG, "HANDLE_RPKT isold rseq", 0, rseq);

      ack (k, rseq, (UCHAR *) 0);

      // If packet was missing add it to window.
      // There is supposed to be a slot available.
      // Don't store a repeated packet again
      rslot = k->r_pw[rseq];
      if (rslot < 0 || rslot >= wsize)
      {
         do_add_pkt = 3;
      }
   }
   else
   {
      // 4. PSN < LOW || PSN > HIGH -- unexpected, undesired, ignore
      debug (DB_LOG, "HANDLE_RPKT unexpected so ignored rseq", 0, rseq);
   }

   if (do_add_pkt > 0)
   {
      test_rslots (k);

      get_rslot (k, &rslot);
      if (rslot < 0 || rslot >= wsize)
      {
         debug (DB_LOG, "HANDLE_RPKT error 3, rslot", 0, rslot);
         debug (DB_LOG, "  do_add_pkt", 0, do_add_pkt);
         return (X_ERROR);
      }

      test_rslots (k);

      // put pbuf into slot in receive table
      for (i = 0; i < P_BUFLEN; i++)
      {
         k->ipktinfo[rslot].buf[i] = pbuf[i];
         if (pbuf[i] == 0)
            break;
      }
      k->ipktinfo[rslot].len = i;
      k->ipktinfo[rslot].flg = 1;
      k->ipktinfo[rslot].seq = rseq;
      k->ipktinfo[rslot].crc = chk3 (pbuf, k);
      k->r_pw[rseq] = rslot;

      test_rslots (k);
   }

#ifdef DEBUG
   show_rslots (k);
#endif

   return (X_OK);
}

void
handle_bad_rpkt ()
{
}


int
ok2rxd (struct k_data *k)
{
   int ok;
   int sw_full;

   if (nused_sslots (k) == k->wslots)
      sw_full = 1;
   else
      sw_full = 0;

   if ((k->what == W_SEND || k->what == W_GET) &&
       k->state == S_DATA && sw_full == 0)
      ok = 0;
   else
      ok = 1;

   debug (DB_LOG, "ok2rxd", 0, ok);

   k->do_rxd = ok;

   return (ok);
}

STATIC void
free_sslot_easca (struct k_data *k)
// Remove earliest & subsequent contiguous ACK'd packets.
// Packet numbers thus remain in order in the sliding window.
// This way we don't send packets which won't fit in their window.
{
   int nfreed = 0;
   int i;

   for (i = 0; i < k->wslots; i++)
   {
      short seq_earl, slot_earl;
      seq_earl = earliest_sseq (k);
      if (seq_earl < 0 || seq_earl > 63)
         break;
      slot_earl = k->s_pw[seq_earl];
      if (slot_earl < 0 || slot_earl >= k->wslots)
         break;
      if (k->opktinfo[slot_earl].flg == 0)
         break;
      free_sslot (k, slot_earl);
      nfreed++;
   }
   debug (DB_LOG, "FREE_SSLOT_EASCA nfreed", 0, nfreed);
}

#ifdef DEBUG
STATIC void
chk_sseq_nos (struct k_data *k)
// check that sequence numbers are still in order
{
   int i;
   int dif, dif0;
   int ok;
   int nerr;

   nerr = 0;
   ok = 0;
   for (i = 0; i < k->wslots; i++)
   {
      short ss;
      if (k->opktinfo[i].seq < 0)
         continue;
      ss = k->opktinfo[i].seq - k->r_seq;
      if (ss < -32)
         ss += 64;
      if (ss > 31)
         ss -= 64;
      dif = ss - i;
      if (ok == 0)
      {
         ok = 1;
         dif0 = dif;
      }
      else if (dif != dif0 && (dif + k->wslots) != dif0)
         nerr++;
   }

   if (nerr)
   {
      debug (DB_LOG, "CHK_SEQ nerr", 0, nerr);
#ifdef DEBUG
      show_sslots (k);
#endif
   }
}
#endif

STATIC int
flush_to_file (struct k_data *k, struct k_response *r)
{
   short wsize = k->wslots;     // negotiated window size
   short rslot;
   short iseq;
   int rc;

   debug (DB_MSG, "FLUSH_TO_FILE begin", 0, 0);

   // flush receive window to file
   while ((iseq = earliest_rseq (k)) >= 0)
   {

      debug (DB_LOG, "FLUSH_TO_FILE iseq", 0, iseq);

      rslot = k->r_pw[iseq];

      debug (DB_LOG, "  rslot", 0, rslot);

      if (rslot < 0 || rslot >= wsize)
      {
         debug (DB_LOG, "FLUSH_TO_FILE error rslot", 0, rslot);
         return (X_ERROR);
      }

      if (k->ipktinfo[rslot].flg == 0)
      {
         debug (DB_MSG, "FLUSH_TO_FILE error flg", 0, k->ipktinfo[rslot].flg);
         return (X_ERROR);
      }

      /* Decode pkt and write file */
      rc = decode (k, r, 1, k->ipktinfo[rslot].buf, rslot);
      debug (DB_LOG, "FLUSH_TO_FILE decode rc", 0, rc);
      if (rc != X_OK)
      {
         debug (DB_LOG, "decode failed rc", 0, rc);
#ifdef DEBUG
         show_rslots (k);
#endif
//       exit (1);
         epkt ("EKSW flush to file failed", k);
         return (rc);
      }
      free_rslot (k, rslot);
#ifdef DEBUG
      show_rslots (k);
#endif
   }

   debug (DB_LOG, "FLUSH_TO_FILE obufpos", 0, k->obufpos);

   if (k->obufpos > 0)
   {                            /* Flush output buffer to file */
      rc = (*(k->writef)) (k, k->obuf, k->obufpos);
      debug (DB_LOG, "FLUSH_TO_FILE writef rc", 0, rc);
      r->sofar += k->obufpos;
      r->sofar_rumor += k->obufpos;
      k->obufpos = 0;
   }

   return (rc);
}

/*
 * Utility routines 
 */

UCHAR *
get_rslot (struct k_data * k, short *n)
{                               /* Find a free packet buffer */
   register int slot;
   /*
    * Note: We don't clear the retry count here. It is cleared only after 
    * the NEXT packet arrives, which indicates that the other Kermit got
    * our ACK for THIS packet. 
    */
   for (slot = 0; slot < k->wslots; slot++)
   {                            /* Search */
      if (k->ipktinfo[slot].len < 1)
      {
         *n = slot;             /* Slot number */
         k->ipktinfo[slot].len = -1;    /* Mark it as allocated but not used */
         k->ipktinfo[slot].seq = -1;
         k->ipktinfo[slot].typ = SP;
         k->ipktinfo[slot].crc = 0xFFFF;
         /*
          * k->ipktinfo[slot].rtr = 0; 
          *//*
          * (see comment above) 
          */
         k->ipktinfo[slot].dat = (UCHAR *) 0;
         debug (DB_LOG, "GET_RSLOT slot", 0, slot);
         return (k->ipktinfo[slot].buf);
      }
   }
   *n = -1;
   debug (DB_LOG, "GET_RSLOT slot", 0, -1);
   return ((UCHAR *) 0);
}

void                            /* Initialize a window slot */
free_rslot (struct k_data *k, short slot)
{
   short seq;

   debug (DB_LOG, "FREE_RSLOT slot", 0, slot);

   if (slot < 0 || slot >= P_WSLOTS)
   {
      debug (DB_LOG, "  confused: slot out of bounds", 0, slot);
      epkt ("EKSW free_rslot confused", k);
//    exit (1);
      return;
   }

   seq = k->ipktinfo[slot].seq;
   debug (DB_LOG, "  seq", 0, seq);

   if (seq >= 0 && seq < 64)
      k->r_pw[seq] = -1;

   k->ipktinfo[slot].len = 0;   /* Packet length */
   k->ipktinfo[slot].seq = -1;  /* Sequence number */
   k->ipktinfo[slot].typ = (char) 0;    /* Type */
   k->ipktinfo[slot].rtr = 0;   /* Retry count */
   k->ipktinfo[slot].flg = 0;   /* Flags */
   k->ipktinfo[slot].crc = 0xFFFF;
}

UCHAR *
get_sslot (struct k_data *k, short *n)
{                               /* Find a free packet buffer */
   register int slot;
   for (slot = 0; slot < k->wslots; slot++)
   {                            /* Search */
      if (k->opktinfo[slot].len < 1)
      {
         *n = slot;             /* Slot number */
         k->opktinfo[slot].len = -1;    /* Mark it as allocated but not used */
         k->opktinfo[slot].seq = -1;
         k->opktinfo[slot].typ = SP;
         k->opktinfo[slot].rtr = 0;
         k->opktinfo[slot].flg = 0;     // ACK'd bit
         k->opktinfo[slot].dat = (UCHAR *) 0;
         debug (DB_LOG, "GET_SSLOT slot", 0, slot);
         return (k->opktinfo[slot].buf);
      }
   }
   *n = -1;
   debug (DB_LOG, "GET_SSLOT slot", 0, -1);
   return ((UCHAR *) 0);
}

STATIC int
nused_sslots (struct k_data *k)
{
   int i;
   int n = 0;

   for (i = 0; i < k->wslots; i++)
      if (k->opktinfo[i].len > 0)
         n++;
   return (n);
}

STATIC int
nused_rslots (struct k_data *k)
{
   int i;
   int n = 0;

   for (i = 0; i < k->wslots; i++)
      if (k->ipktinfo[i].len > 0)
         n++;
   return (n);
}

#ifdef DEBUG
STATIC void
show_sslots (struct k_data *k)
{
   int slot, j, n;
   char tmp[80], *p;

   debug (DB_MSG, "SHOW_SSLOTS", 0, 0);
   for (slot = 0; slot < k->wslots; slot++)
   {
      n = snprintf (tmp, sizeof (tmp) - 1, "  slot=%02d seq=%02d flg=%d "
                    "len=%4d crc=%5d pwi=",
                    slot, k->opktinfo[slot].seq, k->opktinfo[slot].flg,
                    k->opktinfo[slot].len, k->opktinfo[slot].crc);

      p = tmp + n;
      for (j = 0; j < 64; j++)
         if (k->s_pw[j] == slot)
         {
            n = snprintf (p, sizeof (tmp) - 1 - n, " %02d", j);
            p += n;
         }
      debug (DB_MSG, tmp, 0, 0);
   }
}
#endif /* DEBUG */
#ifdef DEBUG
STATIC void
show_rslots (struct k_data *k)
{
   int slot, j, n, m;
   char tmp[256], *p;


   debug (DB_MSG, "SHOW_RSLOTS", 0, 0);
   for (slot = 0; slot < k->wslots; slot++)
   {
      int ok;
      if (k->ipktinfo[slot].seq >= 0 &&
          chk3 (k->ipktinfo[slot].buf, k) != k->ipktinfo[slot].crc)
         ok = 0;
      else
         ok = 1;

      p = tmp;
      m = sizeof (tmp) - 1;
      n = snprintf (p, m, "  slot=%02d seq=%02d flg=%d "
                    "len=%4d crc=%5d crcok=%d pwi=",
                    slot, k->ipktinfo[slot].seq, k->ipktinfo[slot].flg,
                    k->ipktinfo[slot].len, k->ipktinfo[slot].crc, ok);
      if (n < 0)
      {
         debug (DB_LOG, "SHOW_RSLOTS 1 n", 0, n);
         debug (DB_LOG, "SHOW_RSLOTS 1 m", 0, m);
         debug (DB_LOG, "SHOW_RSLOTS 1 slot", 0, slot);
         debug (DB_LOG, "SHOW_RSLOTS 1 seq", 0, k->ipktinfo[slot].seq);
         debug (DB_LOG, "SHOW_RSLOTS 1 flg", 0, k->ipktinfo[slot].flg);
         debug (DB_LOG, "SHOW_RSLOTS 1 len", 0, k->ipktinfo[slot].len);
         debug (DB_LOG, "SHOW_RSLOTS 1 crc", 0, k->ipktinfo[slot].crc);
         debug (DB_LOG, "SHOW_RSLOTS ok", 0, ok);
         debug (DB_LOG, "SHOW_RSLOTS 1 p-tmp", 0, p - tmp);
         debug (DB_LOG, "SHOW_RSLOTS 1 tmp", tmp, 0);
//       exit (1);
      }
      p += n;
      m -= n;
      for (j = 0; j < 64; j++)
      {
         if (k->r_pw[j] == slot)
         {
            n = snprintf (p, m, " %02d", j);
            if (n < 0)
            {
               debug (DB_LOG, "SHOW_RSLOTS 2 j", 0, j);
               debug (DB_LOG, "SHOW_RSLOTS 2 n", 0, n);
               debug (DB_LOG, "SHOW_RSLOTS 2 m", 0, m);
               debug (DB_LOG, "SHOW_RSLOTS 2 slot", 0, slot);
               debug (DB_LOG, "SHOW_RSLOTS 2 seq", 0, k->ipktinfo[slot].seq);
               debug (DB_LOG, "SHOW_RSLOTS 2 flg", 0, k->ipktinfo[slot].flg);
               debug (DB_LOG, "SHOW_RSLOTS 2 len", 0, k->ipktinfo[slot].len);
               debug (DB_LOG, "SHOW_RSLOTS 2 crc", 0, k->ipktinfo[slot].crc);
               debug (DB_LOG, "SHOW_RSLOTS 2 p-tmp", 0, p - tmp);
               debug (DB_LOG, "SHOW_RSLOTS 2 tmp", tmp, 0);
//             exit (1);
            }
            p += n;
            m -= n;
         }
      }
      debug (DB_MSG, tmp, 0, 0);
   }
}
#endif

STATIC int
test_rslots (struct k_data *k)
{
   int slot, nbad = 0;

   for (slot = 0; slot < k->wslots; slot++)
   {
      if (k->ipktinfo[slot].seq >= 0 &&
          chk3 (k->ipktinfo[slot].buf, k) != k->ipktinfo[slot].crc)
      {
         nbad++;
         debug (DB_HEX, "THEX", k->ipktinfo[slot].buf, k->ipktinfo[slot].len);
      }
   }
   if (nbad > 0)
   {
      debug (DB_LOG, "TEST_RSLOTS nbad", 0, nbad);
#ifdef DEBUG
      show_rslots (k);
# endif
      epkt ("EKSW test rslots failed", k);
//    exit (1);
      return X_ERROR;
   }
   return X_OK;
}

void                            /* Initialize a window slot */
free_sslot (struct k_data *k, short slot)
{
   short seq;

   debug (DB_LOG, "FREE_SSLOT slot", 0, slot);
   if (slot < 0 || slot >= P_WSLOTS)
      return;

   seq = k->opktinfo[slot].seq;
   debug (DB_LOG, "  seq", 0, seq);

   if (seq >= 0 && seq < 64)
      k->s_pw[seq] = -1;

   k->opktinfo[slot].len = 0;   /* Packet length */
   k->opktinfo[slot].seq = -1;  /* Sequence number */
   k->opktinfo[slot].typ = (char) 0;    /* Type */
   k->opktinfo[slot].rtr = 0;   /* Retry count */
   k->opktinfo[slot].flg = 0;   /* ACK'd bit */
}

STATIC short
earliest_sseq (struct k_data *k)
{
   short slot;
   short seq;
   short age;
   short oldest_seq = -1;
   short oldest_age = -99;

   for (slot = 0; slot < k->wslots; slot++)
   {
      seq = k->opktinfo[slot].seq;
      if (seq >= 0 && seq < 64)
      {
         age = k->s_seq - seq;
         if (age < 0)
            age += 64;
         if (age > 63)
            age -= 64;

         if (age > oldest_age)
         {
            oldest_age = age;
            oldest_seq = seq;
         }
      }
   }

   debug (DB_LOG, "EARLIEST_SSEQ", 0, oldest_seq);
   return (oldest_seq);
}

/*
 * C H K 1 -- Compute a type-1 Kermit 6-bit checksum.  
 */

STATIC int
chk1 (UCHAR * pkt, struct k_data *k)
{
   register unsigned int chk;
   chk = chk2 (pkt, k);
   chk = (((chk & 0300) >> 6) + chk) & 077;
   return ((int) chk);
}

/*
 * C H K 2 -- Numeric sum of all the bytes in the packet, 12 bits.  
 */

STATIC USHORT
chk2 (UCHAR * pkt, struct k_data *k)
{
   register USHORT chk;
   for (chk = 0; *pkt != '\0'; pkt++)
      chk += *pkt;
   return (chk);
}

/*
 * C H K 3 -- Compute a type-3 Kermit block check.  
 */
/*
 * Calculate the 16-bit CRC-CCITT of a null-terminated string using a
 * lookup table.  Assumes the argument string contains no embedded nulls. 
 */
STATIC USHORT
chk3 (UCHAR * pkt, struct k_data * k)
{
   register USHORT c, crc;
   for (crc = 0; *pkt != '\0'; pkt++)
   {
      c = crc ^ (*pkt);
      crc = (crc >> 8) ^ ((k->crcta[(c & 0xF0) >> 4]) ^ (k->crctb[c & 0x0F]));
   }
   return (crc);
}

/*
 * S P K T -- Send a packet.  
 */
/*
 * Call with packet type, sequence number, data length, data, Kermit
 * struct. Returns: X_OK on success X_ERROR on i/o error 
 */
STATIC int
spkt (char typ, short seq, int len, UCHAR * data, struct k_data *k)
{
   int retc;

   unsigned int crc;            /* For building CRC */
   int i, j, lenpos;            /* Workers */
   UCHAR *s, *buf;
   int buflen;
   short slot;
   UCHAR tmp[100];              // for packets we don't want to resend

   debug (DB_CHR, "SPKT typ", 0, typ);
   debug (DB_LOG, "  seq", 0, seq);
   debug (DB_LOG, "  len", 0, len);

   if (seq < 0 || seq > 63)
      return (X_ERROR);

   if (len < 0)
   {                            /* Calculate data length ourselves? */
      len = 0;
      s = data;
      while (*s++)
         len++;
      debug (DB_LOG, "SPKT calc len", 0, len);
   }
   if (typ == 'Y' || typ == 'N' || typ == 'E')
   {
      buf = tmp;
      buflen = sizeof (tmp);
   }
   else
   {
      debug (DB_LOG, "SPKT k->s_seq", 0, k->s_seq);
      debug (DB_LOG, "SPKT k->s_pw[seq]", 0, k->s_pw[seq]);

      get_sslot (k, &slot);     // get a new send slot
      if (slot < 0 || slot >= k->wslots)
         return (X_ERROR);
      k->s_pw[k->s_seq] = slot;

      // save these for use in resend()
      k->opktinfo[slot].typ = typ;
      k->opktinfo[slot].seq = seq;
      k->opktinfo[slot].len = len;

      buf = k->opktinfo[slot].buf;
      buflen = P_BUFLEN;
   }

   i = 0;                       /* Packet buffer position */
   buf[i++] = k->s_soh;         /* SOH */
   lenpos = i++;                /* Remember this place */
   buf[i++] = tochar (seq);     /* Sequence number */
   buf[i++] = typ;              /* Packet type */
   if (k->bcta3)
      k->bct = 3;
   j = len + k->bct;
   if ((len + k->bct + 2) > 94)
   {                            /* If long packet */
      buf[lenpos] = tochar (0); /* Put blank in LEN field */
      buf[i++] = tochar (j / 95);       /* Make extended header: Big part */
      buf[i++] = tochar (j % 95);       /* and small part of length. */
      buf[i] = NUL;             /* Terminate for header checksum */
      buf[i++] = tochar (chk1 (&buf[lenpos], k));       /* Insert header checksum */
   }
   else
   {                            /* Short packet */
      buf[lenpos] = tochar (j + 2);     /* Single-byte length in LEN field */
   }
   if (data)                    /* Copy data, if any */
      for (; len--; i++)
      {
         if (i < 0 || i >= buflen)
         {
            debug (DB_LOG, "confused copy data i", 0, i);
            epkt ("EKSW spkt confused", k);
//          exit (1);
            return (X_ERROR);
         }
         buf[i] = *data++;
      }
   buf[i] = '\0';

   switch (k->bct)
   {                            /* Add block check */
   case 1:                     /* 1 = 6-bit chksum */
      buf[i++] = tochar (chk1 (&buf[lenpos], k));
      break;
   case 2:                     /* 2 = 12-bit chksum */
      j = chk2 (&buf[lenpos], k);
#if 0
      buf[i++] = (unsigned) tochar ((j >> 6) & 077);
      buf[i++] = (unsigned) tochar (j & 077);
#else
      // HiTech's XAC compiler silently ruins the above code.
      // An intermediate variable provides a work-around.
      // 2004-06-29 -- JHD
      {
         USHORT jj;
         jj = (j >> 6) & 077;
         buf[i++] = tochar (jj);
         jj = j & 077;
         buf[i++] = tochar (jj);
      }
#endif

      break;
   case 3:                     /* 3 = 16-bit CRC */
      crc = chk3 (&buf[lenpos], k);
#if 0
      buf[i++] = (unsigned) tochar (((crc & 0170000)) >> 12);
      buf[i++] = (unsigned) tochar ((crc >> 6) & 077);
      buf[i++] = (unsigned) tochar (crc & 077);
#else
      // HiTech's XAC compiler silently ruins the above code.
      // An intermediate variable provides a work-around.
      // 2004-06-29 -- JHD
      {
         USHORT jj;
         jj = (crc >> 12) & 0x0f;
         buf[i++] = tochar (jj);
         jj = (crc >> 6) & 0x3f;
         buf[i++] = tochar (jj);
         jj = crc & 0x3f;
         buf[i++] = tochar (jj);
      }
#endif
      break;
   }

   buf[i++] = k->s_eom;         /* Packet terminator */
   buf[i] = '\0';               /* String terminator */
   // packet ready to go

   if (i < 0 || i >= buflen)
   {
      debug (DB_LOG, "SPKT i", 0, i);
      debug (DB_LOG, "SPKT buflen", 0, buflen);
      return (X_ERROR);
   }

   k->s_seq = seq;              /* Remember sequence number */
   k->opktlen = i;              /* Remember length for retransmit */

   if (typ != 'Y' && typ != 'N' && typ != 'E')
   {
      k->opktinfo[slot].len = i;        /* Remember length for retransmit */
   }

   debug (DB_LOG, "SPKT opktlen", 0, k->opktlen);

#ifdef DEBUG
   /*
    * CORRUPT THE PACKET SENT BUT NOT THE ONE WE SAVE 
    */
   if (xerror ())
   {
      UCHAR p[P_BUFLEN];
      int i;
      for (i = 0; i < buflen - 8; i++)
         if (!(p[i] = buf[i]))
            break;
      if (xerror ())
      {
         p[i - 2] = 'X';
         debug (DB_PKT, "XPKT", (char *) &p[1], 0);
      }
      else if (xerror ())
      {
         p[k->opktlen - 1] = 'N';
         debug (DB_PKT, "NPKT", (char *) &p[1], 0);
      }
      else
      {
         p[0] = 'A';
         debug (DB_PKT, "APKT", (char *) &p[1], 0);
      }
      return ((*(k->txd)) (k, p, k->opktlen));  /* Send it. */
   }
#endif /* DEBUG */

// debug (DB_PKT, "SPKT", &buf[1], k->opktlen);
   retc = ((*(k->txd)) (k, buf, k->opktlen));   /* Send buf == whole packet */
   debug (DB_LOG, "SPKT txd retc", 0, retc);

   return (retc);
}

/*
 * N A K -- Send a NAK (negative acknowledgement) 
 */

STATIC int
nak (struct k_data *k, short seq, short slot)
{
   int rc;
   k->nsnak++;
   debug (DB_LOG, "NAK seq", 0, seq);
   debug (DB_LOG, "  slot", 0, slot);
// k->anseq = seq;
   rc = spkt ('N', seq, 0, (UCHAR *) 0, k);
   if (slot >= 0 && slot < 64 && k->ipktinfo[slot].rtr++ > k->retry)
   {
      debug (DB_MSG, "X_ERROR returned from nak(): too many retries", 0, 0);
      debug (DB_MSG, "  seq", 0, seq);
      debug (DB_MSG, "  slot", 0, slot);
      rc = X_ERROR;
   }
   return (rc);
}

/*
 * A C K -- Send an ACK (positive acknowledgement) 
 */

STATIC int
ack (struct k_data *k, short seq, UCHAR * text)
{
   int len, rc;
   debug (DB_LOG, "ACK seq", 0, seq);
// k->anseq = (seq+1)&63;
   len = 0;
   if (text)
   {                            /* Get length of data */
      UCHAR *p;
      p = text;
      for (; *p++; len++);
   }
   debug (DB_LOG, "ACK len", 0, len);
   rc = spkt ('Y', seq, len, text, k);  /* Send the packet */
   debug (DB_LOG, "ACK spkt rc", 0, rc);
   if (rc == X_OK && seq == k->r_seq)   /* If OK */
      k->r_seq = (k->r_seq + 1) & 63;   /* bump the packet number */
   debug (DB_LOG, "ACK new k->r_seq", 0, k->r_seq);
   return (rc);
}

/*
 * S P A R -- Set parameters requested by other Kermit 
 */

STATIC void
spar (struct k_data *k, UCHAR * s, int datalen)
{
   int x;
   int y = 0;

   debug (DB_MSG, "SPAR", 0, 0);

   s--;                         /* Line up with field numbers. */

   if (datalen >= 1)            /* Max packet length to send */
      k->s_maxlen = xunchar (s[1]);

   if (datalen >= 2)            /* Timeout on inbound packets */
      k->r_timo = xunchar (s[2]);

   /*
    * No padding 
    */

   if (datalen >= 5)            /* Outbound Packet Terminator */
      k->s_eom = xunchar (s[5]);

   if (datalen >= 6)            /* Incoming control prefix */
      k->r_ctlq = s[6];

   if (datalen >= 7)
   {                            /* 8th bit prefix */
      k->ebq = s[7];
      if ((s[7] > 32 && s[7] < 63) || (s[7] > 95 && s[7] < 127))
      {
         if (!k->parity)        /* They want it */
            k->parity = 1;      /* Set parity to something nonzero */
         k->ebqflg = 1;
      }
      else if (s[7] == 'Y' && k->parity)
      {                         // they will do 8th bit prefixing if requested
         k->ebqflg = 1;
         k->ebq = '&';
      }
      else if (s[7] == 'N')
      {                         // they refuse to do 8th bit prefixing
         /*
          * WHAT? 
          */
      }
   }
   if (datalen >= 8)
   {                            /* Block check */
      k->bct = s[8] - '0';
      if ((k->bct < 1) || (k->bct > 3))
         k->bct = 1;
      if (k->bcta3)
         k->bct = 3;
   }
   if (datalen >= 9)
   {                            /* Repeat counts */
      if ((s[9] > 32 && s[9] < 63) || (s[9] > 95 && s[9] < 127))
      {
         k->rptq = s[9];
         k->rptflg = 1;
      }
   }
   if (datalen >= 10)
   {                            /* Capability bits */
      x = xunchar (s[10]);

      if (!(x & CAP_LP))
         k->capas &= ~CAP_LP;

      if (!(x & CAP_SW))
         k->capas &= ~CAP_SW;

      if (!(x & CAP_AT))
         k->capas &= ~CAP_AT;

#ifdef F_RS                     /* Recovery */
      if (!(x & CAP_RS))
#endif /* F_RS */
         k->capas &= ~CAP_RS;

#ifdef F_LS                     /* Locking shifts */
      if (!(x & CAP_LS))
#endif /* F_LS */
         k->capas &= ~CAP_LS;

      /* In case other Kermit sends addt'l capas fields ...  */

      for (y = 10; (xunchar (s[y]) & 1) && (datalen >= y); y++);
   }
   if (k->capas & CAP_LP)
   {
      if (datalen > y + 1)
      {
         x = xunchar (s[y + 2]) * 95 + xunchar (s[y + 3]);
         k->s_maxlen = (x > P_PKTLEN) ? P_PKTLEN : x;
         if (k->s_maxlen < 10)
            k->s_maxlen = 60;
      }
   }

   debug (DB_LOG, "  s_maxlen", 0, k->s_maxlen);

   if (k->capas & CAP_SW)
   {
      if (datalen > y)
      {
         x = xunchar (s[y + 1]);
         k->wslots = (x > k->wslots_max) ? k->wslots_max : x;
         if (k->wslots < 1)     /* Watch out for bad negotiation */
            k->wslots = 1;
         if (k->wslots > 1)
            if (k->wslots > k->retry)   /* Retry limit must be greater */
               k->retry = k->wslots + 1;        /* than window size. */
      }
   }
   else
   {
      k->wslots = 1;
   }

   debug (DB_LOG, "  k->capas & CAP_LP", 0, k->capas & CAP_LP);
   debug (DB_LOG, "  k->capas & CAP_SW", 0, k->capas & CAP_SW);
   debug (DB_LOG, "  k->capas & CAP_AT", 0, k->capas & CAP_AT);
   debug (DB_LOG, "  k->capas & CAP_RS", 0, k->capas & CAP_RS);
   debug (DB_LOG, "  k->capas & CAP_LS", 0, k->capas & CAP_LS);
   debug (DB_CHR, "  k->ebq           ", 0, k->ebq);
   debug (DB_LOG, "  k->ebqflg        ", 0, k->ebqflg);
   debug (DB_LOG, "  k->parity        ", 0, k->parity);
   debug (DB_LOG, "  k->s_eom         ", 0, k->s_eom);
   debug (DB_LOG, "  k->r_timo        ", 0, k->r_timo);
   debug (DB_LOG, "  k->s_timo        ", 0, k->s_timo);
   debug (DB_CHR, "  k->r_ctlq        ", 0, k->r_ctlq);
   debug (DB_CHR, "  k->s_ctlq        ", 0, k->s_ctlq);
   debug (DB_CHR, "  k->rptq          ", 0, k->rptq);
   debug (DB_LOG, "  k->rptflg        ", 0, k->rptflg);
   debug (DB_LOG, "  k->bct           ", 0, k->bct);
   debug (DB_LOG, "  k->bcta3         ", 0, k->bcta3);
   debug (DB_LOG, "  k->r_maxlen      ", 0, k->r_maxlen);
   debug (DB_LOG, "  k->s_maxlen      ", 0, k->s_maxlen);
   debug (DB_LOG, "  k->wslots        ", 0, k->wslots);
   debug (DB_LOG, "  k->binary        ", 0, k->binary);
   debug (DB_LOG, "  k->retry         ", 0, k->retry);
}

/*
 * R P A R -- Send my parameters to other Kermit 
 */

STATIC int
rpar (struct k_data *k, char type)
{
   UCHAR *d;
   int rc, len;
   short bctsv;
   UCHAR *buf;
   short s_slot;

   debug (DB_LOG, "RPAR capas", 0, k->capas);
   debug (DB_LOG, "  wslots", 0, k->wslots);

   d = k->ack_s;                /* Where to put it */
   d[0] = tochar (94);          /* Maximum short-packet length */
   d[1] = tochar (k->s_timo);   /* When I want to be timed out */
   d[2] = tochar (0);           /* How much padding I need */
   d[3] = ctl (0);              /* Padding character I want */
   d[4] = tochar (k->r_eom);    /* End-of message character I want */
   d[5] = k->s_ctlq;            /* Control prefix I send */
   if ((k->ebq == 'Y') && (k->parity))  /* 8th-bit prefix */
      d[6] = k->ebq = '&';      /* I need to request it */
   else                         /* else just agree with other Kermit */
      d[6] = k->ebq;
   if (k->bcta3)
      d[7] = '3';
   else
      d[7] = k->bct + '0';      /* Block check type */
   d[8] = k->rptq;              /* Repeat prefix */
   d[9] = tochar (k->capas);    /* Capability bits */
   d[10] = tochar (k->wslots);  /* Window size */

   d[11] = tochar (k->r_maxlen / 95);   /* Long packet size, big part */
   d[12] = tochar (k->r_maxlen % 95);   /* Long packet size, little part */
   d[13] = '\0';                /* Terminate the init string */
   len = 13;

   if (k->bcta3)
   {
      bctsv = 3;
      k->bct = 3;
   }
   else
   {
      bctsv = k->bct;
      k->bct = 1;               /* Always use block check type 1 */
   }
   switch (type)
   {
   case 'Y':                   /* This is an ACK for packet 0 */
      rc = ack (k, 0, d);
      break;
   case 'S':                   /* It's an S packet */
      buf = get_sslot (k, &s_slot);     // get a new send slot
      k->s_pw[k->s_seq] = s_slot;
      debug (DB_LOG, "sending S pkt s_seq", 0, k->s_seq);
      debug (DB_LOG, "  s_slot", 0, s_slot);
      rc = spkt ('S', 0, len, d, k);
      break;
   default:
      rc = -1;
   }
   k->bct = bctsv;
   return (rc);                 /* Pass along return code. */
}

/*
 * D E C O D E -- Decode data field of Kermit packet - binary mode only 
 */
/*
Call with:
	k = kermit data structure
	r = kermit response structure
	f = function code:
		0: decode filename
		1: decode file data
	inbuf = pointer to packet data to be decoded
	Returns: X_OK on success X_ERROR if output function fails 
 */
STATIC int
decode (struct k_data *k, struct k_response *r, short f, UCHAR * inbuf,
        int rslot)
{

   register unsigned int a, a7; /* Current character */
   unsigned int b8;             /* 8th bit */
   int rpt;                     /* Repeat count */
   int rc;                      /* Return code */
   UCHAR *ucp = 0;
   int i;
   int nobuf;
   USHORT crc;

   rc = X_OK;
   rpt = 0;                     /* Initialize repeat count. */
   if (f == 0)                  /* Output function... */
      ucp = r->filename;

   debug (DB_LOG, "DECODE rslot", 0, rslot);
   if (rslot >= 0)
   {
      k->anseq = k->ipktinfo[rslot].seq;
      debug (DB_LOG, "DECODE seq", 0, k->ipktinfo[rslot].seq);
      debug (DB_LOG, "DECODE len", 0, k->ipktinfo[rslot].len);
      debug (DB_LOG, "DECODE crc", 0, k->ipktinfo[rslot].crc);
      debug (DB_HEX, "IHEX", inbuf, k->ipktinfo[rslot].len);

      for (i = 0; i < k->ipktinfo[rslot].len; i++)
         if (inbuf[i] == 0)
            break;

      if (i != k->ipktinfo[rslot].len)
      {
         debug (DB_LOG, "DECODE error i", 0, i);
#ifdef DEBUG
         show_rslots (k);
#endif
         epkt ("EKSW decode len bad", k);
//       exit (1);
         return (X_ERROR);
      }

      crc = chk3 (inbuf, k);
      if (crc != k->ipktinfo[rslot].crc)
      {
         debug (DB_LOG, "DECODE error crc", 0, crc);
#ifdef DEBUG
         show_rslots (k);
#endif
         epkt ("EKSW decode crc bad", k);
//       exit (1);
         return (X_ERROR);
      }
   }

   nobuf = 0;
   while ((a = *inbuf++ & 0xFF) != '\0')
   {                            /* Character loop */
      if (k->rptflg && a == k->rptq)
      {                         /* Got a repeat prefix? */
         rpt = xunchar (*inbuf++ & 0xFF);       /* Yes, get the repeat count, */
         a = *inbuf++ & 0xFF;   /* and get the prefixed character. */
      }
      b8 = 0;                   /* 8th-bit value */
      if (k->parity && (a == k->ebq))
      {                         /* Have 8th-bit prefix? */
         b8 = 0200;             /* Yes, flag the 8th bit */
         a = *inbuf++ & 0x7F;   /* and get the prefixed character. */
      }
      if (a == k->r_ctlq)
      {                         /* If control prefix, */
         a = *inbuf++ & 0xFF;   /* get its operand */
         a7 = a & 0x7F;         /* and its low 7 bits. */
         if ((a7 >= 0100 && a7 <= 0137) || a7 == '?')   /* Controllify */
            a = ctl (a);        /* if in control range. */
      }
      a |= b8;                  /* OR in the 8th bit */

//    debug(DB_LOG,"DECODE rpt",0,rpt);
      if (rpt == 0)
         rpt = 1;               /* If no repeats, then one */

      for (; rpt > 0; rpt--)
      {                         /* Output the char 'rpt' times */
         if (f == 0)
         {
            *ucp++ = (UCHAR) a; /* to memory */
         }
         else
         {                      /* or to file */
            k->obuf[k->obufpos++] = (UCHAR) a;  /* Deposit the byte */
            nobuf++;
            if (k->obufpos == k->obuflen)
            {                   /* Buffer full? */
               rc = (*(k->writef)) (k, k->obuf, k->obuflen);    /* Dump it. */
               debug (DB_LOG, "DECODE writef rc", 0, rc);
               r->sofar += k->obuflen;
               r->sofar_rumor += k->obuflen;
               if (rc != X_OK)
                  break;
               k->obufpos = 0;
            }
         }
      }
   }

   debug (DB_LOG, "DECODE nobuf", 0, nobuf);
   debug (DB_LOG, "DECODE obufpos", 0, k->obufpos);

   if (f == 0)                  /* If writing to memory */
      *ucp = '\0';              /* terminate the string */

   debug (DB_LOG, "DECODE rc", 0, rc);
   return (rc);
}

STATIC ULONG                    /* Convert decimal string to number */
stringnum (UCHAR * s, struct k_data * k)
{
   long n;
   n = 0L;
   while (*s == SP)
      s++;
   while (*s >= '0' && *s <= '9')
      n = n * 10 + (*s++ - '0');
   return (n);
}

STATIC UCHAR *                  /* Convert number to string */
numstring (ULONG n, UCHAR * buf, int buflen, struct k_data * k)
{
   int i, x;
   buf[buflen - 1] = '\0';
   for (i = buflen - 2; i > 0; i--)
   {
      x = n % 10L;
      buf[i] = x + '0';
      n /= 10L;
      if (!n)
         break;
   }
   if (n)
   {
      return ((UCHAR *) 0);
   }
   if (i > 0)
   {
      UCHAR *p, *s;
      s = &buf[i];
      p = buf;
      while ((*p++ = *s++));
      *(p - 1) = '\0';
   }
   return ((UCHAR *) buf);
}

/*
 * G A T T R -- Read incoming attributes.
 * 
 * Returns: -1 if no transfer mode (text/binary) was announced. 0 if text
 * was announced. 1 if binary was announced. 
 */

#define SIZEBUFL 32             /* For number conversions */

STATIC int
gattr (struct k_data *k, UCHAR * s, struct k_response *r)
{
   long fsize = 0, fsizek = 0;  /* File size */
   UCHAR c;                     /* Workers */
   int aln, i, rc;

   UCHAR sizebuf[SIZEBUFL];

   rc = -1;
   while ((c = *s++))
   {                            /* Get attribute tag */
      aln = xunchar (*s++);     /* Length of attribute string */
      switch (c)
      {
      case '!':                /* File length in K */
      case '"':                /* File type */
         for (i = 0; (i < aln) && (i < SIZEBUFL); i++)  /* Copy it */
            sizebuf[i] = *s++;
         sizebuf[i] = '\0';     /* Terminate with null */
         if (i < aln)
            s += (aln - i);     /* If field was too long for buffer */
         if (c == '!')
         {                      /* Length */
            fsizek = stringnum (sizebuf, k);    /* Convert to number */
         }
         else
         {                      /* Type */
            if (sizebuf[0] == 'A')      /* Text */
               rc = 0;
            else if (sizebuf[0] == 'B') /* Binary */
               rc = 1;
            debug (DB_LOG, "GATTR rc", 0, rc);
            debug (DB_LOG, "GATTR sizebuf", sizebuf, 0);
         }
         break;

      case '#':                /* File creation date */
         for (i = 0; (i < aln) && (i < DATE_MAX); i++)
            r->filedate[i] = *s++;      /* save it to a string */
         if (i < aln)
            s += (aln - i);
         r->filedate[i] = '\0';
         break;

      case '1':                /* File length in bytes */
         for (i = 0; (i < aln) && (i < SIZEBUFL); i++)  /* Copy it */
            sizebuf[i] = *s++;
         sizebuf[i] = '\0';     /* Terminate with null */
         if (i < aln)
            s += (aln - i);
         fsize = stringnum (sizebuf, k);        /* Convert to number */
         break;

      default:                 /* Unknown attribute */
         s += aln;              /* Just skip past it */
         break;
      }
   }
   if (fsize > -1L)
   {                            /* Remember the file size */
      r->filesize = fsize;
   }
   else if (fsizek > -1L)
   {
      r->filesize = fsizek * 1024L;
   }
   debug (DB_LOG, "gattr r->filesize", 0, (r->filesize));
   debug (DB_LOG, "gattr r->filedate=", r->filedate, 0);
   return (rc);
}

#define ATTRLEN 48

STATIC int
sattr (struct k_data *k, struct k_response *r)
{                               /* Build and send A packet */
   // int i, x, aln;
   int i, x;
   short tmp;
   long filelength;
   UCHAR datebuf[DATE_MAX], *p;
   UCHAR *buf;
   short s_slot;

   debug (DB_PKT, "SATTR k->zincnt 0", 0, (k->zincnt));

   tmp = k->binary;
   filelength = (*(k->finfo))
      (k, k->filename, datebuf, DATE_MAX, &tmp, k->xfermode);
   k->binary = tmp;

   debug (DB_LOG, "  filename: ", k->filename, 0);
   debug (DB_LOG, "  filedate: ", datebuf, 0);
   debug (DB_LOG, "  filelength", 0, filelength);
   debug (DB_LOG, "  binary", 0, (k->binary));

   i = 0;

   k->xdata[i++] = '"';
   if (k->binary)
   {                            /* Binary */
      k->xdata[i++] = tochar (2);       /* Two characters */
      k->xdata[i++] = 'B';      /* B for Binary */
      k->xdata[i++] = '8';      /* 8-bit bytes (note assumption...) */
   }
   else
   {                            /* Text */
      k->xdata[i++] = tochar (3);       /* Three characters */
      k->xdata[i++] = 'A';      /* A = (extended) ASCII with CRLFs */
      k->xdata[i++] = 'M';      /* M for carriage return */
      k->xdata[i++] = 'J';      /* J for linefeed */
      k->xdata[i++] = '*';      /* Encoding */
      k->xdata[i++] = tochar (1);       /* Length of value is 1 */
      k->xdata[i++] = 'A';      /* A for ASCII */
   }
   if (filelength > -1L)
   {                            /* File length in bytes */
      UCHAR lenbuf[16];
      r->filesize = filelength;
      p = numstring (filelength, lenbuf, 16, k);
      if (p)
      {
         for (x = 0; p[x]; x++);        /* Get length of length string */
         if (i + x < ATTRLEN - 3)
         {                      /* Don't overflow buffer */
            k->xdata[i++] = '1';        /* Length-in-Bytes attribute */
            k->xdata[i++] = tochar (x);
            while (*p)
               k->xdata[i++] = *p++;
         }
      }
   }
   debug (DB_LOG, "SATTR datebuf: ", datebuf, 0);

   if (datebuf[0])
   {                            /* File modtime */
      p = datebuf;
      for (x = 0; p[x]; x++);   /* Length of modtime */
      if (i + x < ATTRLEN - 3)
      {                         /* If it will fit */
         k->xdata[i++] = '#';   /* Add modtime attribute */
         k->xdata[i++] = tochar (x);    /* Its length */
         while (*p)             /* And itself */
            k->xdata[i++] = *p++;
         /*
          * Also copy modtime to result struct 
          */
         for (x = 0; x < DATE_MAX - 1 && datebuf[x]; x++)
            r->filedate[x] = datebuf[x];
         r->filedate[x] = '\0';
      }
   }
   k->xdata[i++] = '@';         /* End of Attributes */
   k->xdata[i++] = ' ';
   k->xdata[i] = '\0';          /* Terminate attribute string */
   debug (DB_PKT, "SATTR k->xdata: ", k->xdata, 0);
   buf = get_sslot (k, &s_slot);        // get a new send slot
   k->s_pw[k->s_seq] = s_slot;
   debug (DB_LOG, "SATTR sending A pkt s_seq", 0, k->s_seq);
   debug (DB_LOG, "  s_slot", 0, s_slot);
   return (spkt ('A', k->s_seq, -1, k->xdata, k));
}

STATIC int
getpkt (struct k_data *k, struct k_response *r)
{                               /* Fill a packet from file */
   int i, next, rpt, maxlen;
// static int c;                /* PUT THIS IN STRUCT */
   int c = k->cgetpkt;

   debug (DB_LOG, "GETPKT k->s_first", 0, k->s_first);
// debug (DB_PKT, "  k->s_remain=", k->s_remain, 0);

   if (k->bcta3)
      k->bct = 3;
   maxlen = k->s_maxlen - k->bct - 3 - 6;       /* Maximum data length */
   if (k->s_first == 1)
   {                            /* If first time thru...  */
      k->s_first = 0;           /* don't do this next time, */
      k->s_remain[0] = '\0';    /* discard any old leftovers. */
      if (k->istring)
      {                         /* Get first byte. */
         c = *(k->istring)++;   /* Of memory string... */
         if (!c)
            c = -1;
      }
      else
      {                         /* or file... */
#ifdef USE_ZGETC_MACRO
         c = zgetc ();
#else
         c = zgetc (k);
#endif
      }

      k->cgetpkt = c;

      if (c < 0)
      {                         /* Watch out for empty file. */
         debug (DB_LOG, "GETPKT first c", 0, c);
         k->s_first = -1;
         return (k->size = 0);
      }
      // r->sofar++; // makes it too big
      if (k->state == S_DATA)
         r->sofar_rumor++;
      debug (DB_LOG, "GETPKT first state", 0, k->state);
      debug (DB_CHR, "  first c", 0, c);
   }
   else if (k->s_first == -1 && !k->s_remain[0])
   {                            /* EOF from last time? */
      return (k->size = 0);
   }

   // string copy s_remain to xdata
   for (k->size = 0;
        (k->xdata[k->size] = k->s_remain[k->size]) != '\0'; (k->size)++);

   // set s_remain to zero length
   k->s_remain[0] = '\0';

   if (k->s_first == -1)
      return (k->size);

   rpt = 0;                     /* Initialize repeat counter. */
   while (k->s_first > -1)
   {                            /* Until end of file or string... */
      if (k->istring)
      {
         next = *(k->istring)++;
         if (!next)
            next = -1;
      }
      else
      {
#ifdef USE_ZGETC_MACRO
         next = zgetc ();
#else
         next = zgetc (k);
#endif
      }
      if (next < 0)
      {                         /* If none, we're at EOF. */
         k->s_first = -1;
      }
      else
      {                         /* Otherwise */
         r->sofar_rumor++;      /* count this byte */
      }
      k->osize = k->size;       /* Remember current size. */
      encode (c, next, k);      /* Encode the character. */
      /*
       * k->xdata[k->size] = '\0'; 
       */
      c = next;                 /* Old next char is now current. */

      k->cgetpkt = c;

      if (k->size == maxlen)
      {                         /* Just at end, done. */
         debug (DB_LOG, "GETPKT size perfect c", 0, c);
         return (k->size);
      }

      if (k->size > maxlen)
      {                         /* Past end, must save some. */
         for (i = 0; (k->s_remain[i] = k->xdata[(k->osize) + i]) != '\0';
              i++);
         debug (DB_LOG, "GETPKT size past end i", 0, i);
         k->size = k->osize;
         k->xdata[k->size] = '\0';
         return (k->size);      /* Return size. */
      }
   }
   if (k->size > maxlen)
   {
      debug (DB_LOG, "GETPKT error confused: from getpkt() k->size",
             0, k->size);
      epkt ("EKSW getpkt confused", k);
//    exit (1);
      return (X_ERROR);
   }
   return (k->size);            /* EOF, return size. */
}

STATIC int
sdata (struct k_data *k, struct k_response *r)
{                               /* Send a data packet */
   int len, rc;
   if (k->cancel)
   {                            /* Interrupted */
      debug (DB_LOG, "SDATA interrupted k->cancel", 0, (k->cancel));
      return (0);
   }
   len = getpkt (k, r);         /* Fill data field from input file */
   debug (DB_LOG, "SDATA getpkt len", 0, len);
   if (len < 1)
   {
      debug (DB_LOG, "SDATA getpkt got eof s_seq", 0, k->s_seq);
      return (0);
   }
   debug (DB_LOG, "SDATA sending D pkt s_seq", 0, k->s_seq);

   rc = spkt ('D', k->s_seq, len, k->xdata, k); /* Send the packet */

   debug (DB_LOG, "SDATA spkt rc", 0, rc);
   return ((rc == X_ERROR) ? rc : len);
}

/*
 * E P K T -- Send a (fatal) Error packet with the given message 
 */

STATIC void
epkt (char *msg, struct k_data *k)
{
   int bctsv;

   if (k->bcta3)
   {
      bctsv = 3;
      k->bct = 3;
   }
   else
   {
      bctsv = k->bct;
      k->bct = 1;
   }
   debug (DB_LOG, "EPKT msg:", msg, 0);
   spkt ('E', 0, -1, (UCHAR *) msg, k);
   k->bct = bctsv;
}

STATIC int                      /* Fill a packet from string s. */
encstr (UCHAR * s, struct k_data *k, struct k_response *r)
{
   k->s_first = 1;              /* Start lookahead. */
   k->istring = s;              /* Set input string pointer */
   getpkt (k, r);               /* Fill a packet */
   k->istring = (UCHAR *) 0;    /* Reset input string pointer */
   k->s_first = 1;              /* "Rewind" */
   return (k->size);            /* Return data field length */
}

/*
 * Decode packet data into a string 
 */

#if 0                           // never used
STATIC void
decstr (UCHAR * s, struct k_data *k, struct k_response *r)
{
   k->ostring = s;              /* Set output string pointer */
   (void) decode (k, r, 0, s, -1);
   *(k->ostring) = '\0';        /* Terminate with null */
   k->ostring = (UCHAR *) 0;    /* Reset output string pointer */
}
#endif

STATIC void
encode (int a, int next, struct k_data *k)
{                               /* Encode character into packet == k->xdata */
   int a7, b8, maxlen;

   maxlen = k->s_maxlen - 4;
   if (k->rptflg)
   {                            /* Doing run-length encoding? */
      if (a == next)
      {                         /* Yes, got a run? */
         if (++(k->s_rpt) < 94)
         {                      /* Yes, count. */
            return;
         }
         else if (k->s_rpt == 94)
         {                      /* If at maximum */
            k->xdata[(k->size)++] = k->rptq;    /* Emit prefix, */
            k->xdata[(k->size)++] = tochar (k->s_rpt);  /* and count, */
            k->s_rpt = 0;       /* and reset counter. */
         }
      }
      else if (k->s_rpt == 1)
      {                         /* Run broken, only two? */
         k->s_rpt = 0;          /* Yes, do the character twice */
         encode (a, -1, k);     /* by calling self recursively. */
         if (k->size <= maxlen) /* Watch boundary. */
            k->osize = k->size;
         k->s_rpt = 0;          /* Call self second time. */
         encode (a, -1, k);
         return;
      }
      else if (k->s_rpt > 1)
      {                         /* Run broken, more than two? */
         k->xdata[(k->size)++] = k->rptq;       /* Yes, emit prefix and count */
         k->xdata[(k->size)++] = tochar (++(k->s_rpt));
         k->s_rpt = 0;          /* and reset counter. */
      }
   }
   a7 = a & 127;                /* Get low 7 bits of character */
   b8 = a & 128;                /* And "parity" bit */

   if (k->ebqflg && b8)
   {                            /* If doing 8th bit prefixing */
      k->xdata[(k->size)++] = k->ebq;   /* and 8th bit on, insert prefix */
      a = a7;                   /* and clear the 8th bit. */
   }

// if (a7 < 32 || a7 == 127)    /* If in control range -- conservative */
// if (a7==0 || a7==1 || a7==13)  // 2004-07-04 -- JHD -- need 127 for telnet
   // this is a bit more conservative than C-Kermit "set prefixing minimal" 
   if (a7 == 0 || a7 == 1 || a7 == 3 || a7 == 4 || a7 == 10 ||
       a7 == 13 || a7 == 21 || a7 == 127)
   {
      k->xdata[(k->size)++] = k->s_ctlq;        /* insert control prefix */
      a = ctl (a);              /* and make character printable. */
   }
   else if (a7 == k->s_ctlq)    /* If data is control prefix, */
      k->xdata[(k->size)++] = k->s_ctlq;        /* prefix it. */
   else if (k->ebqflg && a7 == k->ebq)  /* If doing 8th-bit prefixing, */
      k->xdata[(k->size)++] = k->s_ctlq;        /* ditto for 8th-bit prefix. */
   else if (k->rptflg && a7 == k->rptq) /* If doing run-length encoding, */
      k->xdata[(k->size)++] = k->s_ctlq;        /* ditto for repeat prefix. */

   k->xdata[(k->size)++] = a;   /* Finally, emit the character. */
   k->xdata[(k->size)] = '\0';  /* Terminate string with null. */

   if (k->size < 0 || k->size >= P_PKTLEN + 2)
   {
      debug (DB_LOG, "confused: from encode() k->size", 0, k->size);
      epkt ("EKSW encode confused", k);
//    exit (1);
      return;
   }
}

STATIC short
nxtpkt (struct k_data *k)
{                               /* Get next packet to send */
   k->s_seq = (k->s_seq + 1) & 63;      /* Next sequence number */
   k->s_cnt++;
   k->xdata = k->xdatabuf;
   return (k->s_seq);
}

STATIC int
resend (struct k_data *k, short seq)
{
   UCHAR *buf;
   int ret;
   short slot;

   debug (DB_LOG, "RESEND seq", 0, seq);

   if (seq < 0)
      seq = earliest_sseq (k);
   if (seq < 0)
   {
      debug (DB_LOG, "RESEND failed: no earliest seq", 0, seq);
#ifdef DEBUG
      show_sslots (k);
#endif
      return (X_OK);
   }
   slot = k->s_pw[seq];
   if (slot < 0)
   {
      debug (DB_LOG, "RESEND failed: no slot for seq", 0, seq);
#ifdef DEBUG
      show_sslots (k);
#endif
      seq = earliest_sseq (k);
      if (seq < 0)
      {
         debug (DB_LOG, "RESEND failed: still no earliest seq", 0, seq);
#ifdef DEBUG
         show_sslots (k);
#endif
         return (X_OK);
      }
      slot = k->s_pw[seq];
      debug (DB_LOG, "RESEND sending earliest seq", 0, seq);
      debug (DB_LOG, "  slot", 0, slot);
   }
   if (slot < 0)
   {
      debug (DB_LOG, "RESEND failed: still bad slot", 0, slot);
#ifdef DEBUG
      show_sslots (k);
#endif
      return (X_OK);
   }

   debug (DB_MSG, "RESEND opktinfo:", 0, 0);
   debug (DB_LOG, "  seq", 0, k->opktinfo[slot].seq);
   debug (DB_CHR, "  typ", 0, k->opktinfo[slot].typ);
   debug (DB_LOG, "  len", 0, k->opktinfo[slot].len);
   debug (DB_LOG, "  rtr", 0, k->opktinfo[slot].rtr);
   debug (DB_LOG, "  crc", 0, k->opktinfo[slot].crc);
   debug (DB_LOG, "  flg", 0, k->opktinfo[slot].flg);

   k->opktlen = k->opktinfo[slot].len;

   if (k->opktlen < 0 || k->opktlen >= P_BUFLEN)
   {
      debug (DB_LOG, "RESEND error opktlen", 0, k->opktlen);
      return (X_ERROR);
   }

   // what about .seq, .typ, .rtr, .flg ?

   if (!k->opktlen)             /* Nothing to resend */
      return (X_OK);

   k->nresend++;

   buf = k->opktinfo[slot].buf;

   k->opktinfo[slot].rtr++;
   if (k->opktinfo[slot].rtr > k->retry)
   {
      debug (DB_LOG, "RESEND error retries", 0, k->opktinfo[slot].rtr);
      return (X_ERROR);
   }

// debug (DB_PKT, ">PKT", &buf[1], k->opktlen);
   ret = ((*(k->txd)) (k, buf, k->opktlen));
   debug (DB_LOG, "RESEND txd ret", 0, ret);
   return (ret);
}

int                             /* The kermit() function */
kermit (short fc,               /* Function code */
        struct k_data *k,       /* The control struct */
        int len,                /* Length of packet in buf */
        char *msg,              /* Message for error packet */
        struct k_response *r)   /* Response struct */
{
   int did_a_pkt = 0;
   UCHAR *buf = 0;
   short s_slot;

   // int i, j, rc; /* Workers */
   int i, rc;                   /* Workers */
   int datalen = 0;             /* Length of packet data field */
   // int bctu; /* Block check type for this packet */
   UCHAR *pdf = 0;              /* Pointer to packet data field */
   UCHAR *qdf = 0;              /* Pointer to data to be checked */
   UCHAR *s = 0;                /* Worker string pointer */
   // UCHAR c, t; /* Worker chars */
   UCHAR rtyp = 0;              /* Worker chars */
   UCHAR c;                     /* Worker chars */
   UCHAR pbc[4];                /* Copy of packet block check */
   short rseq = 0;              // actual received packet number
   short rlen = 0;
   short chklen;                /* Length of packet block check */
   unsigned int crc;            /* 16-bit CRC */
   int ok;

   /* Mark each entry: */
   debug (DB_LOG, "KERMIT ---------------------- version", VERSION, 0);
   debug (DB_LOG, "  fc", 0, fc);
   debug (DB_LOG, "  state", 0, k->state);
   debug (DB_LOG, "  zincnt", 0, (k->zincnt));
   debug (DB_LOG, "  k->wslots", 0, k->wslots);

   test_rslots (k);

#ifdef DEBUG
   show_sslots (k);
#endif

   if (fc == K_INIT)
   {                            /* Initialize packet buffers etc */

      k->version = (UCHAR *) VERSION;   /* Version of this module */
      r->filename[0] = '\0';    /* No filename yet. */
      r->filedate[0] = '\0';    /* No filedate yet. */
      r->filesize = 0L;         /* No filesize yet. */
      r->sofar = 0L;            /* No bytes transferred yet */
      r->sofar_rumor = 0L;      /* No bytes transferred yet */


      for (i = 0; i < P_WSLOTS; i++)
      {                         /* Packet info for each window slot */
         free_rslot (k, i);
         free_sslot (k, i);
      }
      for (i = 0; i < 64; i++)
      {                         /* Packet finder array */
         k->r_pw[i] = -1;       /* initialized to "no packets yet" */
         k->s_pw[i] = -1;       /* initialized to "no packets yet" */
      }

/* Initialize the k_data structure */

      k->sw_full = 0;
      k->do_rxd = 1;
      k->s_cnt = 0;

      for (i = 0; i < 6; i++)
         k->s_remain[i] = '\0';

      k->state = R_WAIT;        /* Beginning protocol state */
      r->rstatus = R_WAIT;
      k->what = W_RECV;         /* Default action */
      k->s_first = 1;           /* Beginning of file */
      k->r_soh = k->s_soh = SOH;        /* Packet start */
      k->r_eom = k->s_eom = CR; /* Packet end */
      k->s_seq = k->r_seq = 0;  /* Packet sequence number */
      k->s_cnt = 0;             /* Packet count */
      k->s_type = k->r_type = 0;        /* Packet type */
      k->r_timo = P_R_TIMO;     /* Timeout interval for me to use */
      k->s_timo = P_S_TIMO;     /* Timeout for other Kermit to use */
      k->r_maxlen = k->p_maxlen;        /* Maximum packet length */
      k->s_maxlen = k->p_maxlen;        /* Maximum packet length */
      k->wslots = k->wslots_max;        /* Current window slots */
      k->zincnt = 0;
      k->filename = (UCHAR *) 0;

      /* Parity must be filled in by the caller */

      k->retry = P_RETRY;       /* Retransmission limit */
      k->s_ctlq = k->r_ctlq = '#';      /* Control prefix */
      k->ebq = 'Y';             /* 8th-bit prefix negotiation */
      k->ebqflg = 0;            /* 8th-bit prefixing flag */
      k->rptq = '~';            /* Send repeat prefix */
      k->rptflg = 0;            /* Repeat counts negotiated */
      k->s_rpt = 0;             /* Current repeat count */
      k->capas = 0              /* Capabilities */
         | CAP_LP               /* Long packets */
         | CAP_AT               /* Attribute packets */
         ;
      if (k->wslots > 1)
         k->capas |= CAP_SW;    /* Sliding windows */

      for (i = 0; i < P_WSLOTS; i++)
      {
         k->ipktinfo[i].buf = k->ipktbufs + i * P_BUFLEN;
         k->ipktinfo[i].buf[0] = '\0';
         k->ipktinfo[i].len = 0;
         k->ipktinfo[i].seq = -1;
         k->ipktinfo[i].typ = SP;
         k->ipktinfo[i].dat = (UCHAR *) (0);
         k->ipktinfo[i].crc = 0xFFFF;
      }

      for (i = 0; i < P_WSLOTS; i++)
      {
         k->opktinfo[i].buf = k->opktbuf + i * P_BUFLEN;
         k->opktinfo[i].buf[0] = '\0';
         k->opktinfo[i].len = 0;
         k->opktinfo[i].seq = -1;
         k->opktinfo[i].typ = SP;
         k->opktinfo[i].dat = (UCHAR *) (0);
      }

      k->opktlen = 0;

      /* This is the only way to initialize these tables -- no static data. */

      k->crcta[0] = 0;          /* CRC generation table A */
      k->crcta[1] = 010201;
      k->crcta[2] = 020402;
      k->crcta[3] = 030603;
      k->crcta[4] = 041004, k->crcta[5] = 051205;
      k->crcta[6] = 061406;
      k->crcta[7] = 071607;
      k->crcta[8] = 0102010;
      k->crcta[9] = 0112211;
      k->crcta[10] = 0122412;
      k->crcta[11] = 0132613;
      k->crcta[12] = 0143014, k->crcta[13] = 0153215;
      k->crcta[14] = 0163416;
      k->crcta[15] = 0173617;

      k->crctb[0] = 0;          /* CRC table B */
      k->crctb[1] = 010611;
      k->crctb[2] = 021422;
      k->crctb[3] = 031233;
      k->crctb[4] = 043044;
      k->crctb[5] = 053655;
      k->crctb[6] = 062466;
      k->crctb[7] = 072277;
      k->crctb[8] = 0106110;
      k->crctb[9] = 0116701;
      k->crctb[10] = 0127532;
      k->crctb[11] = 0137323;
      k->crctb[12] = 0145154;
      k->crctb[13] = 0155745;
      k->crctb[14] = 0164576;
      k->crctb[15] = 0174367;

//              k->nspkt = 0;
//    k->nsack = 0;
      k->nsnak = 0;
      k->nresend = 0;
//    k->nepkt = 0;
//    k->nbchk = 0;
//    k->nshort = 0;
//    k->nnaa = 0;
//    k->ndiscard1 = 0;
//    k->ndiscard2 = 0;
//    k->ndiscard3 = 0;

      return (X_OK);

   }
   else if (fc == K_GET)
   {
      /*
       * Send R packet with filenames we want.
       * Filenames cannot have spaces
       * since names are separated by spaces.
       */
      int i;
      char *p, *q;

      debug (DB_LOG, "function code == K_GET fc", 0, fc);

      p = (char *) (k->obuf);
      for (i = 0;; i++)
      {
         q = (char *) (k->filelist[i]);
         if (q == 0)
            break;
         if (i > 0)
            *p++ = ' ';
         while (*q)
            *p++ = *q++;
      }
      *p = 0;

      debug (DB_LOG, "before encstr k->obuf", k->obuf, 0);
      k->xdata = k->xdatabuf;
      encstr (k->obuf, k, r);   // Encode the name for transmission 
      debug (DB_LOG, "after encstr k->xdata", k->xdata, 0);

      buf = get_sslot (k, &s_slot);     // get a new send slot
      k->s_pw[k->s_seq] = s_slot;
      if (k->bcta3)
         k->bct = 3;
      else
         k->bct = 1;
      debug (DB_LOG, "K_GET sending R pkt s_seq", 0, k->s_seq);
      if (spkt ('R', k->s_seq, -1, k->xdata, k) != X_OK)
      {
         debug (DB_LOG, "K_GET error spkt(R) failed fc", 0, fc);
         return (X_ERROR);      /* I/O error, quit. */
      }
      k->state = R_WAIT;        /* All OK, switch states */
      r->rstatus = R_WAIT;
      k->what = W_GET;
      return (X_OK);
   }
   else if (fc == K_SEND)
   {
      if (rpar (k, 'S') != X_OK)        /* Send S packet with my parameters */
      {
         debug (DB_LOG, "K_SEND error rpar(S) failed fc", 0, fc);
         return (X_ERROR);      /* I/O error, quit. */
      }
      k->state = S_INIT;        /* All OK, switch states */
      r->rstatus = S_INIT;
      k->what = W_SEND;         /* Act like a sender */
      return (X_OK);
   }
   else if (fc == K_STATUS)
   {                            /* Status report requested. */
      debug (DB_LOG, "function code == K_STATUS fc", 0, fc);
      return (X_STATUS);        /* File name, date, size, if any. */
   }
   else if (fc == K_QUIT)
   {                            /* You told me to quit */
      debug (DB_LOG, "function code == K_QUIT fc", 0, fc);
      return (X_DONE);          /* so I quit. */
   }
   else if (fc == K_SYNC)
   {
      debug (DB_LOG, "function code == K_SYNC fc", 0, fc);
      epkt (msg, k);
      return (X_OK);
   }
   else if (fc == K_ERROR)
   {                            /* Send an error packet... */
      debug (DB_LOG, "K_ERROR error fc", 0, fc);
      epkt (msg, k);
      k->closef (k, 0, (k->state == S_DATA) ? 1 : 2);   /* Close file */
      return (X_DONE);          /* and quit. */
   }
   else if (fc != K_RUN)
   {                            /* Anything else is an error. */
      debug (DB_LOG, "not K_RUN error fc", 0, fc);
      return (X_ERROR);
   }

   if (k->state == R_NONE)      /* (probably unnecessary) */
      return (X_OK);

   /* If we're in the protocol, check to make sure we got a new packet */
   debug (DB_MSG, "In the protocol", 0, 0);

   if (k->do_rxd)
   {                            // we tried to read a packet in main loop

      debug (DB_LOG, "DO_RXD len", 0, len);     // in kermit call list

      if (len < 4)
      {                         /* Packet obviously no good? */
         int ret;

         if (k->what == W_RECV) /* If receiving */
         {
            debug (DB_MSG, "DO_RXD len<4", 0, 0);
#ifdef USE_NAK_OLDEST_UNACKED
            nak_oldest_unacked (k, -1);
#endif
            if (k->state == R_FILE)
            {
               debug (DB_MSG, "calling rpar again", 0, 0);
               rc = rpar (k, 'Y');      /* ACK again with my parameters */
            }
            return (X_OK);
         }
         else                   /* If W_SEND or W_GET */
         {
            debug (DB_MSG, "DO_RXD len<4: resending earliest", 0, 0);
            ret = resend (k, -1);       /* retransmit earliest packet in queue. */
            return (ret);
         }
      }

      /* Parse the packet */

      if (k->what == W_RECV)
      {                         /* If we're sending ACKs */
         switch (k->cancel)
         {                      /* Get cancellation code if any */
         case 0:
            s = (UCHAR *) 0;
            break;
         case 1:
            s = (UCHAR *) "X";
            break;
         case 2:
            s = (UCHAR *) "Z";
            break;
         }
      }

      pdf = k->ipktbuf;

      qdf = pdf;                /* Pointer to data to be checked */
      rlen = xunchar (*pdf++);  /* Length field */
      rseq = xunchar (*pdf++);  /* Received Sequence number */
      rtyp = *pdf++;            /* Type */

      if (k->state == S_EOT &&
          len == 4 && rseq == 0 && rtyp == 'N' && *pdf == 0x33)
      {
         debug (DB_MSG, "Got NAK for seq=0 after sending B-pkt", 0, 0);
         debug (DB_MSG, "  so assuming we are done.", 0, 0);
         return (X_DONE);       /* (or X_ERROR) */
      }

      // Really to use rseq the packet must be validated by CRC first.
      if (rseq < 0 || rseq > 63)
      {
         debug (DB_LOG, "WARNING: TOSSING BAD PACKET: rseq", 0, rseq);
         debug (DB_LOG, "  rlen", 0, rlen);
         debug (DB_CHR, "  rtyp", 0, rtyp);
         debug (DB_LOG, "  what", 0, k->what);
         debug (DB_PKT, "  k->ipktbuf", k->ipktbuf, 0);
         return (X_OK);
      }

      if ((k->what == W_RECV) && (rtyp == 'N' || rtyp == 'Y'))
      {
         /* Echo (it happens), ignore */
         return (X_OK);
      }

      if (rlen == 0)
      {                         /* Length 0 means long packet */
         c = pdf[2];            /* Get header checksum */
         pdf[2] = '\0';
         if (xunchar (c) != chk1 (pdf - 3, k))
         {                      /* Check it */
            int ret;
            debug (DB_MSG, "long pkt chk1 bad", 0, 0);
            if (k->what == W_RECV)
            {
#ifdef USE_NAK_OLDEST_UNACKED
               debug (DB_MSG, "sending NAK for oldest unacked", 0, 0);
               nak_oldest_unacked (k, -1);      /* Send NAK */
#endif
               return (X_OK);
            }
            else
            {
               debug (DB_MSG, "resending earliest", 0, 0);
               ret = resend (k, -1);
               debug (DB_LOG, "resend ret", 0, ret);
               return (ret);
            }
         }
         debug (DB_MSG, "HDR CHKSUM OK", 0, 0);
         pdf[2] = c;            /* Put checksum back */
         if (k->bcta3)
            k->bct = 3;
         datalen = xunchar (pdf[0]) * 95 + xunchar (pdf[1]) - k->bct;   /* Data length */

         debug (DB_LOG, "  long packet datalen", 0, datalen);
         debug (DB_LOG, "  rlen", 0, rlen);
         debug (DB_LOG, "  rseq", 0, rseq);

         pdf += 3;              /* Fix data pointer */
      }
      else
      {                         /* Regular packet */
         if (k->bcta3)
            k->bct = 3;
         datalen = rlen - k->bct - 2;   /* Data length */
         debug (DB_LOG, "regular packet datalen", 0, datalen);
      }


      if (rtyp == 'S' || k->state == S_INIT)
      {                         /* S-packet was
                                 * retransmitted? */
         if (k->bcta3)
         {
            chklen = 3;
            datalen = rlen - 5;
         }
         else
         {
            chklen = 1;         /* Block check is always type 1 */
            datalen = rlen - 3;
         }
         debug (DB_LOG, "S-packet datalen", 0, datalen);
      }
      else
      {
         if (k->bcta3)
            k->bct = 3;
         chklen = k->bct;
      }

      debug (DB_LOG, "DO_RXD state", 0, k->state);
      debug (DB_MSG, "  These are unverified: (before blk chk tested)", 0, 0);
      debug (DB_LOG, "  rlen", 0, rlen);
      debug (DB_LOG, "  rseq", 0, rseq);
      debug (DB_CHR, "  rtyp", 0, rtyp);
      debug (DB_LOG, "  bct", 0, k->bct);
      debug (DB_LOG, "  bcta3", 0, k->bcta3);
      debug (DB_LOG, "  datalen", 0, datalen);
      debug (DB_LOG, "  chklen", 0, chklen);

      if (datalen < 0 || datalen + chklen + 1 >= P_BUFLEN)
      {
         debug (DB_MSG, "DO_RXD datalen out of bounds", 0, 0);
         if (k->what == W_RECV)
         {
#ifdef USE_NAK_OLDEST_UNACKED
            debug (DB_LOG, "  NAK oldest or rseq", 0, rseq);
            nak_oldest_unacked (k, rseq);
#endif
         }
         else
         {
            debug (DB_MSG, "  resend earliest", 0, 0);
            resend (k, -1);
         }
         return (X_OK);
      }

      for (i = 0; i < chklen; i++)      /* Copy the block check */
         pbc[i] = pdf[datalen + i];
      pbc[i] = '\0';            /* Null-terminate block check string */
      pdf[datalen] = '\0';      /* and the packet DATA field. */
      switch (chklen)
      {                         /* Check the block check */
      case 1:                  /* Type 1, 6-bit checksum */
         ok = (xunchar (*pbc) == chk1 (qdf, k));
#ifdef DEBUG
         if (ok && xerror ())
            ok = 0;
#endif /* DEBUG */
         if (!ok)
         {
            debug (DB_CHR, "6-bit checksum ERROR rtyp", 0, rtyp);
            debug (DB_LOG, "  rseq", 0, rseq);
            debug (DB_PKT, "  k->ipktbuf", k->ipktbuf, 0);
            if (k->what == W_RECV)
            {
#ifdef USE_NAK_OLDEST_UNACKED
               debug (DB_LOG, "  NAK oldest or rseq", 0, rseq);
               nak_oldest_unacked (k, rseq);
#endif
            }
            else
            {
               debug (DB_MSG, "  resend earliest", 0, 0);
               resend (k, -1);
            }
            return (X_OK);
         }
         break;

      case 2:                  /* Type 2, 12-bit checksum */
         i = xunchar (*pbc) << 6 | xunchar (pbc[1]);
         ok = (i == chk2 (qdf, k));
#ifdef DEBUG
         if (ok && xerror ())
            ok = 0;
#endif /* DEBUG */
         if (!ok)
         {                      /* No match */
            debug (DB_CHR, "12-bit checksum ERROR rtyp", 0, rtyp);
            debug (DB_LOG, "  rseq", 0, rseq);
            debug (DB_PKT, "  k->ipktbuf", k->ipktbuf, 0);
            if (rtyp == 'E')
            {                   /* Allow E packets to have type 1 */
               int j;
               j = datalen;
               pdf[j++] = pbc[0];
               pdf[j] = '\0';
               if (xunchar (pbc[1]) == chk1 (qdf, k))
                  break;
               else
                  pdf[--j] = '\0';
            }
            if (k->what == W_RECV)
            {
#ifdef USE_NAK_OLDEST_UNACKED
               debug (DB_LOG, "  NAK oldest or rseq", 0, rseq);
               nak_oldest_unacked (k, rseq);
#endif
            }
            else
            {
               debug (DB_MSG, "  resend earliest", 0, 0);
               resend (k, -1);
            }
            return (X_OK);
         }
         break;

      case 3:                  /* Type 3, 16-bit CRC */
         crc = (xunchar (pbc[0]) << 12)
            | (xunchar (pbc[1]) << 6) | (xunchar (pbc[2]));
         ok = (crc == chk3 (qdf, k));
#ifdef DEBUG
         if (ok && xerror ())
         {
            ok = 0;
            debug (DB_MSG, "INPUT CRC ERROR INJECTED", 0, 0);
         }
#endif /* DEBUG */
         if (!ok)
         {
            debug (DB_MSG, "Packet blk chk3 bad", 0, 0);
            debug (DB_LOG, "  rseq", 0, rseq);

            if (rtyp == 'E')
            {                   /* Allow E packets to have type 1 */
               int j;
               j = datalen;
               pdf[j++] = pbc[0];
               pdf[j++] = pbc[1];
               pdf[j] = '\0';
               if (xunchar (pbc[2]) == chk1 (qdf, k))
                  break;
               else
               {
                  j -= 2;
                  pdf[j] = '\0';
               }
            }
            if (k->what == W_RECV)
            {
#ifdef USE_NAK_OLDEST_UNACKED
               debug (DB_LOG, "  NAK oldest or rseq", 0, rseq);
               nak_oldest_unacked (k, rseq);
#endif
            }
            else
            {
               debug (DB_MSG, "  resend earliest", 0, 0);
               resend (k, -1);
            }
            return (X_OK);
         }
      }

      // now the packet has a good block check
      debug (DB_MSG, "Packet blk chk good", 0, 0);
      debug (DB_CHR, "  rtyp", 0, rtyp);
      debug (DB_LOG, "  rseq", 0, rseq);
      debug (DB_LOG, "  k->r_seq", 0, k->r_seq);
      debug (DB_LOG, "  k->state", 0, k->state);
      debug (DB_LOG, "  chklen", 0, chklen);
      debug (DB_LOG, "  datalen", 0, datalen);

      if (rtyp == 'E')          /* (AND CLOSE FILES?) */
      {
         debug (DB_MSG, "error msg received from other kermit", 0, 0);
         debug (DB_PKT, "EPKT", pdf, 0);
         return (X_ERROR);
      }

      if (k->what == W_SEND)    /* Sending, check for ACK */
      {
         if (rtyp != 'Y')
         {
            int ret;

            debug (DB_CHR, "rtyp not Y, rtyp", 0, rtyp);

            if (k->state == S_DATA &&
                rtyp == 'N' && rseq == ((k->r_seq + 1) & 63))
            {
               debug (DB_MSG,
                      "FYI got NAK for packet just after last one sent", 0,
                      0);
#ifdef DEBUG
               show_sslots (k);
#endif

# if 0
               debug (DB_MSG, "W_SEND Freeing all send slots", 0, 0);
               for (i = 0; i < k->wslots; i++)
                  free_sslot (k, i);
               k->sw_full = 0;
# endif
            }

            if (nused_sslots (k) == 0)
            {
               debug (DB_LOG, "sending requested rseq", 0, rseq);

               nxtpkt (k);
               if (k->s_seq != rseq)
               {
                  debug (DB_LOG, "error confused s_seq", 0, k->s_seq);
                  debug (DB_LOG, "  rseq", 0, rseq);
                  epkt ("EKSW W_SEND confused", k);
//                exit (1);
                  return (X_ERROR);
               }
               buf = get_sslot (k, &s_slot);    // get a new send slot
               k->s_pw[k->s_seq] = s_slot;

               rc = sdata (k, r);       /* Send next data packet */
               if (rc == X_ERROR)
                  return (rc);
               if (rc == 0)
               {                /* If there was no data to send */
                  k->closef (k, 0, 1);  /* Close input file */
                  k->state = S_EOF;     /* And wait for ACK */
                  r->rstatus = S_EOF;
                  k->s_seq--;
                  if (k->s_seq < 0)
                     k->s_seq += 64;
                  free_sslot (k, s_slot);
               }                /* Otherwise stay in data state */
               k->r_seq = k->s_seq;     /* Sequence number to wait for */
               return (X_OK);
            }
            else
            {
               debug (DB_LOG, "6: resending rseq", 0, rseq);
               // resend will send rseq if it's in the send table
               // otherwise it will resend earliest unacked packet
               ret = resend (k, rseq);
               debug (DB_LOG, "ret", 0, ret);
               return (ret);
            }
         }

         // we're sending, received an ACK and packet block check OK

         s_slot = k->s_pw[rseq];
         if (s_slot < 0 || s_slot >= k->wslots)
         {
            debug (DB_LOG, "ignoring ack -- not in table rseq", 0, rseq);
#ifdef DEBUG
            show_sslots (k);
#endif
            return (X_OK);
         }

         // set ACK'd flag for that send slot
         k->opktinfo[s_slot].flg = 1;

         // remove earliest and subsequent
         free_sslot_easca (k);

#ifdef DEBUG
         // check that send table sequence numbers are in order
         chk_sseq_nos (k);
#endif

         if (k->state == S_DATA)
         {                      /* ACK to Data packet? */
            if (k->cancel ||    /* Cancellation requested by caller? */
                *pdf == 'X' || *pdf == 'Z')
            {                   /* Or by receiver? */
               k->closef (k, 0, 1);     /* Close input file */
               nxtpkt (k);      /* Next packet sequence number */
               buf = get_sslot (k, &s_slot);    // get a new send slot
               k->s_pw[k->s_seq] = s_slot;

               debug (DB_LOG, "Cancellation: sending Z pkt s_seq", 0,
                      k->s_seq);
               debug (DB_LOG, "  s_slot", 0, s_slot);

               rc = spkt ('Z', k->s_seq, 0, (UCHAR *) 0, k);
               debug (DB_LOG, "  rc", 0, rc);
               if (rc != X_OK)
               {
                  return (rc);
               }
               if (*pdf == 'Z' || k->cancel == I_GROUP)
               {                /* Cancel Group? */
                  debug (DB_MSG, "Group Cancel (Send)", 0, 0);
                  while (*(k->filelist))
                  {             /* Go to end of file list */
                     debug (DB_LOG, "Skip", *(k->filelist), 0);
                     (k->filelist)++;
                  }
               }
               k->state = S_EOF;        /* Wait for ACK to EOF */
               r->rstatus = S_EOF;
               k->r_seq = k->s_seq;     /* Sequence number of packet we want */
               return (X_OK);
            }
         }
         r->sofar = r->sofar_rumor;

         debug (DB_LOG, "end of W_SEND rseq", 0, rseq);
         debug (DB_LOG, "  k->r_seq", 0, k->r_seq);
         debug (DB_LOG, "  k->state", 0, k->state);
         debug (DB_CHR, "  rtyp", 0, rtyp);
      }                         // if (k->what == W_SEND)
   }                            // if(k->do_rxd)

   switch (k->state)
   {                            /* Kermit protocol state switcher */

   case S_INIT:                /* Got other Kermit's parameters */
   case S_EOF:                 /* got ack to Z packet */
      if (k->state == S_INIT)
      {                         /* Got ACK to S packet? */
         debug (DB_MSG, "S_INIT", 0, 0);
         spar (k, pdf, datalen);        /* Set negotiated parameters */
         debug (DB_CHR, "Parity", 0, k->parity);
         debug (DB_LOG, "Ebqflg", 0, k->ebqflg);
         debug (DB_CHR, "Ebq", 0, k->ebq);
      }
      else
      {
         debug (DB_LOG, "S_EOF rseq", 0, rseq);

# if 0                          // don't use k->r_seq to switch states -- use nused_sslots()
         debug (DB_LOG, "S_EOF k->r_seq", 0, k->r_seq);
         if (rseq != k->r_seq)  // keep reading until last packet ACKed
            return (X_OK);
# endif

         if ((i = nused_sslots (k)) > 0)
         {
            debug (DB_LOG, "keep reading until all sslots free.  nused", 0,
                   i);
#ifdef DEBUG
            show_sslots (k);
#endif
            return (X_OK);
         }
      }

      nxtpkt (k);               /* Get next packet number etc */

      k->filename = *(k->filelist);     /* Get next filename */
      if (k->filename)
      {                         /* If there is one */
         int i;
         for (i = 0; i < FN_MAX; i++)
         {                      /* Copy name to result struct 
                                 */
            r->filename[i] = k->filename[i];
            if (!(r->filename[i]))
               break;
         }
         (k->filelist)++;
         debug (DB_LOG, "Filename", k->filename, 0);
         if ((rc = (k->openf) (k, k->filename, 1)) != X_OK)     /* Try to open */
         {
            debug (DB_LOG, "k->openf failed rc", 0, rc);
            return (rc);
         }

         encstr (k->filename, k, r);    /* Encode the name for transmission */

         buf = get_sslot (k, &s_slot);  // get a new send slot
         k->s_pw[k->s_seq] = s_slot;

         debug (DB_LOG, "sending F pkt k->s_seq", 0, k->s_seq);
         debug (DB_LOG, "sending F pkt s_slot", 0, s_slot);
         k->sw_full = 0;
         if ((rc = spkt ('F', k->s_seq, -1, k->xdata, k)) != X_OK)
         {
            return (rc);        /* Send F packet */
         }
         r->sofar = 0L;
         r->sofar_rumor = 0L;
         k->state = S_FILE;     /* Wait for ACK */
         r->rstatus = S_FILE;
      }
      else
      {                         /* No more files - we're done */

# if 0                          // this was a hack but should not be needed

         int nused = nused_sslots (k);
         debug (DB_LOG, "want to send B pkt nused", 0, nused);

         if (nused == k->wslots)
         {
            short rm_sseq;
            short rm_sslot;

            rm_sseq = earliest_sseq (k);
            if (rm_sseq < 0 || rm_sseq >= k->wslots)
            {
               debug (DB_LOG, "want to send B pkt error rm_sseq", 0, rm_sseq);
               return (X_ERROR);
            }

            rm_sslot = k->s_pw[rm_sseq];
            if (rm_sslot < 0 || rm_sslot >= k->wslots)
            {
               debug (DB_LOG, "want to send B pkt error rm_sslot", 0,
                      rm_sslot);
               debug (DB_LOG, "  rm_sseq", 0, rm_sseq);
               return (X_ERROR);
            }

            free_sslot (k, rm_sslot);
         }
# endif

         // all sslots are supposed to be free at this point

         buf = get_sslot (k, &s_slot);  // get a new send slot
         if (s_slot < 0 || s_slot >= k->wslots)
         {
            debug (DB_LOG, "want to send B pkt error s_slot", 0, s_slot);
            debug (DB_LOG, "  k->s_seq", 0, k->s_seq);
            return (X_ERROR);
         }
         k->s_pw[k->s_seq] = s_slot;

         debug (DB_LOG, "sending B pkt k->s_seq", 0, k->s_seq);
         debug (DB_LOG, "  s_slot", 0, s_slot);

         if ((rc = spkt ('B', k->s_seq, 0, (UCHAR *) 0, k)) != X_OK)
         {
            return (rc);        /* Send EOT packet */
         }
         k->state = S_EOT;      /* Wait for ACK to B packet, end of transmission */
         r->rstatus = S_EOT;
      }
      k->r_seq = k->s_seq;      /* Sequence number of packet we want */
      return (X_OK);            /* Return to control program */

   case S_FILE:                /* Got ACK to F packet */
      nxtpkt (k);               /* Get next packet number etc */
      if (k->capas & CAP_AT)
      {                         /* A-packets negotiated? */
         if ((rc = sattr (k, r)) != X_OK)       /* Yes, send Attribute packet */
         {
            debug (DB_LOG, "SATTR failed rc", 0, rc);
            return (rc);
         }
         k->state = S_ATTR;     /* And wait for its ACK */
         r->rstatus = S_ATTR;
         did_a_pkt = 1;
      }
      else
      {
         did_a_pkt = 0;
      }

      if (did_a_pkt == 0)
      {
         /* No A packets - send first data */

         buf = get_sslot (k, &s_slot);  // get a new send slot
         k->s_pw[k->s_seq] = s_slot;

         debug (DB_LOG, "sending first D k->s_seq", 0, k->s_seq);
         debug (DB_LOG, "  s_slot", 0, s_slot);

         rc = sdata (k, r);     /* Send next data packet */
         if (rc == X_ERROR)
            return (rc);
         if (rc == 0)
         {
            /* File is empty so send EOF packet */
            buf = get_sslot (k, &s_slot);       // get a new send slot
            k->s_pw[k->s_seq] = s_slot;
            debug (DB_LOG, "empty file: sending Z pkt k->s_seq", 0, k->s_seq);
            debug (DB_LOG, "  s_slot", 0, s_slot);
            if ((rc = spkt ('Z', k->s_seq, 0, (UCHAR *) 0, k)) != X_OK)
            {
               return (rc);
            }
            k->closef (k, 0, 1);        /* Close input file */
            k->state = S_EOF;   /* Wait for ACK to EOF */
            r->rstatus = S_EOF;
         }
         else
         {                      /* Sent some data */
            k->state = S_DATA;  /* Wait for ACK to first data */
            r->rstatus = S_DATA;
         }
      }                         // if(did_a_pkt==0)

      k->r_seq = k->s_seq;      /* Sequence number to wait for */
      return (X_OK);

   case S_ATTR:                /* Got ACK to A packet */
   case S_DATA:                /* Got ACK to D packet */
      if (k->state == S_ATTR)
      {
         /*
          * CHECK ATTRIBUTE RESPONSE 
          */
         /*
          * IF REJECTED do the right thing...
          * Left as an exersise for the reader...
          */
         k->state = S_DATA;
         r->rstatus = S_DATA;
      }

      buf = get_sslot (k, &s_slot);     // get a new send slot
      if (s_slot < 0)
      {
         debug (DB_LOG, "window full k->state", 0, k->state);
         k->sw_full = 1;
         return (X_OK);
      }
      nxtpkt (k);               /* Get next packet number */
      k->s_pw[k->s_seq] = s_slot;

      k->sw_full = 0;

      debug (DB_LOG, "S_DATA sending k->s_seq", 0, k->s_seq);
      debug (DB_LOG, "  s_slot", 0, s_slot);

      rc = sdata (k, r);        /* Send first or next data packet */

      debug (DB_LOG, "S_DATA sdata rc", 0, rc);
      debug (DB_LOG, "  k->s_seq", 0, k->s_seq);

      if (rc == X_ERROR)
         return (rc);

      if (rc == 0)
      {                         /* If there was no data to send */
         k->closef (k, 0, 1);   /* Close input file */

         debug (DB_LOG, "NUSED_SSLOTS", 0, nused_sslots (k));

         k->state = S_EOF;      /* And wait for ACK to Z pkt */
         r->rstatus = S_EOF;

         // sdata() above did not send D pkt so send Z pkt in its place
         debug (DB_LOG, "EOF so sending Z pkt k->s_seq", 0, k->s_seq);
         debug (DB_LOG, "  s_slot", 0, s_slot);

         if ((rc = spkt ('Z', k->s_seq, 0, (UCHAR *) 0, k)) != X_OK)
            return (rc);

      }                         /* Otherwise stay in data state */
      k->r_seq = k->s_seq;      /* Sequence number to wait for */
      return (X_OK);

   case S_EOT:                 /* Get ACK to EOT packet */
      debug (DB_MSG, "S_EOT X_DONE", 0, 0);
      return (X_DONE);          /* (or X_ERROR) */

   case R_WAIT:                /* Waiting for the S packet */
      debug (DB_CHR, "R_WAIT rtyp", 0, rtyp);
      debug (DB_LOG, "  rseq", 0, rseq);
      debug (DB_LOG, "  what", 0, k->what);
      if (rtyp == 'S')
      {                         /* Got it */
         spar (k, pdf, datalen);        /* Set parameters from it */

         debug (DB_MSG, "R_WAIT rtyp==S after spar", 0, 0);
         debug (DB_CHR, "  Parity", 0, k->parity);
         debug (DB_LOG, "  Ebqflg", 0, k->ebqflg);
         debug (DB_CHR, "  Ebq", 0, k->ebq);

         rc = rpar (k, 'Y');    /* ACK with my parameters */

         debug (DB_LOG, "R_WAIT rtyp==S after rpar rc", 0, rc);
         debug (DB_LOG, "  k->capas & CAP_LP", 0, k->capas & CAP_LP);
         debug (DB_LOG, "  k->capas & CAP_SW", 0, k->capas & CAP_SW);
         debug (DB_LOG, "  k->capas & CAP_AT", 0, k->capas & CAP_AT);
         debug (DB_LOG, "  k->capas & CAP_RS", 0, k->capas & CAP_RS);
         debug (DB_LOG, "  k->capas & CAP_LS", 0, k->capas & CAP_LS);
         debug (DB_CHR, "  k->ebq           ", 0, k->ebq);
         debug (DB_LOG, "  k->ebqflg        ", 0, k->ebqflg);
         debug (DB_LOG, "  k->parity        ", 0, k->parity);
         debug (DB_LOG, "  k->s_eom         ", 0, k->s_eom);
         debug (DB_LOG, "  k->r_timo        ", 0, k->r_timo);
         debug (DB_LOG, "  k->s_timo        ", 0, k->s_timo);
         debug (DB_CHR, "  k->r_ctlq        ", 0, k->r_ctlq);
         debug (DB_CHR, "  k->s_ctlq        ", 0, k->s_ctlq);
         debug (DB_CHR, "  k->rptq          ", 0, k->rptq);
         debug (DB_LOG, "  k->rptflg        ", 0, k->rptflg);
         debug (DB_LOG, "  k->bct           ", 0, k->bct);
         debug (DB_LOG, "  k->bcta3           ", 0, k->bcta3);
         debug (DB_LOG, "  k->r_maxlen      ", 0, k->r_maxlen);
         debug (DB_LOG, "  k->s_maxlen      ", 0, k->s_maxlen);
         debug (DB_LOG, "  k->wslots        ", 0, k->wslots);
         debug (DB_LOG, "  k->binary        ", 0, k->binary);
         debug (DB_LOG, "  k->retry         ", 0, k->retry);

         if (rc != X_OK)
         {
            debug (DB_MSG, "R_WAIT error rpar(Y) failed", 0, 0);
            return (X_ERROR);   /* I/O error, quit. */
         }
         k->state = R_FILE;     /* All OK, switch states */
         r->rstatus = R_FILE;
         k->what = W_RECV;
      }
      else if (k->what == W_GET)
      {
         debug (DB_MSG, "  what==W_GET so resending R-packet", 0, 0);
         rc = resend (k, 0);
      }
      else
      {
         debug (DB_MSG, "  unexpected packet so send NAK for seq 0", 0, 0);
         rc = nak (k, 0, -1);
      }
      if (rc != X_OK)
         debug (DB_LOG, "R_WAIT rc not X_OK: rc", 0, rc);
      return (rc);

   case R_FILE:                /* Want an F or B packet, may get Z and S pkt */
      debug (DB_CHR, "R_FILE rtyp", 0, rtyp);
      if (rtyp == 'F')
      {                         /* File name */
         if ((rc = decode (k, r, 0, pdf, -1)) == X_OK)  /* Decode and save */
            k->state = R_ATTR;  /* Switch to next state */
         r->rstatus = k->state;
         debug (DB_LOG, "R_FILE decode rc", 0, rc);
         debug (DB_LOG, "R_FILE FILENAME", r->filename, 0);
         if (rc == X_OK)
         {                      /* All OK so far */
            r->filedate[0] = '\0';      /* No file date yet */
            r->filesize = 0L;   /* Or file size */
            r->sofar = 0L;      /* Or bytes transferred yet */
            r->sofar_rumor = 0L;        /* Or bytes transferred yet */
            rc = ack (k, rseq, r->filename);    /* so ACK the F packet */
         }
         else
         {
            epkt ("eksw Filename error", k);    /* Error decoding filename */
            return (rc);
         }
      }
      else if (rtyp == 'B')
      {                         /* Break, end of transaction */
//       Extra ACKs to insure they heard the ACK to their B-packet.
//       But they send extra NAKs in response.
//       ack (k, rseq, (UCHAR *) 0);
//       ack (k, rseq, (UCHAR *) 0);
         rc = (ack (k, rseq, (UCHAR *) 0) == X_OK) ? X_DONE : X_ERROR;
      }
      else if (rtyp == 'Z')
      {                         /* End of file again */
         rc = ack (k, rseq, (UCHAR *) 0);
      }
      else if (rtyp == 'S')
      {                         /* got S pkt again */
         spar (k, pdf, datalen);        /* Set parameters from it */

         debug (DB_MSG, "R_FILE rtyp==S again", 0, 0);
         debug (DB_CHR, "  Parity", 0, k->parity);
         debug (DB_LOG, "  Ebqflg", 0, k->ebqflg);
         debug (DB_CHR, "  Ebq", 0, k->ebq);

         rc = rpar (k, 'Y');    /* ACK with my parameters */

         debug (DB_LOG, "R_FILE after rpar rc", 0, rc);
         if (rc != X_OK)
         {
            debug (DB_MSG, "R_FILE error rpar(Y) failed", 0, 0);
            return (X_ERROR);   /* I/O error, quit. */
         }
         k->state = R_FILE;     /* All OK, switch states */
         r->rstatus = R_FILE;
         k->what = W_RECV;
      }
      else
      {
         rc = X_ERROR;
      }
      debug (DB_LOG, "rc", 0, rc);
      return (rc);

   case R_ATTR:                /* Want A, D, or Z packet */
      debug (DB_CHR, "R_ATTR rtyp", 0, rtyp);
      if (rtyp == 'A')
      {                         /* Attribute packet */
         int x;
         x = gattr (k, pdf, r); /* Read the attributes */
         if (x > -1)
            k->binary = x;
         ack (k, rseq, (UCHAR *) "Y");  /* Always accept the file */
         return (X_OK);
      }
      else if (rtyp == 'D')
      {                         /* First data packet */
         k->obufpos = 0;        /* Initialize output buffer */
         k->filename = r->filename;
         r->sofar = 0L;
         r->sofar_rumor = 0L;
         if ((rc = (*(k->openf)) (k, r->filename, 2)) == X_OK)
         {
            k->state = R_DATA;  /* Switch to Data state */
            r->rstatus = k->state;
            rc = handle_good_rpkt (k, r, rseq, pdf);
         }
         else
         {
            debug (DB_MSG, "eksw cannot open output file", 0, 0);
            epkt ("eksw cannot open output file", k);
            return (rc);
         }

         if (rc == X_OK)
         {
         }
         else
         {
            debug (DB_MSG, "eksw Error writing data to file", 0, 0);
            epkt ("eksw Error writing data to file", k);
         }
         return (rc);
      }
      else if (rtyp == 'Z')
      {                         /* Empty file */
         debug (DB_LOG, "R_ATTR empty file", r->filename, 0);
         k->obufpos = 0;        /* Initialize output buffer */
         k->filename = r->filename;
         r->sofar = 0L;         /* Open and close the file */
         r->sofar_rumor = 0L;   /* Open and close the file */
         if ((rc = (*(k->openf)) (k, r->filename, 2)) == X_OK)
         {
            if (((rc = (*(k->closef)) (k, *pdf, 2)) == X_OK))
            {
               k->state = R_FILE;
               rc = ack (k, rseq, s);
            }
            else
            {
               debug (DB_MSG, "eksw Error closing empty file", 0, 0);
               epkt ("eksw Error closing empty file", k);
               return (rc);
            }
         }
         else
         {
            debug (DB_LOG, "eksw File refused or cannot be opened rc", 0, rc);
            epkt ("eksw File refused or cannot be opened", k);
            return (rc);
         }
         r->rstatus = k->state;
         return (X_OK);
      }
      else if (rtyp == 'F')     // received F pkt again
      {
         ack (k, rseq, (UCHAR *) 0);
         return (X_OK);
      }
      else
      {
         debug (DB_CHR, "R_ATTR error 3 unexpected packet rtyp", 0, rtyp);
         epkt ("eksw R_ATTR error 3 unexpected packet type", k);
//       exit (1);
         return (X_ERROR);
      }
//    break;

   case R_DATA:                /* Want a D or Z packet */
      debug (DB_CHR, "R_DATA rtyp", 0, rtyp);
      debug (DB_LOG, "R_DATA rseq", 0, rseq);
      if (rtyp == 'D')
      {                         /* Data */
         rc = handle_good_rpkt (k, r, rseq, pdf);
         debug (DB_LOG, "R_DATA hgr rc", 0, rc);
      }
      else if (rtyp == 'Z')
      {                         /* End of file */
         debug (DB_LOG, "R_DATA Z pkt obufpos", 0, k->obufpos);
         flush_to_file (k, r);
         if (((rc = (*(k->closef)) (k, *pdf, 2)) == X_OK) && (rc == X_OK))
            k->state = R_FILE;
         debug (DB_LOG, "R_DATA closef rc", 0, rc);
         r->rstatus = k->state;
      }
      else
      {
         debug (DB_CHR, "R_DATA error 4 unexpected packet rtyp", 0, rtyp);
         epkt ("eksw error 4 unexpected packet type", k);
//       exit (1);
         return (X_ERROR);
      }

      if (rc == X_OK)
      {
         if (rtyp == 'Z')
         {
            rc = ack (k, rseq, s);      // usual ACK to D or Z packet
         }
      }
      else
      {
         debug (DB_CHR, "Error 12: rc != X_OK rtyp", 0, rtyp);
         epkt (rtyp == 'Z' ? "eksw Can't close file" : "eksw hgr failed", k);
      }

      return (rc);

   case R_ERROR:               /* Canceled from above */
      debug (DB_LOG, "R_ERROR error so sending E pkt k->state", 0, k->state);
      epkt (msg, k);
      return (X_ERROR);

   default:
      debug (DB_LOG, "default error so sending E pkt k->state", 0, k->state);
      epkt (msg, k);
      return (X_ERROR);
   }

   // not supposed to get here
// debug (DB_LOG, "Kermit logic error k->state", 0, k->state);
// exit (1);
// return (X_ERROR);            /* make compiler happy */
}
