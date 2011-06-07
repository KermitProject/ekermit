typedef unsigned char uchar;

/*
 * Embedded Kermit demo, main program.  
 */

/*
 * Author: Frank da Cruz, the Kermit Project, Columbia University, New
 * York. Copyright (C) 1995, 2002, Trustees of Columbia University in the 
 * City of New York. All rights reserved. 
 * For license see kermit.c.
 */

/*
 * This is a demo/test framework, to be replaced by a real control
 * program. It includes a simple Unix-style command-line parser to allow
 * setup and testing of the Kermit module.  Skip past all this to where it 
 * says REAL STUFF to see the real stuff.  ANSI C required.  Note: order
 * of the following includes is important. 
 */

#ifdef __linux
#include <stdlib.h>             // for exit()
#include <unistd.h>             // for access()
#include <ctype.h>              // for isdigit()
#include <errno.h>
#endif /* __linux */

// handle name clash
#ifdef X_OK
#undef X_OK
#endif

#include "cdefs.h"              /* Data types for all modules */
#include "debug.h"              /* Debugging */
#include "platform.h"           /* Platform-specific includes and
                                 * definitions */
#include "kermit.h"             /* Kermit symbols and data structures */
#include "string.h"

/*
 * Sample prototypes for i/o functions. The functions are defined in a
 * platform-specific i/o module. The function names are unknown to the
 * Kermit module. The names can be changed but not their calling
 * conventions. The following prototypes are keyed to unixio.c. 
 */
int devopen (char *, long baud);        /* Communications device/path */
int devsettings (char *);
int devrestore (void);
int devclose (void);
int pktmode (short);

int readpkt (struct k_data *, UCHAR *, int);    /* Communications 
                                                 * i/o functions */
int tx_data (struct k_data *, UCHAR *, int);
int inchk (struct k_data *);

int openfile (struct k_data *, UCHAR *, int);   /* File i/o
                                                 * functions */
int writefile (struct k_data *, UCHAR *, int);
int readfile (struct k_data *);
int closefile (struct k_data *, UCHAR, int);
ULONG fileinfo (struct k_data *, UCHAR *, UCHAR *, int, short *, short);

/*
 * External data 
 */

extern UCHAR o_buf[];           /* Must be defined in io.c */
extern UCHAR i_buf[];           /* Must be defined in io.c */
extern int errno;

/*
 * Data global to this module 
 */

struct k_data k;                /* Kermit data structure */
struct k_response r;            /* Kermit response structure */

char **xargv;                   /* Global pointer to arg vector */
UCHAR **cmlist = (UCHAR **) 0;  /* Pointer to file list */
char *xname = "eksw";           /* Default program name */

int xargc;                      /* Global argument count */
int nfils = 0;                  /* Number of files in file list */
int action = 0;                 /* Send or Receive */
int xmode = 1;                  /* File-transfer mode */
int ftype = 1;                  /* Global file type 0=text 1=binary */
int keep = 0;                   /* Keep incompletely received files */
int sync_server = 0;            /* Sync a server with E-pkt */
int dbg = 0;                    /* Debugging */
short fmode = -1;               /* Transfer mode for this file */
int parity = 0;                 /* Parity */
int check = 3;                  /* Block check */
int remote = 1;                 /* 1 = Remote, 0 = Local */

#ifdef DEBUG
int errorrate = 0;              /* Simulated error rate */
int seed = 1234;                /* Random number generator seed */
#endif /* DEBUG */

void
doexit (int status)
{
   devrestore ();               /* Restore device */
   devclose ();                 /* Close device */
   exit (status);               /* Exit with indicated status */
}

void
usage ()
{
   fprintf (stderr, "E-Kermit %s\n", VERSION);
   fprintf (stderr, "Usage: %s <options>\n", xname);
   fprintf (stderr, "Options:\n");
   fprintf (stderr, " -r           Receive files\n");
   fprintf (stderr, " -g <files>   Get files\n");
   fprintf (stderr, " -s <files>   Send files\n");
   fprintf (stderr, " -w <number>  # of window slots\n");
   fprintf (stderr, " -l <number>  packet length\n");
   fprintf (stderr, " -p [neoms]   Parity: none, even, odd, mark, space\n");
   fprintf (stderr, " -b [1235]     Block check type: 1, 2, 3 or 5\n");
   fprintf (stderr, " -k           Keep incompletely received files\n");
   fprintf (stderr, " -B           Force binary mode\n");
   fprintf (stderr, " -T           Force text mode\n");
   fprintf (stderr, " -R           Remote mode (vs local)\n");
   fprintf (stderr, " -L           Local mode (vs remote)\n");
#ifdef DEBUG
   fprintf (stderr, " -E <number>  Simulated error rate (0-100)\n");
   fprintf (stderr, " -d           debugging output to \"debug.log\"\n");
#endif /* DEBUG */
   fprintf (stderr, " -S           Synchronize a kermit server\n");
   fprintf (stderr, " -h           Help (this message)\n");
   doexit (FAILURE);
}

void static
fatal (char *msg1, char *msg2, char *msg3)
{                               /* Not to be called except */
   if (msg1)
   {                            /* from this module */
      fprintf (stderr, "%s: %s", xname, msg1);
      if (msg2)
         fprintf (stderr, "%s", msg2);
      if (msg3)
         fprintf (stderr, "%s", msg3);
      fprintf (stderr, "\n");
   }
   doexit (FAILURE);
}

/*
 * Simple user interface for testing 
 */

int
doarg (char c)
{                               /* Command-line option parser */
   int x;                       /* Parses one option with its arg(s) */
   char *xp, *s;
   struct stat statbuf;

   xp = *xargv + 1;             /* Pointer for bundled args */
   while (c)
   {
#ifdef DEBUG
      if (errorrate)
         seed += (int) c;
#endif /* DEBUG) */
      switch (c)
      {
      case 'r':                /* Receive */
         if (action)
            fatal ("Conflicting actions", (char *) 0, (char *) 0);
         action = A_RECV;
         break;

      case 'g':                /* Get */
         if (action)
            fatal ("Conflicting actions", (char *) 0, (char *) 0);
         if (*(xp + 1))
            fatal ("Invalid argument bundling after -g", (char *) 0,
                   (char *) 0);
         nfils = 0;             /* Initialize file counter, flag */
         cmlist = (UCHAR **) (xargv + 1);       /* Remember this pointer */
         while (--xargc > 0)
         {                      /* Traverse the list */
            xargv++;
            s = *xargv;
#ifdef DEBUG
            if (errorrate)
               seed += (int) *s;
#endif /* DEBUG) */
            if (**xargv == '-')
               break;
            errno = 0;
            nfils++;
         }
         xargc++;
         xargv--;               /* Adjust argv/argc */
         if (nfils < 1)
            fatal ("Missing filename for -g", (char *) 0, (char *) 0);
         action = A_GET;
         break;

      case 's':                /* Send */
         if (action)
            fatal ("Conflicting actions", (char *) 0, (char *) 0);
         if (*(xp + 1))
            fatal ("Invalid argument bundling after -s", (char *) 0,
                   (char *) 0);
         nfils = 0;             /* Initialize file counter, flag */
         cmlist = (UCHAR **) (xargv + 1);       /* Remember this pointer */
         while (--xargc > 0)
         {                      /* Traverse the list */
            xargv++;
            s = *xargv;
#ifdef DEBUG
            if (errorrate)
               seed += (int) *s;
#endif /* DEBUG) */
            if (**xargv == '-')
               break;
            errno = 0;
            x = stat (s, &statbuf);
            if (x < 0)
               fatal ("File '", s, "' not found");
            if (access (s, 4) < 0)
               fatal ("File '", s, "' not accessible");
            nfils++;
         }
         xargc++;
         xargv--;               /* Adjust argv/argc */
         if (nfils < 1)
            fatal ("Missing filename for -s", (char *) 0, (char *) 0);
         action = A_SEND;
         break;

      case 'b':                /* Block-check type */
#ifdef DEBUG
      case 'E':                /* Simulated error rate */
#endif /* DEBUG */
      case 'w':                /* max window slots */
      case 'l':                /* max packet length */
         if (*(xp + 1))
            fatal ("Invalid argument bundling", (char *) 0, (char *) 0);
         xargv++, xargc--;
         if ((xargc < 1) || (**xargv == '-'))
            fatal ("Missing option argument", (char *) 0, (char *) 0);
         s = *xargv;
         while (*s)
         {
            if (!isdigit (*s))
               fatal ("Numeric argument required", (char *) 0, (char *) 0);
            s++;
         }
         if (c == 'b')
         {
            check = atoi (*xargv);
            if ((check < 1 || check > 3) && check != 5)
               fatal ("Invalid block check", (char *) 0, (char *) 0);
         }
#ifdef DEBUG
         else if (c == 'E')
         {
            errorrate = atoi (*xargv);
            if (errorrate > 100)
               fatal ("Invalid error rate", (char *) 0, (char *) 0);
         }
#endif /* DEBUG */
         else if (c == 'w')
         {
            // maximum number of window slots to negotiate
            k.wslots_max = atoi (*xargv);
            if (k.wslots_max == 0)
               k.wslots_max = 1;
            if (k.wslots_max < 1 || k.wslots_max > P_WSLOTS)
               fatal ("Invalid no. of window slots", (char *) 0, (char *) 0);
         }
         else if (c == 'l')
         {
            int maxlen;
            // maximum packet lengths
            maxlen = atoi (*xargv);
            if (maxlen < 10 || maxlen > P_PKTLEN)
               fatal ("Invalid packet maxlen", (char *) 0, (char *) 0);
            k.p_maxlen = maxlen;
         }
         break;

      case 'h':                /* Help */
      case '?':
         usage ();

      case 'B':                /* Force binary file transfer */
         xmode = 1;             /* So no automatic switching */
         ftype = BINARY;
         break;

      case 'T':                /* Force text file transfer */
         xmode = 1;             /* So no automatic switching */
         ftype = TEXT;
         break;

      case 'R':                /* Tell Kermit it's in remote mode */
         remote = 1;
         break;

      case 'L':                /* Tell Kermit it's in local mode */
         remote = 0;
         break;

      case 'k':                /* Keep incompletely received files */
         keep = 1;
         break;

      case 'S':                /* Synchronize a server by sending E-packet */
         sync_server = 1;
         break;

      case 'p':                /* Parity */
         if (*(xp + 1))
            fatal ("Invalid argument bundling", (char *) 0, (char *) 0);
         xargv++, xargc--;
         if ((xargc < 1) || (**xargv == '-'))
            fatal ("Missing parity", (char *) 0, (char *) 0);
         switch (x = **xargv)
         {
         case 'e':             /* Even */
         case 'o':             /* Odd */
         case 'm':             /* Mark */
         case 's':
            parity = x;
            break;              /* Space */
         case 'n':
            parity = 0;
            break;              /* None */
         default:
            fatal ("Invalid parity '", *xargv, "'");
         }
         break;

#ifdef DEBUG
      case 'd':
         dbg++;
         break;
#else
      case 'd':
         fprintf (stderr, "ignoring -d flag -- debugging code not present\n");
         break;
#endif /* DEBUG */

      default:                 /* Anything else */
         fatal ("Unknown command-line option ", *xargv,
                " type 'eksw -h' for help.");
      }
      c = *++xp;                /* See if options are bundled */
   }
   return (action);
}

int
main (int argc, char **argv)
{
   int loop;

   int status, rx_len = 0, xact;
   char c;
   UCHAR *inbuf;
   char ttyname[100];
   long baud;

#if 0
   fprintf (stderr, "MAIN Options:\n");
   fprintf (stderr, " IBUFLEN=%d\n", IBUFLEN);
   fprintf (stderr, " OBUFLEN=%d\n", OBUFLEN);
   fprintf (stderr, " IDATALEN=%d\n", IDATALEN);
   fprintf (stderr, " P_PKTLEN=%d\n", P_PKTLEN);
   fprintf (stderr, " P_WSLOTS=%d\n", P_WSLOTS);
//      fprintf (stderr, " F_SW\n");
//      fprintf (stderr, " F_SSW\n");
//      fprintf (stderr, " F_TSW\n");
#endif

   k.wslots_max = 1;            // default to use one window slot
   k.p_maxlen = P_PKTLEN;

   parity = P_PARITY;           /* Set this to desired parity */
   status = X_OK;               /* Initial kermit status */

   if (argc == 1)
   {
      fprintf (stderr, "usage: eksw [tty baud] [options]\n");
      exit (1);
   }

   if (argv[1][0] == '-')
   {
      strncpy (ttyname, "stdin", sizeof (ttyname) - 1);
      baud = 0;

      xargc = argc;
      xargv = argv;
   }
   else
   {
      strncpy (ttyname, argv[1], sizeof (ttyname) - 1);
      baud = atol (argv[2]);

      xargc = argc - 2;
      xargv = argv + 2;
   }

   xname = argv[0];

   while (--xargc > 0)
   {                            /* Loop through command-line words */
      xargv++;
      if (**xargv == '-')
      {                         /* Have dash */
         c = *(*xargv + 1);     /* Get the option letter */
         xact = doarg (c);      /* Go handle the option */
         if (xact < 0)
            doexit (FAILURE);
      }
      else
      {                         /* No dash where expected */
         fatal ("Malformed command-line option: '", *xargv, "'");
      }
   }
   if (!action)                 /* Nothing to do, give usage message */
      usage ();

//      fprintf(stderr,"dbg=%d\n",dbg);

   /*
    * THE REAL STUFF IS FROM HERE DOWN 
    */

   if (!devopen (ttyname, baud))        /* Open the communication device */
      doexit (FAILURE);
   if (!devsettings ("dummy"))  /* Perform any needed settings */
      doexit (FAILURE);
   if (dbg == 1)
   {                            /* Open debug log if requested */
//              fprintf(stderr,"opening debug.log without time stamps\n");
      debug (DB_OPN, "debug.log", 0, 0);
   }
   if (dbg == 2)
   {                            /* Open debug log with time stamps */
//              fprintf(stderr,"opening debug.log with time stamps\n");
      debug (DB_OPNT, "debug.log", 0, 0);
   }

   debug (DB_MSG, "MAIN Initializing...", 0, 0);

#ifdef DEBUG
   debug (DB_LOG, "MAIN SIMULATED ERROR RATE", 0, errorrate);
   if (errorrate)
      srand (seed);             /* Init random error generator */
#endif /* DEBUG */

   /*
    * Fill in parameters for this run 
    */

   k.send_pause_us = 1000000;
   k.send_pause_us = 0;
   k.baud = baud;

   k.xfermode = xmode;          /* Text/binary automatic/manual */
   k.remote = remote;           /* Remote vs local */
   k.binary = ftype;            /* 0 = text, 1 = binary */
   k.parity = parity;           /* Communications parity */
   if (check == 5)
   {
      k.bct = 3;                /* Block check type 3 for all packets */
      k.bcta3 = 1;
   }
   else
   {
      k.bct = check;            /* Block check type */
      k.bcta3 = 0;
   }
   k.ikeep = keep;              /* Keep incompletely received files */
   k.filelist = cmlist;         /* List of files to send (if any) */
   k.cancel = 0;                /* Not canceled yet */

   /*
    * Fill in the i/o pointers 
    */

   k.zinbuf = i_buf;            /* File input buffer */
   k.zinlen = IBUFLEN;          /* File input buffer length */
   k.zincnt = 0;                /* File input buffer position */
   k.obuf = o_buf;              /* File output buffer */
   k.obuflen = OBUFLEN;         /* File output buffer length */
   k.obufpos = 0;               /* File output buffer position */

   /*
    * Fill in function pointers 
    */

   k.rxd = readpkt;             /* for reading packets */
   k.txd = tx_data;             /* for sending packets */
   k.ixd = inchk;               /* for checking connection */
   k.openf = openfile;          /* for opening files */
   k.finfo = fileinfo;          /* for getting file info */
   k.readf = readfile;          /* for reading files */
   k.writef = writefile;        /* for writing to output file */
   k.closef = closefile;        /* for closing files */
#ifdef DEBUG
   k.dbf = dbg ? dodebug : 0;   /* for debugging */
#else
   k.dbf = 0;
#endif /* DEBUG */

   /*
    * Initialize Kermit protocol 
    */

   debug (DB_LOG, "MAIN action", 0, action);

   status = kermit (K_INIT, &k, 0, "eksw init", &r);
   debug (DB_LOG, "MAIN K_INIT kermit return status", 0, status);
   if (status == X_ERROR)
      doexit (FAILURE);

   if (sync_server)
   {
      // Send an E-pkt before starting protocol to reset a kermit server
      // The E-pkt will force an exit for simple send or receive kermits
      if (kermit (K_SYNC, &k, 0, "eksw sync", &r) == X_ERROR)
         doexit (FAILURE);
   }

   if (action == A_SEND)
      status = kermit (K_SEND, &k, 0, "eksw send", &r);
   if (action == A_GET)
      status = kermit (K_GET, &k, 0, "eksw get", &r);
   /*
    * Now we read a packet ourselves and call Kermit with it.  Normally,
    * Kermit would read its own packets, but in the embedded context, the 
    * device must be free to do other things while waiting for a packet
    * to arrive.  So the real control program might dispatch to other
    * types of tasks, of which Kermit is only one.  But in order to read
    * a packet into Kermit's internal buffer, we have to ask for a buffer 
    * address and slot number.
    * 
    * To interrupt a transfer in progress, set k.cancel to I_FILE to
    * interrupt only the current file, or to I_GROUP to cancel the
    * current file and all remaining files.  To cancel the whole
    * status, call Kermit with K_ERROR. 
    */
   loop = 0;
   while (status != X_DONE)
   {
      loop++;
      /*
       * Here we block waiting for a packet to come in (unless readpkt
       * times out). Another possibility would be to call inchk() to see 
       * if any bytes are waiting to be read, and if not, go do
       * something else for a while, then come back here and check
       * again. 
       */

      debug (DB_LOG, "MAIN -------------- loop", 0, loop);

      if (ok2rxd (&k))
      {
         inbuf = k.ipktbuf;

         rx_len = k.rxd (&k, inbuf, P_PKTLEN);  /* Try to read a packet */

         debug (DB_LOG, "MAIN rx_len", 0, rx_len);
         debug (DB_HEX, "MHEX", inbuf, rx_len);

         if (rx_len < 1)
         {                      /* No data was read */
            if (rx_len < 0)     /* If there was a fatal error */
               doexit (FAILURE);        /* give up */

            /*
             * This would be another place to dispatch to another task 
             * while waiting for a Kermit packet to show up. 
             */

         }
      }

      /*
       * Handle the input 
       *
       * For simplicity, kermit() ACKs the packet immediately after
       * verifying it was received correctly.  If, afterwards, the
       * control program fails to handle the data correctly (e.g. can't
       * open file, can't write data, can't close file), then it tells
       * Kermit to send an Error packet next time through the loop. 
       */

      status = kermit (K_RUN, &k, rx_len, "", &r);
      debug (DB_LOG, "MAIN K_RUN return status", 0, status);

      switch (status)
      {
      case X_OK:
         /*
          * This shows how, after each packet, you get the protocol
          * state, file name, date, size, and bytes transferred so far. 
          * These can be used in a file-transfer progress display, log, 
          * etc. 
          */
#if 0
         debug (DB_LOG, "NAME",
                r.filename ? (uchar *) r.filename : (uchar *) "(NULL)", 0);
         debug (DB_LOG, "DATE",
                r.filedate ? (uchar *) r.filedate : (uchar *) "(NULL)", 0);
         debug (DB_LOG, "SIZE", 0, r.filesize);
         debug (DB_LOG, "STATE", 0, r.status);
         debug (DB_LOG, "SOFAR", 0, r.sofar);
#endif
         /*
          * Maybe do other brief tasks here... 
          */
         continue;              /* Keep looping */
      case X_DONE:
         debug (DB_MSG, "MAIN X_DONE", 0, 0);
         break;                 /* Finished */
      case X_ERROR:
         debug (DB_MSG, "MAIN error", 0, 0);
         doexit (FAILURE);      /* Failed */
         break;
      default:
         debug (DB_LOG, "MAIN unknown status=%d", 0, status);
         break;
      }
   }
   doexit (SUCCESS);
   return (0);
}
