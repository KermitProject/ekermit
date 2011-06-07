#define SIMULATED_RTT 0

/*
 * Sample system-dependent communications i/o routines for embedded
 * Kermit. 
 */

/*
 * Author: Frank da Cruz. Copyright (C) 1995, 2004, Trustees of Columbia
 * University in the City of New York. All rights reserved. 
 * For license see kermit.c.
 */

/*
 * The sample i/o routines for UNIX that provide packet i/o functions on
 * the console (login) device. Copy this file, rename it appropriately,
 * and replace the contents of each routine appropriately for your
 * platform.
 * 
 * Device i/o:
 * 
 * int devopen() Communications device - open int pktmode() Communications 
 * device - enter/exit packet mode int readpkt() Communications device -
 * read a packet int tx_data() Communications device - send data int
 * devclose() Communications device - close int inchk() Communications
 * device - check if bytes are ready to read
 * 
 * File i/o:
 * 
 * int openfile() File - open for input or output ULONG fileinfo() Get
 * input file modtime and size int readfile() Input file - read data int
 * writefile() Output file - write data int closefile() Input or output
 * file - close
 * 
 * Full definitions below, prototypes in kermit.h.
 * 
 * These routines must handle speed setting, parity, flow control, file
 * i/o, and similar items without the kermit() routine knowing anything
 * about it. If parity is in effect, these routines must add it to
 * outbound characters and strip it from inbound characters. 
 */
#include <stdio.h>
#include <stdlib.h>             // for rand(), exit()
#include <unistd.h>             // for read(), write()
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#ifndef O_WRONLY
#include <sys/file.h>
#endif /* O_WRONLY */

#include <sys/select.h>
#include <termio.h>             /* for settty(), gettty() args */
#include <fcntl.h>              /* for open() args */
#include <string.h>             /* for str...() */

#include "sys/time.h"           // for gettimeofday()

#ifdef X_OK
#undef X_OK
#endif /* X_OK */

#include "./cdefs.h"
#include "./debug.h"
#include "./platform.h"
#include "./kermit.h"

UCHAR o_buf[OBUFLEN + 8];       /* File output buffer */
UCHAR i_buf[IBUFLEN + 8];       /* File output buffer */

/*
 * In this example, the output file is unbuffered to ensure that every
 * output byte is commited.  The input file, however, is buffered for
 * speed. This is just one of many possible implmentation choices,
 * invisible to the Kermit protocol module. 
 */
static int ttyfd = -1;
static int ofile = -1;          /* File descriptors */
static FILE *ifile = (FILE *) 0;        /* and pointers */

static FILE *ttyfp = 0;

void
fprintf_date (FILE * fp)
{
   struct timeval tvnow;
   struct timezone tz;
   struct tm tmnow;

   gettimeofday (&tvnow, &tz);
   localtime_r (&tvnow.tv_sec, &tmnow);

# if 0
   fprintf (fp, "%04d-%02d-%02d %02d:%02d:%02d.%06ld ",
            tmnow.tm_year + 1900,
            tmnow.tm_mon + 1,
            tmnow.tm_mday,
            tmnow.tm_hour, tmnow.tm_min, tmnow.tm_sec, tvnow.tv_usec);
# else
   fprintf (fp, "%02d:%02d:%02d.%03ld ",
            tmnow.tm_hour, tmnow.tm_min, tmnow.tm_sec, tvnow.tv_usec / 1000);
# endif

}

/*
 * Debugging 
 */

#ifdef DEBUG
static FILE *dp = (FILE *) 0;   /* Debug log */
static int xdebug = 0;          /* Debugging on/off */
static int tdebug = 0;

int
dodebug (int fc, UCHAR * label, UCHAR * sval, long nval)
{
   if (fc != DB_OPN && fc != DB_OPNT && !xdebug)
      return (-1);
   if (!label)
      label = (UCHAR *) "";

   switch (fc)
   {                            /* Function code */
   case DB_OPNT:
      tdebug = 1;
   case DB_OPN:                /* Open debug log */
      xdebug = 1;

//              fprintf(stderr,"DODEBUG fc=%d xdebug=%d tdebug=%d\n",
//                      fc,xdebug,tdebug);
//              if(label)
//                      fprintf(stderr,"DODEBUG label=[%s]\n",label); 

      if (!*label)
         dp = stderr;
      else
      {
         if (dp)
            fclose (dp);
         dp = fopen ((char *) label, "wt");
         if (!dp)
         {
            dp = stderr;
         }
         else
         {
            setbuf (dp, (char *) 0);    // cause dp to be unbuffered
         }
      }
      if (tdebug)
         fprintf_date (dp);
      if (*label)
      {
         fprintf (dp, "DEBUG LOG OPEN: %s\n", label);
      }
      else
      {
         fprintf (dp, "DEBUG LOG OPEN: %s\n", "stderr");
      }
      return (0);
   case DB_MSG:                /* Write a message */
      if (dp)
      {
         if (tdebug)
            fprintf_date (dp);
         fprintf (dp, "%s\n", (char *) label);
      }
      return (0);
   case DB_CHR:                /* Write label and character */
      if (dp)
      {
         if (tdebug)
            fprintf_date (dp);
         if (nval > 32 && nval < 127)
         {
            fprintf (dp, "%s=[%c]\n", (char *) label, (char) nval);
         }
         else
         {
            fprintf (dp, "%s=[%d decimal]\n", (char *) label, (char) nval);
         }
      }
      return (0);
   case DB_PKT:                /* Log a packet */
      if (!dp)
         return (0);
      if (sval)
      {
         int i;
         if (tdebug)
            fprintf_date (dp);
         fprintf (dp, "%s[", (char *) label);
         for (i = 0; sval[i] != 0; i++)
         {
            int c = sval[i];
            if (c >= 32 && c < 127)
               fprintf (dp, "%c", c);
            else if (c == '\\')
               fprintf (dp, "\\\\");
            else if (c == 0x0d)
               fprintf (dp, "\\r");
            else if (c == 0x0a)
               fprintf (dp, "\\n");
//          else if (c == '^')
//             fprintf (dp, "\\^");
//          else if (c >= 1 && c <= 26)
//             fprintf (dp, "^%c",c + 64);
            else
               fprintf (dp, "[%02x]", c);
         }
         fprintf (dp, "]\n");
      }
      else
      {
         if (tdebug)
            fprintf_date (dp);
         fprintf (dp, "%s=%ld\n", (char *) label, nval);
      }
      return (0);

   case DB_HEX:                /* Log data in hex */
      if (!dp)
         return (0);
      if (sval)
      {
         int i;
         if (tdebug)
            fprintf_date (dp);
         fprintf (dp, "%s[", (char *) label);
         for (i = 0; i < nval; i++)
         {
            int c = sval[i];
            if (i > 0)
               fprintf (dp, " ");
            fprintf (dp, "%02x", c);
         }
         fprintf (dp, "]\n");
         fprintf (dp, "  i=%d, nval=%ld\n", i, nval);
      }
      else
      {
         if (tdebug)
            fprintf_date (dp);
         fprintf (dp, "%s=%ld\n", (char *) label, nval);
      }
      return (0);

   case DB_LOG:                /* Write label and string or number */
      if (tdebug)
         fprintf_date (dp);
      if (sval && dp)
         fprintf (dp, "%s[%s]\n", (char *) label, sval);
      else
         fprintf (dp, "%s=%ld\n", (char *) label, nval);
      return (0);
   case DB_CLS:                /* Close debug log */
      if (dp)
      {
         fclose (dp);
         dp = (FILE *) 0;
      }
      xdebug = 0;
   }
   return (-1);
}
#endif /* DEBUG */

/*
 * D E V O P E N -- Open communications device 
 */
/*
 * 
 * Call with: string pointer to device name.  This routine should get the
 * current device settings and save them so devclose() can restore them.
 * It should open the device.  If the device is a serial port, devopen()
 * set the speed, stop bits, flow control, etc. Returns: 0 on failure, 1
 * on success. 
 */

int
devopen (char *ttyname, long baud)
{
   static struct termios settty;
   int ret;
   int baudflag;

   ttyfp = 0;

   if (strcmp (ttyname, "stdin") == 0)
   {
      ttyfd = 0;
      ttyfp = stdin;
      return (1);
   }

   switch (baud)
   {
   case 2400:
      baudflag = B2400;
      break;
   case 4800:
      baudflag = B4800;
      break;
   case 9600:
      baudflag = B9600;
      break;
   case 19200:
      baudflag = B19200;
      break;
   case 38400:
      baudflag = B38400;
      break;
   case 57600:
      baudflag = B57600;
      break;
   case 115200:
      baudflag = B115200;
      break;
   default:
      fprintf (stderr, "unimplemented baud=%ld\n", baud);
      return (-1);
      break;
   }

   if ((ttyfd = open (ttyname, O_RDWR | O_NDELAY)) < 0)
   {
      perror ("devopen(): serial port open failed");
      fprintf (stderr, "ttyname=\"%s\"\n", ttyname);
      return (-1);
   }

   settty.c_iflag = 0;
   settty.c_oflag = 0;
   settty.c_cflag = 0;
   settty.c_lflag = 0;

   cfmakeraw (&settty);

   settty.c_cflag |= CLOCAL;    /* ignore modem control lines */
   settty.c_cflag &= ~CRTSCTS;  /* no flow control */
   settty.c_cflag |= CREAD;     // added June 21, 2002 per new tty driver

   cfsetispeed (&settty, baudflag);
   cfsetospeed (&settty, baudflag);

   ret = tcsetattr (ttyfd, TCSANOW, &settty);
   if (ret < 0)
   {
      perror ("devopen(): tcsetattr() serial port failed");
      fprintf (stderr, "ttyname=\"%s\"\n", ttyname);
      return (-1);
   }

   if ((ttyfp = fdopen (ttyfd, "r+")) == 0)
   {
      fprintf (stderr, "fdopen(ttyfd) failed\n");
      return (-1);
   }

   return (1);
}

/*
 * P K T M O D E -- Put communications device into or out of packet mode 
 */
/*
 * Call with: 0 to put in normal (cooked) mode, 1 to put in packet (raw)
 * mode. For a "dumb i/o device" like an i/o port that does not have a
 * login attached to it, this routine can usually be a no-op. Returns: 0
 * on failure, 1 on success. 
 */
int
pktmode (short on)
{
   if (ttyfd < 0)               /* Device must be open */
      return (0);
   if (ttyfd == 0)
      system (on ? "stty raw -echo" : "stty sane");     /* Crude but effective */
   return (1);
}


/*
 * D E V S E T T I N G S 
 */

int
devsettings (char *s)
{
   /*
    * Get current device settings, save them for devrestore() 
    */
   /*
    * Parse string s, do whatever it says, e.g. "9600;8N1" 
    */
   if (!pktmode (ON))           /* And put device in packet mode */
      return (0);
   return (1);
}

/*
 * D E V R E S T O R E 
 */

int
devrestore (void)
{
   /*
    * Put device back as we found it 
    */
   pktmode (OFF);
   return (1);
}


/*
 * D E V C L O S E -- Closes the current open communications device 
 */
/*
 * Call with: nothing Closes the device and puts it back the way it was
 * found by devopen(). Returns: 0 on failure, 1 on success. 
 */
int
devclose (void)
{
   if (ttyfd > 0)               // ttyfd == 0 when device == "stdin"
   {
      fclose (ttyfp);
      close (ttyfd);            // may be superfluous
   }
   ttyfd = -1;
   ttyfp = 0;
   return (1);
}

/*
 * I N C H K -- Check if input waiting 
 */

/*
 * Check if input is waiting to be read, needed for sliding windows.  This
 * sample version simply looks in the stdin buffer (which is not portable
 * even among different Unixes).  If your platform does not provide a way
 * to look at the device input buffer without blocking and without actually
 * reading from it, make this routine return (-1).  On success, returns the
 * numbers of characters waiting to be read, i.e. that can be safely read
 * without blocking. 
 */
int
inchk (struct k_data *k)
{
   int n;
   FILE *ttyfp = 0;

   if (ttyfd < 0)               /* Device must be open */
      return (0);

   if (ttyfd == 0)
   {
      ttyfp = stdin;
   }
   else
   {
   }

#ifdef _IO_file_flags           /* Linux */
   n = ttyfp->_IO_read_end - ttyfp->_IO_read_ptr;
#else
#ifdef AIX                      /* AIX */
   n = ttyfp->_cnt;
#else
#ifdef SunOS                    /* Solaris and SunOS */
   n = ttyfp->_cnt;
#else
#ifdef HPUX                     /* HPUX */
   n = ttyfp->__cnt;
#else
   n = -1;
#endif /* HPUX */
#endif /* SunOS */
#endif /* AIX */
#endif /* _IO_file_flags */

   return (n);
}

/*
 * R E A D P K T -- Read a Kermit packet from the communications device 
 */
/*
 * Call with: k - Kermit struct pointer p - pointer to read buffer len -
 * length of read buffer
 * 
 * When reading a packet, this function looks for start of Kermit packet
 * (k->r_soh), then reads everything between it and the end of the packet
 * (k->r_eom) into the indicated buffer.  Returns the number of bytes
 * read, or: 0 - timeout or other possibly correctable error; -1 - fatal
 * error, such as loss of connection, or no buffer to read into. 
 */

int
readpkt (struct k_data *k, UCHAR * p, int len, int fc)
{
   int x = 0, n;
   short flag;
   UCHAR c;

   /*
    * Although it is not be needed in many cases,
    * timeout is implemented in this sample because Iridium modems seem
    * to get stuck occasionally and C-Kermit timeout action from the
    * other end of the
    * connection doesn't seem to be able to break the deadlock.
    */

#ifdef F_CTRLC
   short ccn;
   ccn = 0;
#endif /* F_CTRLC */

   debug (DB_LOG, "READPKT ttyfd", 0, ttyfd);
   debug (DB_LOG, "  unused len", 0, len);
   debug (DB_LOG, "  used k->r_maxlen", 0, k->r_maxlen);
   debug (DB_LOG, "  k->r_timo", 0, k->r_timo);
   debug (DB_LOG, "  ttyfd", 0, ttyfd);

   if (ttyfd < 0 || !p)
   {                            /* Device not open or no buffer */
      debug (DB_MSG, "READPKT FAIL", 0, 0);
      return (-1);
   }
   flag = n = 0;                /* Init local variables */

//  p2 = (char *) p;

   while (1)
   {
      // x = getchar(); /* Replace this with real i/o */

      fd_set readfds;
      int nfds = ttyfd + 1;
      int selret;
      struct timeval timeout;
      struct timeval tmosv;

      FD_ZERO (&readfds);
      FD_SET (ttyfd, &readfds);

      timeout.tv_sec = k->r_timo;
      timeout.tv_usec = 0;
      tmosv = timeout;

      if ((selret = select (nfds, &readfds, 0, 0, &timeout)) < 0)
      {
         debug (DB_LOG, "READPKT selret", 0, selret);
         return (-1);
      }

      if (selret == 0)
      {
         debug (DB_LOG, "READPKT timed out k->r_timo", 0, k->r_timo);
         return (0);            // indicate timeout to calling prog
      }


      if (selret > 0)
      {                         // something's available

         if (FD_ISSET (ttyfd, &readfds))
         {
            char kar;
            int nread;
            if ((nread = read (ttyfd, &kar, 1)) != 1)
            {
               debug (DB_LOG, "READPKT ttyfd", 0, ttyfd);
               debug (DB_LOG, "  nread", 0, nread);
               return (-1);
            }
            x = kar;
         }
      }
//    debug(DB_LOG,"READPKT x",0,x);

      c = (k->parity) ? x & 0x7f : x & 0xff;    /* Strip parity */

#ifdef F_CTRLC
      /*
       * In remote mode only: three consecutive ^C's to quit 
       */
      if (k->remote && c == (UCHAR) 3)
      {
         if (++ccn > 2)
         {
            debug (DB_MSG, "READPKT ^C^C^C", 0, 0);
            return (-1);
         }
      }
      else
      {
         ccn = 0;
      }
#endif /* F_CTRLC */

      if (!flag && c != k->r_soh)       /* No start of packet yet */
         continue;              /* so discard these bytes. */
      if (c == k->r_soh)
      {                         /* Start of packet */
         flag = 1;              /* Remember */
         continue;              /* But discard. */
      }
      else if (c == k->r_eom    /* Packet terminator */
               || c == '\012'   /* 1.3: For HyperTerminal */
         )
      {
         *p = NUL;              /* Terminate for printing */
         debug (DB_LOG, "READPKT return", 0, n);
//        debug (DB_PKT, "RPKT", p2, n);
         return (n);
      }
      else
      {                         /* Contents of packet */
         if (n++ > k->r_maxlen) /* Check length */
         {
            debug (DB_MSG, "READPKT return=0", 0, 0);
            return (0);
         }
         else
            *p++ = x & 0xff;
      }
   }
   debug (DB_MSG, "READPKT FAIL (end)", 0, 0);
   return (-1);
}

/*
 * T X _ D A T A -- Writes n bytes of data to communication device.  
 */
/*
 * Call with: k = pointer to Kermit struct. p = pointer to data to
 * transmit. n = length. Returns: X_OK on success. X_ERROR on failure to
 * write - i/o error. 
 */
int
tx_data (struct k_data *k, UCHAR * p, int n)
{
   int x;
   int max = 10;                /* Loop breaker */
   long usecs;

   debug (DB_LOG, "TX_DATA write n=", 0, n);

   usleep (k->send_pause_us);

#if SIMULATED_RTT > 0
   sleep (SIMULATED_RTT);
#endif
   while (n > 0)
   {                            /* Keep trying till done */
      x = write (ttyfd, p, n);
      max--;
      debug (DB_LOG, "TX_DATA write x=", 0, x);
      if (x == -1 && max > 0)
      {
         usecs = k->s_maxlen * (10000000L / k->baud);
         debug (DB_LOG, "TX_DATA sleeping usecs", 0, usecs);
         usleep (usecs);
         continue;
      }
      if (x < 0 || max < 1)     /* Errors are fatal */
      {
         debug (DB_LOG, "TX_DATA X_ERROR, max", 0, max);
         return (X_ERROR);
      }
      n -= x;
      p += x;
   }
   return (X_OK);               /* Success */
}

/*
 * O P E N F I L E -- Open output file 
 */
/*
 * Call with: Pointer to filename. Size in bytes. Creation date in format
 * yyyymmdd hh:mm:ss, e.g. 19950208 14:00:00 Mode: 1 = read, 2 = create, 3 
 * = append. Returns: X_OK on success. X_ERROR on failure, including
 * rejection based on name, size, or date. 
 */
int
openfile (struct k_data *k, UCHAR * s, int mode)
{
   debug (DB_LOG, "OPENFILE ", s, 0);
   debug (DB_LOG, "  mode", 0, mode);

   switch (mode)
   {
   case 1:                     /* Read */
      if (!(ifile = fopen ((char *) s, "r")))
      {
         debug (DB_LOG, "openfile read error", s, 0);
         return (X_ERROR);
      }
      k->s_first = 1;           /* Set up for getkpt */
      k->zinbuf[0] = '\0';      /* Initialize buffer */
      k->zinptr = k->zinbuf;    /* Set up buffer pointer */
      k->zincnt = 0;            /* and count */
      debug (DB_LOG, "openfile read ok", s, 0);
      return (X_OK);

   case 2:                     /* Write (create) */
      ofile = creat ((char *) s, 0644);
      if (ofile < 0)
      {
         debug (DB_LOG, "openfile write error", s, 0);
         return (X_ERROR);
      }
      debug (DB_LOG, "openfile write ok", s, 0);
      return (X_OK);

#ifdef COMMENT
   case 3:                     /* Append (not used) */
      ofile = open (s, O_WRONLY | O_APPEND);
      if (ofile < 0)
      {
         debug (DB_LOG, "openfile append error", s, 0);
         return (X_ERROR);
      }
      debug (DB_LOG, "openfile append ok", s, 0);
      return (X_OK);
#endif /* COMMENT */

   default:
      return (X_ERROR);
   }
}

/*
 * F I L E I N F O -- Get info about existing file 
 */
/*
 * Call with: Pointer to filename Pointer to buffer for date-time string
 * Length of date-time string buffer (must be at least 18 bytes) Pointer
 * to int file type: 0: Prevailing type is text. 1: Prevailing type is
 * binary. Transfer mode (0 = auto, 1 = manual): 0: Figure out whether
 * file is text or binary and return type. 1: (nonzero) Don't try to
 * figure out file type. Returns: X_ERROR on failure. 0L or greater on
 * success == file length. Date-time string set to yyyymmdd hh:mm:ss
 * modtime of file. If date can't be determined, first byte of buffer is
 * set to NUL. Type set to 0 (text) or 1 (binary) if mode == 0. 
 */
#ifdef F_SCAN
#define SCANBUF 1024
#define SCANSIZ 49152
#endif /* F_SCAN */

ULONG
fileinfo (struct k_data * k,
          UCHAR * filename, UCHAR * buf, int buflen, short *type, short mode)
{
   struct stat statbuf;
   struct tm *timestamp, *localtime ();

#ifdef F_SCAN
   FILE *fp;                    /* File scan pointer */
   char inbuf[SCANBUF];         /* and buffer */
#endif /* F_SCAN */

   debug (DB_MSG, "FILEINFO", 0, 0);

   if (!buf)
      return (X_ERROR);
   buf[0] = '\0';
   if (buflen < 18)
      return (X_ERROR);
   if (stat ((char *) filename, &statbuf) < 0)
      return (X_ERROR);
   timestamp = localtime (&(statbuf.st_mtime));
   sprintf ((char *) buf, "%04d%02d%02d %02d:%02d:%02d",
            timestamp->tm_year + 1900,
            timestamp->tm_mon + 1,
            timestamp->tm_mday,
            timestamp->tm_hour, timestamp->tm_min, timestamp->tm_sec);
#ifdef F_SCAN
   /*
    * Here we determine if the file is text or binary if the transfer
    * mode is not forced.  This is an extremely crude sample, which
    * diagnoses any file that contains a control character other than HT, 
    * LF, FF, or CR as binary. A more thorough content analysis can be
    * done that accounts for various character sets as well as various
    * forms of Unicode (UTF-8, UTF-16, etc). Or the diagnosis could be
    * based wholly or in part on the filename. etc etc.  Or the
    * implementation could skip this entirely by not defining F_SCAN
    * and/or by always calling this routine with type set to -1. 
    */
   if (!mode)
   {                            /* File type determination requested */
      int isbinary = 1;
      fp = fopen (filename, "r");       /* Open the file for scanning */
      if (fp)
      {
         int n = 0, count = 0;
         char c, *p;

         debug (DB_LOG, "fileinfo scan ", filename, 0);

         isbinary = 0;
         while (count < SCANSIZ && !isbinary)
         {                      /* Scan this much */
            n = fread (inbuf, 1, SCANBUF, fp);
            if (n == EOF || n == 0)
               break;
            count += n;
            p = inbuf;
            while (n--)
            {
               c = *p++;
               if (c < 32 || c == 127)
               {
                  if (c != 9 && /* Tab */
                      c != 10 &&        /* LF */
                      c != 12 &&        /* FF */
                      c != 13)
                  {             /* CR */
                     isbinary = 1;
                     debug (DB_MSG, "fileinfo BINARY", 0, 0);
                     break;
                  }
               }
            }
         }
         fclose (fp);
         *type = isbinary;
      }
   }
#endif /* F_SCAN */

   return ((ULONG) (statbuf.st_size));
}


/*
 * R E A D F I L E -- Read data from a file 
 */

int
readfile (struct k_data *k)
{

   if (!k->zinptr)
   {
#ifdef DEBUG
      debug (DB_MSG, "READFILE ZINPTR NOT SET", 0, 0);
#endif /* DEBUG */
      return (X_ERROR);
   }
   if (k->zincnt < 1)
   {                            /* Nothing in buffer - must refill */
      if (k->binary)
      {                         /* Binary - just read raw buffers */
         k->dummy = 0;
         if (k->zinlen != 512)
         {
            debug (DB_LOG, "READFILE should be 512, zinlen", 0, k->zinlen);
            return (-1);
         }
         k->zincnt = fread (k->zinbuf, 1, k->zinlen, ifile);
         debug (DB_LOG, "READFILE binary ok zincnt", 0, k->zincnt);
      }
      else
      {                         /* Text mode needs LF/CRLF handling */
         int c;                 /* Current character */
         for (k->zincnt = 0; (k->zincnt < (k->zinlen - 2)); (k->zincnt)++)
         {
            if ((c = getc (ifile)) == EOF)
               break;
            if (c == '\n')      /* Have newline? */
               k->zinbuf[(k->zincnt)++] = '\r'; /* Insert CR */
            k->zinbuf[k->zincnt] = c;
         }
#ifdef DEBUG
         k->zinbuf[k->zincnt] = '\0';
         debug (DB_LOG, "READFILE text ok zincnt", 0, k->zincnt);
#endif /* DEBUG */
      }
      k->zinbuf[k->zincnt] = '\0';      /* Terminate. */
      if (k->zincnt == 0)       /* Check for EOF */
         return (-1);
      k->zinptr = k->zinbuf;    /* Not EOF - reset pointer */
   }
   (k->zincnt)--;               /* Return first byte. */

   debug (DB_LOG, "READFILE exit zincnt", 0, k->zincnt);
   debug (DB_LOG, "READFILE exit zinptr", 0, k->zinptr);
   return (*(k->zinptr)++ & 0xff);
}


/*
 * W R I T E F I L E -- Write data to file 
 */
/*
 * Call with: Kermit struct String pointer Length Returns: X_OK on success
 * X_ERROR on failure, such as i/o error, space used up, etc 
 */
int
writefile (struct k_data *k, UCHAR * s, int n)
{
   int rc;
   rc = X_OK;

   debug (DB_LOG, "WRITEFILE n", 0, n);
   debug (DB_LOG, "WRITEFILE k->binary", 0, k->binary);

   if (k->binary)
   {                            /* Binary mode, just write it */
      debug (DB_HEX, "WHEX", s, n);
      if (write (ofile, s, n) != n)
         rc = X_ERROR;
   }
   else
   {                            /* Text mode, skip CRs */
      UCHAR *p, *q;
      int i;
      q = s;

      while (1)
      {
         for (p = q, i = 0; ((*p) && (*p != (UCHAR) 13)); p++, i++);
         if (i > 0)
            if (write (ofile, q, i) != i)
               rc = X_ERROR;
         if (!*p)
            break;
         q = p + 1;
      }
   }
   return (rc);
}

/*
 * C L O S E F I L E -- Close output file 
 */
/*
 * Mode = 1 for input file, mode = 2 or 3 for output file.
 * 
 * For output files, the character c is the character (if any) from the Z
 * packet data field.  If it is D, it means the file transfer was canceled
 * in midstream by the sender, and the file is therefore incomplete.  This
 * routine should check for that and decide what to do.  It should be
 * harmless to call this routine for a file that that is not open. 
 */
int
closefile (struct k_data *k, UCHAR c, int mode)
{
   int rc = X_OK;               /* Return code */

   debug (DB_LOG, "closefile mode", 0, mode);
   debug (DB_CHR, "closefile c", 0, c);

   switch (mode)
   {
   case 1:                     /* Closing input file */
      if (!ifile)               /* If not not open */
         break;                 /* do nothing but succeed */
      debug (DB_LOG, "closefile (input)", k->filename, 0);
      if (fclose (ifile) < 0)
         rc = X_ERROR;
      ifile = (FILE *) 0;
      break;
   case 2:                     /* Closing output file */
   case 3:
      if (ofile < 0)            /* If not open */
         break;                 /* do nothing but succeed */
      debug (DB_LOG, "closefile (output) name", k->filename, 0);
      debug (DB_LOG, "closefile (output) keep", 0, k->ikeep);
      if (close (ofile) < 0)
      {                         /* Try to close */
         rc = X_ERROR;
      }
      else if ((k->ikeep == 0) &&       /* Don't keep incomplete files */
               (c == 'D'))
      {                         /* This file was incomplete */
         if (k->filename)
         {
            debug (DB_LOG, "deleting incomplete", k->filename, 0);
            unlink ((char *) (k->filename));    /* Delete it. */
         }
      }
      break;
   default:
      rc = X_ERROR;
   }
   return (rc);
}

#ifdef DEBUG
int
xerror ()
{
   unsigned int x;
   extern int errorrate;        /* Fix this - NO EXTERNS */
   if (!errorrate)
      return (0);
   x = rand () % 100;           /* Fix this - NO C LIBRARY */
   debug (DB_LOG, "RANDOM", 0, x);
   debug (DB_LOG, "ERROR", 0, (x < errorrate));
   return (x < errorrate);
}
#endif /* DEBUG */
