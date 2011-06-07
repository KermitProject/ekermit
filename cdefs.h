#ifndef __CDEFS_H__
#define __CDEFS_H__

/*
  By default, the internal routines of kermit.c are not static,
  because this is not allowed in some embedded environments.
  To have them declared static, define STATIC=static on the cc
  command line.
*/
#ifdef MY_DEFS                  // HiTech's XAC cmd line is small
#define STATIC static
#else // MY_DEFS
#ifndef STATIC
#define STATIC
#endif /* STATIC */
#endif // MY_DEFS

/*
  By default we assume the compiler supports unsigned char and
  unsigned long.  If not you can override these definitions on
  the cc command line.
  Added unsigned short.
*/
#ifndef HAVE_UCHAR
typedef unsigned char UCHAR;
#endif /* HAVE_UCHAR */
#ifndef HAVE_ULONG
typedef unsigned long ULONG;
#endif /* HAVE_ULONG */
#ifndef HAVE_USHORT
typedef unsigned short USHORT;
#endif /* HAVE_USHORT */

#endif /* __CDEFS_H__ */
