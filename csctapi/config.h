#include "../oscam-config.h"

/* Debug Interface Device */
/* #undef DEBUG_IFD */
//#define DEBUG_IFD 1

/* #undef DEBUG_IO */
// #define DEBUG_IO 1

/* Debug Input/Output */
#define DEBUG_USB_IO 1

/* Debug Protocol */
/* #undef DEBUG_PROTOCOL */
//#define DEBUG_PROTOCOL 1

//#define PROTOCOL_T0_ISO 1

/* Define to 1 if you have the `nanosleep' function. */
#if !defined(OS_AIX) && !defined(OS_SOLARIS) && !defined(OS_OSF5)
#define HAVE_NANOSLEEP 1
#endif

/* Transportation of APDUs by T=0 */
/* #undef PROTOCOL_T0_ISO */

/* Timings in ATR are not used in T=0 cards */
/* #undef PROTOCOL_T0_USE_DEFAULT_TIMINGS */

/* Timings in ATR are not used in T=1 cards */
/* #undef PROTOCOL_T1_USE_DEFAULT_TIMINGS */

