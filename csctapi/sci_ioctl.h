#if defined(SCI_DEV) && !defined(_sci_inf_h_)
#define _sci_inf_h_

/* constants */
#define DEVICE_NAME			"sci_dev"

//#define ULONG (unsigned long)

#define SCI_IOW_MAGIC			's'

#ifndef OS_CYGWIN32
/* ioctl cmd table */
#define IOCTL_SET_RESET			_IOW(SCI_IOW_MAGIC, 1,  unsigned long)
#define IOCTL_SET_MODES			_IOW(SCI_IOW_MAGIC, 2,  SCI_MODES)
#define IOCTL_GET_MODES			_IOW(SCI_IOW_MAGIC, 3,  SCI_MODES)
#define IOCTL_SET_PARAMETERS		_IOW(SCI_IOW_MAGIC, 4,  SCI_PARAMETERS)
#define IOCTL_GET_PARAMETERS		_IOW(SCI_IOW_MAGIC, 5,  SCI_PARAMETERS)
#define IOCTL_SET_CLOCK_START		_IOW(SCI_IOW_MAGIC, 6,  unsigned long)
#define IOCTL_SET_CLOCK_STOP		_IOW(SCI_IOW_MAGIC, 7,  unsigned long)
#define IOCTL_GET_IS_CARD_PRESENT	_IOW(SCI_IOW_MAGIC, 8,  unsigned long)
#define IOCTL_GET_IS_CARD_ACTIVATED	_IOW(SCI_IOW_MAGIC, 9,  unsigned long)
#define IOCTL_SET_DEACTIVATE		_IOW(SCI_IOW_MAGIC, 10, unsigned long)
#define IOCTL_SET_ATR_READY		_IOW(SCI_IOW_MAGIC, 11, unsigned long)
#define IOCTL_GET_ATR_STATUS		_IOW(SCI_IOW_MAGIC, 12, unsigned long)
#define IOCTL_DUMP_REGS			_IOW(SCI_IOW_MAGIC, 20, unsigned long)
#else
#define IOCTL_SET_RESET			1
#define IOCTL_SET_MODES			2
#define IOCTL_GET_MODES			3
#define IOCTL_SET_PARAMETERS		4
#define IOCTL_GET_PARAMETERS		5
#define IOCTL_SET_CLOCK_START		6
#define IOCTL_SET_CLOCK_STOP		7
#define IOCTL_GET_IS_CARD_PRESENT	8
#define IOCTL_GET_IS_CARD_ACTIVATED	9
#define IOCTL_SET_DEACTIVATE		10
#define IOCTL_SET_ATR_READY		11
#define IOCTL_GET_ATR_STATUS		12
#define IOCTL_DUMP_REGS			13
#endif

/* MAJOR NUM OF DEVICE DRVIER */
#define MAJOR_NUM			169

#endif /* _sci_inf_h_ */
