#define MODULE_LOG_PREFIX "dvbstapi"

#include "globals.h"

#if defined(HAVE_DVBAPI) && defined(WITH_STAPI5)

#include "module-dvbapi.h"
#include "module-dvbapi-stapi.h"
#include "oscam-client.h"
#include "oscam-files.h"
#include "oscam-string.h"
#include "oscam-time.h"

extern int32_t exit_oscam;

#define MAX_STREAMPIDS MAX_DEMUX

struct tTkdDescInfo
{
	int STREAMPIDs[MAX_STREAMPIDS];
	uint32_t key_hndl;
	uint32_t iv_hndl;
	uint32_t path_hndl;
};

struct read_thread_param
{
	int32_t id;
	struct s_client *cli;
};

#define BUFFLEN 1024
#define PROCDIR "/proc/STAPI/stpti/"
#define MAX_DESCRAMBLER 16
#define TKD_MAX_NUMBER 1

/* These functions are in liboscam_stapi5.a */
extern char *oscam_stapi5_LibVersion(void);
extern uint32_t oscam_stapi5_Open(char *name, uint32_t *sessionhandle);
extern uint32_t oscam_stapi5_SignalAllocate(uint32_t sessionhandle, uint32_t *signalhandle);
extern uint32_t oscam_stapi5_FilterAllocate(uint32_t sessionhandle, uint32_t *filterhandle);
extern uint32_t oscam_stapi5_SlotInit(uint32_t sessionhandle, uint32_t signalhandle, uint32_t *bufferhandle, uint32_t *slothandle, uint16_t pid);
extern uint32_t oscam_stapi5_FilterSet(uint32_t filterhandle, uchar *filt, uchar *mask);
extern uint32_t oscam_stapi5_FilterAssociate(uint32_t filterhandle, uint32_t slothandle);
extern uint32_t oscam_stapi5_SlotDeallocate(uint32_t slothandle);
extern uint32_t oscam_stapi5_BufferDeallocate(uint32_t bufferhandle);
extern uint32_t oscam_stapi5_FilterDeallocate(uint32_t filterhandle, uint32_t bufferhandle, uint32_t slothandle);
extern uint32_t oscam_stapi5_Close(uint32_t sessionhandle);
extern const char *oscam_stapi5_GetRevision(void);
extern uint32_t oscam_stapi5_SignalWaitBuffer(uint32_t signalhandle, uint32_t *qbuffer, int32_t timeout);
extern uint32_t oscam_stapi5_SignalDisassociateBuffer(uint32_t signalhandle, uint32_t bufferhandle);
extern uint32_t oscam_stapi5_BufferReadSection(uint32_t bufferhandle, uint32_t *filterlist, int32_t maxfilter, uint32_t *filtercount, int32_t *crc, uchar *buf, int32_t bufsize, uint32_t *size);
extern uint32_t oscam_stapi5_SignalAbort(uint32_t signalhandle);
extern uint32_t oscam_stapi5_PidQuery(char *name, uint16_t pid);
extern uint32_t oscam_stapi5_BufferFlush(uint32_t bufferhandle);
extern uint32_t oscam_stapi5_SlotClearPid(uint32_t slot);
extern uint32_t oscam_stapi5_SlotUnlink(uint32_t slot);

extern const char *oscam_sttkd_GetRevision(void);
extern uint32_t oscam_sttkd_Open(char *name, uint32_t *sessionhandle);
extern uint32_t oscam_sttkd_Close(uint32_t tkdhandle);
extern uint32_t oscam_sttkd_Allocate(uint32_t tkdhandle, uint8_t cp, uint32_t *pathhandle, uint32_t *keyhandle);
extern uint32_t oscam_sttkd_Associate(char *name, uint32_t pathhandle, uint16_t Pid);
extern uint32_t oscam_sttkd_Deallocate(uint32_t pathhandle, uint32_t Keyhandle);
extern uint32_t oscam_sttkd_Disassociate(char *name, uint16_t pid);
extern uint32_t oscam_sttkd_KeyWrite(uint32_t keyhandle, uint8_t pol, const uchar * cw);

// Local functions
static void *stapi_read_thread(void *);
static int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uchar *filt, uchar *mask, int32_t dev_id);
static int32_t stapi_do_remove_filter(int32_t demux_id, FILTERTYPE *filter, int32_t dev_id);

// These variables are declared in module-dvbapi.c
extern int32_t disable_pmt_files;
extern struct s_dvbapi_priority *dvbapi_priority;
extern DEMUXTYPE demux[MAX_DEMUX];

static int32_t stapi_on;
static pthread_mutex_t filter_lock;
struct STDEVICE dev_list[PTINUM];

struct tTkdDescInfo tkd_desc_info[MAX_DESCRAMBLER];

static char TKD_DeviceName[TKD_MAX_NUMBER][16];
static uint32_t TKDHandle[TKD_MAX_NUMBER];


static void stapi_off(void)
{
	int32_t i;
	uint32_t ErrorCode;

	SAFE_MUTEX_LOCK(&filter_lock);

	cs_log("stapi shutdown");

	disable_pmt_files = 1;
	stapi_on = 0;
	for(i = 0; i < MAX_DEMUX; i++)
	{
		dvbapi_stop_descrambling(i);
		
		if (tkd_desc_info[i].path_hndl != 0)
		{
	        ErrorCode = oscam_sttkd_Deallocate(tkd_desc_info[i].path_hndl, tkd_desc_info[i].key_hndl);
		    if (ErrorCode != 0)
			    { cs_log("oscam_sttkd_Deallocate faild! ErrorCode: %d", ErrorCode);	}
		}				
	}
	
	uint8_t TKD_InstanceID = 0;
	for(TKD_InstanceID = 0; TKD_InstanceID < TKD_MAX_NUMBER; TKD_InstanceID++)
	{
			ErrorCode = oscam_sttkd_Close(TKDHandle[TKD_InstanceID]);
			if(ErrorCode != 0)
				{ cs_log("oscam_sttkd_Close: ErrorCode: %d TKDHandle: 0x%08X", ErrorCode, TKDHandle[TKD_InstanceID]); }
	}	

	for(i = 0; i < PTINUM; i++)
	{
		if(dev_list[i].SessionHandle > 0)
		{
			if(dev_list[i].SignalHandle > 0)
			{
				oscam_stapi5_SignalAbort(dev_list[i].SignalHandle);
			}
			pthread_cancel(dev_list[i].thread);
		}
	}

	SAFE_MUTEX_UNLOCK(&filter_lock);
	sleep(2);
	return;
}

int32_t stapi_open(void)
{
	uint32_t ErrorCode;

	DIR *dirp;
	struct dirent entry, *dp = NULL;
	struct stat buf;
	int32_t i;
	char pfad[80];
	stapi_on = 1;
	int32_t stapi_priority = 0;

	dirp = opendir(PROCDIR);
	if(!dirp)
	{
		cs_log("opendir failed (errno=%d %s)", errno, strerror(errno));
		return 0;
	}

	memset(dev_list, 0, sizeof(struct STDEVICE)*PTINUM);

	if(dvbapi_priority)
	{
		struct s_dvbapi_priority *p;
		for(p = dvbapi_priority; p != NULL; p = p->next)
		{
			if(p->type == 's')
			{
				stapi_priority = 1;
				break;
			}
		}
	}

	if(!stapi_priority)
	{
		cs_log("WARNING: no PTI devices defined, stapi disabled");
		return 0;
	}

	oscam_stapi5_GetRevision();
	oscam_sttkd_GetRevision();

	i = 0;
	while(!cs_readdir_r(dirp, &entry, &dp))
	{
		if(!dp) { break; }

		snprintf(pfad, sizeof(pfad), "%s%s", PROCDIR, dp->d_name);
		if(stat(pfad, &buf) != 0)
			{ continue; }

		if(!(buf.st_mode & S_IFDIR && strncmp(dp->d_name, ".", 1) != 0))
			{ continue; }

		int32_t do_open = 0;
		struct s_dvbapi_priority *p;

		for(p = dvbapi_priority; p != NULL; p = p->next)
		{
			if(p->type != 's') { continue; }
			if(strcmp(dp->d_name, p->devname) == 0)
			{
				do_open = 1;
				break;
			}
		}

		if(!do_open)
		{
			cs_log("PTI: %s skipped", dp->d_name);
			continue;
		}

		ErrorCode = oscam_stapi5_Open(dp->d_name, &dev_list[i].SessionHandle);
		if(ErrorCode != 0)
		{
			cs_log("STPTI_Open ErrorCode: %d", ErrorCode);
			continue;
		}

		//debug
		//oscam_stapi_Capability(dp->d_name);

		cs_strncpy(dev_list[i].name, dp->d_name, sizeof(dev_list[i].name));
		cs_log("PTI: %s open %d", dp->d_name, i);

		ErrorCode = oscam_stapi5_SignalAllocate(dev_list[i].SessionHandle, &dev_list[i].SignalHandle);
		if(ErrorCode != 0)
			{ cs_log("SignalAllocate: ErrorCode: %d SignalHandle: %x", ErrorCode, dev_list[i].SignalHandle); }

		i++;
		if(i >= PTINUM) { break; }
	}
	closedir(dirp);

	if(i == 0) { return 0; }
		
	uint8_t TKD_InstanceID = 0;
	memset(&tkd_desc_info, 0, sizeof(tkd_desc_info[0]) * MAX_DESCRAMBLER);

	for(TKD_InstanceID = 0; TKD_InstanceID < TKD_MAX_NUMBER; TKD_InstanceID++)
	{	
			/* Generate the device name dynamically based upon the Instance ID */
			snprintf(TKD_DeviceName[TKD_InstanceID], sizeof(TKD_DeviceName), "TKD_%02d", TKD_InstanceID);
	
			ErrorCode = oscam_sttkd_Open(TKD_DeviceName[TKD_InstanceID], &TKDHandle[TKD_InstanceID]);
			if(ErrorCode != 0)
				cs_log("oscam_sttkd_Open: DeviceName: %s, TKDHandle: 0x%08X, ErrorCode: %d", TKD_DeviceName[TKD_InstanceID], TKDHandle[TKD_InstanceID], ErrorCode);
	}		

	SAFE_MUTEX_INIT(&filter_lock, NULL);

	for(i = 0; i < PTINUM; i++)
	{
		if(dev_list[i].SessionHandle == 0)
			{ continue; }

		struct read_thread_param *para;
		if(!cs_malloc(&para, sizeof(struct read_thread_param)))
			{ return 0; }
		para->id = i;
		para->cli = cur_client();

		int32_t ret = start_thread("stapi read", stapi_read_thread, (void *)para, &dev_list[i].thread, 1, 0);
		if(ret)
		{
			return 0;
		}
	}

	atexit(stapi_off);

	cs_log("liboscam_stapi5 v.%s initialized", oscam_stapi5_LibVersion());
	return 1;
}

int32_t stapi_activate_section_filter(int32_t fd, uchar *filter, uchar *mask)
{
	uint32_t ErrorCode;

	ErrorCode = oscam_stapi5_FilterSet(fd, filter, mask);
	if(ErrorCode != 0)
	{
			cs_log_dbg(D_DVBAPI, "Error: oscam_stapi5_FilterSet; %d", ErrorCode);
			return -1;
	}
	
	return ErrorCode;
}

int32_t stapi_set_filter(int32_t demux_id, uint16_t pid, uchar *filter, uchar *mask, int32_t num, char *pmtfile)
{
	int32_t i;
	int32_t ret = -1;
	char dest[1024];
	uint16_t pids[1] = { pid };
	struct s_dvbapi_priority *p;

	if(!pmtfile)
	{
		cs_log_dbg(D_DVBAPI, "No valid pmtfile!");
		return -1;
	}

	cs_log_dbg(D_DVBAPI, "pmt file %s demux_id %d", pmtfile, demux_id);

	for(p = dvbapi_priority; p != NULL; p = p->next)
	{
		if(p->type != 's') { continue; }  // stapi rule?
		if(strcmp(pmtfile, p->pmtfile) != 0) { continue; }  // same file?

		for(i = 0; i < PTINUM; i++)
		{
			if(strcmp(dev_list[i].name, p->devname) == 0 && p->disablefilter == 0)  // check device name and if filtering is enabled!
			{
				cs_log_dbg(D_DVBAPI, "set stapi filter on %s for pid %04X", dev_list[i].name, pids[0]);
				ret = stapi_do_set_filter(demux_id, &dev_list[i].demux_fd[demux_id][num], pids, 1, filter, mask, i);
				if(ret > 0)    // success
				{
					demux[demux_id].dev_index = i;
					cs_log_dbg(D_DVBAPI, "%s filter %d set (pid %04X)", dev_list[i].name, num, pid);
					return ret; // return filternumber
				}
				else   // failure
				{
					cs_log_dbg(D_DVBAPI, "Error setting new filter for pid %04X on %s!", pid, dev_list[i].name);
					return -1; // set return to error
				}
			}
		}
	}

	if(p == NULL)
	{
		cs_log_dbg(D_DVBAPI, "No matching S: line in oscam.dvbapi for pmtfile %s -> stop descrambling!", pmtfile);
		snprintf(dest, sizeof(dest), "%s%s", TMPDIR, demux[demux_id].pmt_file);
		unlink(dest); // remove obsolete pmt file
		dvbapi_stop_descrambling(demux_id);
	}
	return ret;
}

int32_t stapi_remove_filter(int32_t demux_id, int32_t num, char *pmtfile)
{
	int32_t i, ret = 0;
	struct s_dvbapi_priority *p;

	if(!pmtfile) { return 0; }

	for(p = dvbapi_priority; p != NULL; p = p->next)
	{
		if(p->type != 's') { continue; }
		if(strcmp(pmtfile, p->pmtfile) != 0)
			{ continue; }

		for(i = 0; i < PTINUM; i++)
		{
			if(strcmp(dev_list[i].name, p->devname) == 0 && p->disablefilter == 0)
			{
				ret = stapi_do_remove_filter(demux_id, &dev_list[i].demux_fd[demux_id][num], i);
			}
		}
	}
	if(ret == 1)
	{
		cs_log_dbg(D_DVBAPI, "filter %d removed", num);
	}
	else
	{
		cs_log_dbg(D_DVBAPI, "Error: filter %d was not removed!", num);
	}
	return ret;
}

static uint32_t check_slot(int32_t dev_id, uint32_t checkslot, FILTERTYPE *skipfilter)
{
	int32_t d, f, l;
	for(d = 0; d < MAX_DEMUX; d++)
	{
		for(f = 0; f < MAX_FILTER; f++)
		{
			if(skipfilter && &dev_list[dev_id].demux_fd[d][f] == skipfilter)
				{ continue; }
			for(l = 0; l < dev_list[dev_id].demux_fd[d][f].NumSlots; l++)
			{
				if(checkslot == dev_list[dev_id].demux_fd[d][f].SlotHandle[l])
				{
					return dev_list[dev_id].demux_fd[d][f].BufferHandle[l];
				}
			}
		}
	}
	return 0;
}


static int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uchar *filt, uchar *mask, int32_t dev_id)
{
	uint32_t FilterAssociateError = 0;
	int32_t k, ret = 0;

	filter->fd          = 0;
	filter->BufferHandle[0]     = 0;
	filter->SlotHandle[0]   = 0;

	if(dev_list[dev_id].SessionHandle == 0) { return 0; }

	uint32_t FilterAllocateError = oscam_stapi5_FilterAllocate(dev_list[dev_id].SessionHandle, &filter->fd);

	if(FilterAllocateError != 0)
	{
		cs_log("FilterAllocate problem");
		filter->fd = 0;
		return 0;
	}

	uint32_t FilterSetError = oscam_stapi5_FilterSet(filter->fd, filt, mask);

	for(k = 0; k < pidcount; k++)
	{
		uint16_t pid = pids[k];

		uint32_t QuerySlot = oscam_stapi5_PidQuery(dev_list[dev_id].name, pid);
		int32_t SlotInit = 1;

		if(QuerySlot != 0)
		{
			uint32_t checkslot = check_slot(dev_id, QuerySlot, NULL);
			if(checkslot > 0)
			{
				filter->SlotHandle[k] = QuerySlot;
				filter->BufferHandle[k] = checkslot;
				SlotInit = 0;
			}
			else
			{
				cs_log("overtake: clear pid, errorcode: %d", oscam_stapi5_SlotClearPid(QuerySlot));
				SlotInit = 1;
			}
		}

		if(SlotInit == 1)
		{
			ret = oscam_stapi5_SlotInit(dev_list[dev_id].SessionHandle, dev_list[dev_id].SignalHandle, &filter->BufferHandle[k], &filter->SlotHandle[k], pid);
		}

		FilterAssociateError = oscam_stapi5_FilterAssociate(filter->fd, filter->SlotHandle[k]);
		filter->NumSlots++;
	}

	if(ret || FilterAllocateError || FilterAssociateError || FilterSetError)
	{
		cs_log("set_filter: dev: %d FAl: %d FAs: %d FS: %d",
			   dev_id, FilterAllocateError, FilterAssociateError, FilterSetError);
		stapi_do_remove_filter(demux_id, filter, dev_id);
		return 0;
	}
	else
	{
		return filter->fd; // return fd of filter
	}
}

static int32_t stapi_do_remove_filter(int32_t UNUSED(demux_id), FILTERTYPE *filter, int32_t dev_id)
{
	if(filter->fd == 0) { return 0; }

	uint32_t BufferDeallocateError = 0, SlotDeallocateError = 0, FilterDeallocateError = 0;

	if(dev_list[dev_id].SessionHandle == 0) { return 0; }

	int32_t k;
	for(k = 0; k < filter->NumSlots; k++)
	{
		uint32_t checkslot = check_slot(dev_id, filter->SlotHandle[k], filter);

		if(checkslot == 0)
		{
			FilterDeallocateError   = oscam_stapi5_FilterDeallocate(filter->fd, filter->BufferHandle[k], filter->SlotHandle[k]);
			
			oscam_stapi5_SlotClearPid(filter->SlotHandle[k]);
			oscam_stapi5_SlotUnlink(filter->SlotHandle[k]);
			oscam_stapi5_SignalDisassociateBuffer(dev_list[dev_id].SignalHandle, filter->BufferHandle[k]);

			BufferDeallocateError   = oscam_stapi5_BufferDeallocate(filter->BufferHandle[k]);
			SlotDeallocateError     = oscam_stapi5_SlotDeallocate(filter->SlotHandle[k]);			

		}
	}

	memset(filter, 0, sizeof(FILTERTYPE));

	if(BufferDeallocateError || SlotDeallocateError || FilterDeallocateError)
	{
		cs_log("remove_filter: dev: %d BD: %d SD: %d FDe: %d",
			   dev_id, BufferDeallocateError, SlotDeallocateError, FilterDeallocateError);
		return 0;
	}
	else
	{
		return 1;
	}
}

static void stapi_cleanup_thread(void *dev)
{
	int32_t dev_index = (int)dev;

	int32_t ErrorCode;
	ErrorCode = oscam_stapi5_Close(dev_list[dev_index].SessionHandle);

	cs_log("liboscam_stapi5: PTI %s closed - %d\n", dev_list[dev_index].name, ErrorCode);
	dev_list[dev_index].SessionHandle = 0;
}

static void *stapi_read_thread(void *sparam)
{
	int32_t dev_index, ErrorCode, i, j, CRCValid;
	uint32_t QueryBufferHandle = 0, DataSize = 0;
	uchar buf[BUFFLEN];

	struct read_thread_param *para = sparam;
	dev_index = para->id;

	SAFE_SETSPECIFIC(getclient, para->cli);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_cleanup_push(stapi_cleanup_thread, (void *) dev_index);

	int32_t error_count = 0;

	while(!exit_oscam)
	{
		QueryBufferHandle = 0;
		ErrorCode = oscam_stapi5_SignalWaitBuffer(dev_list[dev_index].SignalHandle, &QueryBufferHandle, 1000);

		switch(ErrorCode)
		{
		case 0: // NO_ERROR:
			break;
		case 852042: // ERROR_SIGNAL_ABORTED
			cs_log("Caught abort signal");
			pthread_exit(NULL);
			break;
		case 11: // ERROR_TIMEOUT:
			//cs_log("timeout %d", dev_index);
			//TODO: if pidindex == -1 try next
			continue;
			break;
		default:
			if(QueryBufferHandle != 0)
			{
				cs_log("SignalWaitBuffer error: %d", ErrorCode);
				oscam_stapi5_BufferFlush(QueryBufferHandle);
				continue;
			}
			cs_log("SignalWaitBuffer: index %d ErrorCode: %d - QueryBuffer: %x", dev_index, ErrorCode, QueryBufferHandle);
			error_count++;
			if(error_count > 10)
			{
				cs_log("Too many errors in reader thread %d, quitting.", dev_index);
				pthread_exit(NULL);
			}
			continue;
			break;
		}

		uint32_t NumFilterMatches = 0;
		int32_t demux_id = 0, filter_num = 0;
		DataSize = 0;
		uint32_t k;

		uint32_t MatchedFilterList[10];
		ErrorCode = oscam_stapi5_BufferReadSection(QueryBufferHandle, MatchedFilterList, 10, &NumFilterMatches, &CRCValid, buf, BUFFLEN, &DataSize);

		if(ErrorCode != 0)
		{
			cs_log("BufferRead: index: %d ErrorCode: %d", dev_index, ErrorCode);
			cs_sleepms(1000);
			continue;
		}

		if(DataSize <= 0)
			{ continue; }

		SAFE_MUTEX_LOCK(&filter_lock); // don't use cs_lock() here; multiple threads using same s_client struct
		for(k = 0; k < NumFilterMatches; k++)
		{
			for(i = 0; i < MAX_DEMUX; i++)
			{
				for(j = 0; j < MAX_FILTER; j++)
				{
					if(dev_list[dev_index].demux_fd[i][j].fd == MatchedFilterList[k])
					{
						demux_id = i;
						filter_num = j;

						dvbapi_process_input(demux_id, filter_num, buf, DataSize);
					}
				}
			}
		}
		SAFE_MUTEX_UNLOCK(&filter_lock);
	}
	
	pthread_cleanup_pop(0);
	
	return NULL;
}

int32_t stapi_init_descrambler(int32_t dev_index)
{
	int32_t ErrorCode;

	if(dev_index >= MAX_DESCRAMBLER)
	{
		cs_log("TKD MAX_DESCRAMBLER reached!");
		return 0;
	}

	ErrorCode = oscam_sttkd_Allocate(TKDHandle[0], 0, &tkd_desc_info[dev_index].path_hndl, &tkd_desc_info[dev_index].key_hndl);
	if (ErrorCode != 0)
	{
		cs_log("oscam_sttkd_Allocate faild! ErrorCode: %d", ErrorCode);
		return 0;
	}

	return 1;
}

int32_t stapi_set_pid(int32_t demux_id, int32_t UNUSED(num), int32_t idx, uint16_t pid, char *UNUSED(pmtfile))
{
	if(idx == -1)
	{
		if (tkd_desc_info[demux[demux_id].dev_index].path_hndl != 0)
		{
			cs_log_dbg(D_DVBAPI, "stop descrambling of PID %d on %s", pid, dev_list[demux[demux_id].dev_index].name);
	        uint32_t ErrorCode = oscam_sttkd_Disassociate(dev_list[demux[demux_id].dev_index].name, pid);
		    if (ErrorCode != 0)
			    cs_log("oscam_sttkd_Disassociate faild! ErrorCode: %d", ErrorCode);
				
			int i;
			for (i = 0; i < MAX_STREAMPIDS; i++)
			{
				if (tkd_desc_info[demux[demux_id].dev_index].STREAMPIDs[i] == pid)
				{
					tkd_desc_info[demux[demux_id].dev_index].STREAMPIDs[i] = 0;
					break;
				}
			}
			
		}
	}

	return 1;
}

int32_t stapi_write_cw(int32_t demux_id, uchar *cw, uint16_t *STREAMpids, int32_t STREAMpidcount, char *UNUSED(pmtfile))
{
	int32_t ErrorCode, l, x;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	char *text[] = { "even", "odd" };

	if(dev_list[demux[demux_id].dev_index].SessionHandle == 0) { return 0; }
		
	// check if descrambler is started for this dev_index
	if(tkd_desc_info[demux[demux_id].dev_index].path_hndl == 0)
	{
		if(!stapi_init_descrambler(demux[demux_id].dev_index))
		{
			cs_log_dbg(D_DVBAPI, "stapi_write_cw , faild to added descrambler for %s", dev_list[demux[demux_id].dev_index].name);
		    return 0;
		}			
	}

    // descrambler started, check each pid
	for (x = 0; x < STREAMpidcount; x++)
	{
		int pid_associated = -1;
		
		// search STREAMpids if path got associated
		for (l = 0; l < MAX_STREAMPIDS; l++)
		{
			if (tkd_desc_info[demux[demux_id].dev_index].STREAMPIDs[l] == STREAMpids[x])
			{
				pid_associated = l;
				break;
			}
		}
		
		// if not associated add the pid
		if(pid_associated < 0)
		{
			ErrorCode = oscam_sttkd_Associate(dev_list[demux[demux_id].dev_index].name, tkd_desc_info[demux[demux_id].dev_index].path_hndl, STREAMpids[x]);
			if (ErrorCode != 0)
			{
				cs_log("stapi_write_cw , oscam_sttkd_Associate faild for pid %04X! ErrorCode: %d", STREAMpids[x], ErrorCode);
				return 0;
			}				
					
			// add the pid to the next free index
			for (l = 0; l < MAX_STREAMPIDS; l++)
			{
				if (tkd_desc_info[demux[demux_id].dev_index].STREAMPIDs[l] == 0)
				{
					tkd_desc_info[demux[demux_id].dev_index].STREAMPIDs[l] = STREAMpids[x];
					pid_associated = l;
					break;
				}
			}
			
			if (pid_associated < 0)
			{
			    cs_log("stapi_write_cw , faild to associate pid %04X, maximum number of %d pids reached", STREAMpids[x], MAX_STREAMPIDS);
				return 0;
			}			
		}
	}

	//@theparasol: please verify this block is in the right place
	int32_t pidnum = demux[demux_id].pidindex; // get current pidindex used for descrambling
	int32_t idx = demux[demux_id].ECMpids[pidnum].index;

	if(!idx)   // if no indexer for this pid get one!
	{
		idx = dvbapi_get_descindex(demux_id);
		demux[demux_id].ECMpids[pidnum].index = idx;
		cs_log_dbg(D_DVBAPI, "Demuxer %d PID: %d CAID: %04X ECMPID: %04X is using index %d", demux_id, pidnum,
				  demux[demux_id].ECMpids[pidnum].CAID, demux[demux_id].ECMpids[pidnum].ECM_PID, idx - 1);
	}
	//

	for(l = 0; l < 2; l++)
	{
		if(memcmp(cw + (l * 8), demux[demux_id].lastcw[l], 8) != 0 && memcmp(cw + (l * 8), nullcw, 8) != 0)
		{
			ErrorCode = oscam_sttkd_KeyWrite(tkd_desc_info[demux[demux_id].dev_index].key_hndl, l, cw + (l * 8));
			
			memcpy(demux[demux_id].lastcw[l], cw + (l * 8), 8);
			cs_log_dbg(D_DVBAPI, "write cw %s index: %d on %s", text[l], demux_id, dev_list[demux[demux_id].dev_index].name);
		}
	}

	return 1;
}

#endif
