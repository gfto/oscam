#if defined(LIBUSB)
/*
    ifd_smartreader.c
    This module provides IFD handling functions for for Argolis smartreader+.
*/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include "ifd_smartreader.h"

#ifdef OS_CYGWIN32
#undef OK
#undef ERROR
#undef LOBYTE
#undef HIBYTE
#endif

#define OK 0
#define ERROR 1
#define LOBYTE(w) ((BYTE)((w) & 0xff))
#define HIBYTE(w) ((BYTE)((w) >> 8))

//The number of concurrent bulk reads to queue onto the smartreader
#define NUM_TXFERS 2

struct s_sr_config {
    int32_t F;
    float D;
    int32_t fs;
    int32_t N;
    int32_t T;
    int32_t inv;
    int32_t parity;
    int32_t irdeto;
    int32_t running;
	libusb_device *usb_dev;
	libusb_device_handle *usb_dev_handle;
    enum smartreader_chip_type type;
    uint8_t in_ep;  // 0x01
    uint8_t out_ep; // 0x82
    int32_t index;
    /** usb read timeout */
    int32_t usb_read_timeout;
    /** usb write timeout */
    int32_t usb_write_timeout;
    uint32_t  writebuffer_chunksize;
    unsigned char bitbang_enabled;
    int32_t baudrate;
    int32_t interface;   // 0 or 1
    /** maximum packet size. Needed for filtering modem status bytes every n packets. */
    uint32_t  max_packet_size;
    unsigned char g_read_buffer[4096];
    uint32_t  g_read_buffer_size;
    pthread_mutex_t g_read_mutex;
    pthread_cond_t g_read_cond;
    pthread_mutex_t g_usb_mutex;
    pthread_cond_t g_usb_cond;
    int32_t poll;
    pthread_t rt;
    unsigned char modem_status;
};

typedef struct s_reader S_READER;

static bool smartreader_check_endpoint(libusb_device *usb_dev, uint8_t out_endpoint);
static struct libusb_device *find_smartreader(const char*busname,const char *devname, uint8_t out_endpoint);
static void smartreader_init(S_READER *reader, uint8_t out_endpoint);
static uint32_t  smartreader_determine_max_packet_size(S_READER *reader);
static int32_t smartreader_usb_close_internal (S_READER *reader);
static int32_t smartreader_usb_reset(S_READER *reader);
static int32_t smartreader_usb_open_dev(S_READER *reader);
static int32_t smartreader_usb_purge_rx_buffer(S_READER *reader);
static int32_t smartreader_usb_purge_tx_buffer(S_READER *reader);
static int32_t smartreader_usb_purge_buffers(S_READER *reader);
static int32_t smartreader_convert_baudrate(int32_t baudrate, S_READER *reader, uint16_t  *value, uint16_t  *index);
static int32_t smartreader_set_baudrate(S_READER *reader, int32_t baudrate);
static int32_t smartreader_setdtr_rts(S_READER *reader, int32_t dtr, int32_t rts);
static int32_t smartreader_setflowctrl(S_READER *reader, int32_t flowctrl);
static int32_t smartreader_set_line_property2(S_READER *reader, enum smartreader_bits_type bits,
                            enum smartreader_stopbits_type sbit, enum smartreader_parity_type parity,
                            enum smartreader_break_type break_type);
static int32_t smartreader_set_line_property(S_READER *reader, enum smartreader_bits_type bits,
                           enum smartreader_stopbits_type sbit, enum smartreader_parity_type parity);
static void smart_flush(S_READER *reader);
static int32_t smartreader_set_latency_timer(S_READER *reader, uint16_t  latency);
static void EnableSmartReader(S_READER *reader, int32_t clock, uint16_t  Fi, unsigned char Di, unsigned char Ni, unsigned char T,unsigned char inv, int32_t parity);
static void *ReaderThread(void *p);
static void smart_fastpoll(S_READER *reader, int32_t on);

static int32_t init_count = 0;

int32_t SR_Init (struct s_reader *reader)
{
    uint8_t out_endpoint;
    int32_t ret;
    char device[128];
    char *busname, *devname, *search = ":", *saveptr1 = NULL;
    // split the device name from the reader conf into devname and busname
    memcpy(device,reader->device,128);
    busname=strtok_r(device,search, &saveptr1);
    devname=strtok_r(NULL,search, &saveptr1);
    if(!busname || !devname) {
        cs_log("Wrong device format (%s), it should be Device=bus:dev",reader->device);
        return ERROR;
    }
    reader->sr_config=malloc(sizeof(struct s_sr_config));
    if(!reader->sr_config) {
        cs_log("Couldn't allocate memory for Device=%s config",reader->device);
        return ERROR;
    }
    cs_writelock(&sr_lock);
    cs_debug_mask (D_DEVICE, "IO:SR: Looking for device %s on bus %s",devname,busname);

    if(!init_count) {
     ret = libusb_init(NULL);
     if (ret < 0) {
        cs_writeunlock(&sr_lock);
        cs_log("Libusb init error : %d",ret);
        return ret;
     }
    }
    init_count++;

    //Overwrite default endpoint if config has a value for it
    if(reader->device_endpoint != 0)
      out_endpoint = reader->device_endpoint;
    else
        out_endpoint = 0x82;

    cs_log("Using 0x%2X as endpoint for smartreader hardware detection", out_endpoint);

    smartreader_init(reader,out_endpoint);

    reader->sr_config->usb_dev=find_smartreader(busname,devname,out_endpoint);
    if(!reader->sr_config->usb_dev){
        cs_writeunlock(&sr_lock);
        return ERROR;
    }

    //The smartreader has different endpoint addresses
    //compared to a real FT232 device, so change them here,
    //also a good way to compare a real FT232 with a smartreader
    //if you enumarate usb devices
    reader->sr_config->in_ep = 0x1;
    reader->sr_config->out_ep=out_endpoint;

    cs_debug_mask (D_DEVICE, "IO:SR: Opening smartreader device %s on bus %s",devname,busname);

    if ((ret=smartreader_usb_open_dev(reader))) {
        cs_writeunlock(&sr_lock);
        cs_log("unable to open smartreader device %s in bus %s (ret=%d)\n", devname,busname,ret);
        return ERROR;
    }

    cs_debug_mask (D_DEVICE, "IO:SR: Setting smartreader latency timer to 1ms");

    //Set the FTDI latency timer to 1ms
    ret = smartreader_set_latency_timer(reader, 1);

    //Set databits to 8o2
    ret = smartreader_set_line_property(reader, BITS_8, STOP_BIT_2, ODD);

    //Set the DTR HIGH and RTS LOW
    ret=smartreader_setdtr_rts(reader, 0, 0);

    //Disable flow control
    ret=smartreader_setflowctrl(reader, 0);
    
    cs_writeunlock(&sr_lock);

    // start the reading thread
    reader->sr_config->g_read_buffer_size = 0;
    reader->sr_config->modem_status = 0 ;
    pthread_mutex_init(&reader->sr_config->g_read_mutex,NULL);
    pthread_cond_init(&reader->sr_config->g_read_cond,NULL);
    pthread_mutex_init(&reader->sr_config->g_usb_mutex,NULL);
    pthread_cond_init(&reader->sr_config->g_usb_cond,NULL);
    ret = pthread_create(&reader->sr_config->rt, NULL, ReaderThread, (void *)(reader));
    if (ret) {
        cs_log("ERROR; return code from pthread_create() is %d", ret);
        return ERROR;
    }

  return OK;
}


int32_t SR_GetStatus (struct s_reader *reader, int32_t * in)
{
  int32_t state;

    smart_fastpoll(reader, TRUE);
    pthread_mutex_lock(&reader->sr_config->g_read_mutex);
    state =(reader->sr_config->modem_status & 0x80) == 0x80 ? 0 : 2;
    pthread_mutex_unlock(&reader->sr_config->g_read_mutex);
    smart_fastpoll(reader, FALSE);

  //state = 0 no card, 1 = not ready, 2 = ready
  if (state)
    *in = 1; //CARD, even if not ready report card is in, or it will never get activated
  else
    *in = 0; //NOCARD

  return OK;
}

static int32_t smart_read(S_READER *reader, unsigned char* buff, uint32_t  size, int32_t timeout_sec)
{
    int32_t ret = 0;
    uint32_t  total_read = 0;
    struct timeval start, now, dif = {0};
    struct timespec timeout = {0};

    gettimeofday(&start, NULL);
    timeout.tv_sec = start.tv_sec + timeout_sec;
    timeout.tv_nsec = start.tv_usec * 1000;

    while(total_read < size && dif.tv_sec < timeout_sec) {
        pthread_mutex_lock(&reader->sr_config->g_read_mutex);

        while (reader->sr_config->g_read_buffer_size == 0 && dif.tv_sec < timeout_sec)
        {
            pthread_cond_timedwait(&reader->sr_config->g_read_cond, &reader->sr_config->g_read_mutex, &timeout);
            gettimeofday(&now,NULL);
            timersub(&now, &start, &dif);
        }

        ret = (reader->sr_config->g_read_buffer_size > size-total_read ? size - total_read : reader->sr_config->g_read_buffer_size);
        memcpy(buff + total_read, reader->sr_config->g_read_buffer,ret);
        reader->sr_config->g_read_buffer_size -= ret;

        if(reader->sr_config->g_read_buffer_size > 0)
            memmove(reader->sr_config->g_read_buffer, reader->sr_config->g_read_buffer + ret, reader->sr_config->g_read_buffer_size);

        total_read += ret;
        pthread_mutex_unlock(&reader->sr_config->g_read_mutex);

        gettimeofday(&now, NULL);
        timersub(&now, &start, &dif);
    }

    cs_ddump_mask(D_DEVICE, buff, total_read, "SR IO: Receive: ");
    return total_read;
}

int32_t SR_Reset (struct s_reader *reader, ATR *atr)
{
    unsigned char data[ATR_MAX_SIZE];
    int32_t ret;
    int32_t atr_ok;
    uint32_t  i;
    int32_t parity[4] = {EVEN, ODD, NONE, EVEN};    // the last EVEN is to try with different F, D values for irdeto card.
    static const char * const parity_str[5] = {"NONE", "ODD", "EVEN", "MARK", "SPACE"};

    if(reader->mhz == reader->cardmhz && reader->cardmhz * 10000 > 3690000)
        reader->sr_config->fs = reader->cardmhz * 10000;
    else
        reader->sr_config->fs = 3690000;

    smart_fastpoll(reader, TRUE);
    smart_flush(reader);
    // set smartreader+ default values
    reader->sr_config->F = 372;
    reader->sr_config->D = 1.0;
    reader->sr_config->N = 0;
    reader->sr_config->T = 1;
    reader->sr_config->inv = 0;

    for(i=0 ; i < 4 ;i++) {
        reader->sr_config->irdeto=FALSE;
        atr_ok=ERROR;
        memset(data,0,sizeof(data));
        cs_debug_mask (D_DEVICE, "IO:SR: Trying with parity %s",parity_str[parity[i]]);


        // special irdeto case
        if(i==3) {
            cs_debug_mask (D_DEVICE, "IO:SR: Trying irdeto");
            reader->sr_config->F=618; /// magic smartreader value
            reader->sr_config->D=1;
            reader->sr_config->T=2; // will be set to T=1 in EnableSmartReader
            reader->sr_config->fs=6000000;
        }

        smart_flush(reader);
        EnableSmartReader(reader, reader->sr_config->fs/10000, reader->sr_config->F, (BYTE)reader->sr_config->D, reader->sr_config->N, reader->sr_config->T, reader->sr_config->inv,parity[i]);

        //Reset smartcard

        //Set the DTR HIGH and RTS HIGH
        smartreader_setdtr_rts(reader, 1, 1);
        // A card with an active low reset is reset by maintaining RST in state L for at least 40 000 clock cycles
        // so if we have a base freq of 3.5712MHz : 40000/3690000 = .0112007168458781 seconds, aka 11ms
        // so if we have a base freq of 6.00MHz : 40000/6000000 = .0066666666666666 seconds, aka 6ms
        cs_sleepms(20);

        //Set the DTR HIGH and RTS LOW
        smartreader_setdtr_rts(reader, 1, 0);

        //Read the ATR
        ret = smart_read(reader,data,ATR_MAX_SIZE,1);
        cs_debug_mask (D_DEVICE, "IO:SR: get ATR ret = %d" , ret);
        if(ret)
            cs_ddump_mask(D_DEVICE, data,ATR_MAX_SIZE*2,"IO:SR: ");

        // this is to make sure we don't think this 03 FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00  is a valid ATR.
        if((data[0]!=0x3B && data[0]!=0x03 && data[0]!=0x3F) || (data[1]==0xFF && data[2]==0x00)) {
            reader->sr_config->irdeto=FALSE;
            continue; // this is not a valid ATR.
        }

        if(data[0]==0x03) {
            cs_debug_mask (D_DEVICE, "IO:SR: Inverse convention detected, setting smartreader inv to 1");

            reader->sr_config->inv=1;
            EnableSmartReader(reader, reader->sr_config->fs/10000, reader->sr_config->F, (BYTE)reader->sr_config->D, reader->sr_config->N, reader->sr_config->T, reader->sr_config->inv,parity[i]);
        }
        // parse atr
        if(ATR_InitFromArray (atr, data, ret) == ATR_OK) {
            cs_debug_mask (D_DEVICE, "IO:SR: ATR parsing OK");
            atr_ok=OK;
            if(i==3) {
                cs_debug_mask (D_DEVICE, "IO:SR: Locking F and D for Irdeto mode");
                reader->sr_config->irdeto=TRUE;
            }
        }

        if(atr_ok == OK)
            break;
     }

    smart_fastpoll(reader, FALSE);

    return atr_ok;
}

static int32_t smart_write(S_READER *reader, unsigned char* buff, uint32_t  size)
{

    uint32_t  idx;

    int32_t write_size;
    uint32_t  offset = 0;
    int32_t total_written = 0;
    int32_t written;

    if(size<reader->sr_config->writebuffer_chunksize)
        write_size=size;
    else
        write_size = reader->sr_config->writebuffer_chunksize;

    while (offset < size)
    {
        if (offset+write_size > size)
            write_size = size-offset;

        int32_t ret = libusb_bulk_transfer(reader->sr_config->usb_dev_handle,
                                    reader->sr_config->in_ep,
                                    buff+offset,
                                    write_size,
                                    &written,
                                    reader->sr_config->usb_write_timeout);
        if (ret < 0) {
            cs_log("usb bulk write failed : ret = %d",ret);
            return(ret);
        }
        cs_ddump_mask(D_DEVICE, buff+offset, written, "SR IO: Transmit: ");
        total_written += written;
        offset += write_size;
    }

    return total_written;
}

int32_t SR_Transmit (struct s_reader *reader, BYTE * buffer, uint32_t size)
{
    uint32_t  ret;

    smart_fastpoll(reader, TRUE);
    ret = smart_write(reader, buffer, size);
    smart_fastpoll(reader, FALSE);
    if (ret!=size)
        return ERROR;

  return OK;
}

int32_t SR_Receive (struct s_reader *reader, BYTE * buffer, uint32_t size)
{
    uint32_t  ret;

    smart_fastpoll(reader, TRUE);
    ret = smart_read(reader, buffer, size, 1);
    smart_fastpoll(reader, FALSE);
    if (ret!=size)
        return ERROR;

  return OK;
}

int32_t SR_WriteSettings (struct s_reader *reader, uint16_t  F, BYTE D, BYTE N, BYTE T, uint16_t  convention)
{
    // smartreader supports 3.20, 3.43, 3.69, 4.00, 4.36, 4.80, 5.34, 6.00, 6.86, 8.00, 9.61, 12.0, 16.0 Mhz
    reader->sr_config->inv = convention;//FIXME this one is set by icc_async and local smartreader reset routine

    if (reader->mhz >=1600) reader->mhz = 1600; else
    if (reader->mhz >=1200) reader->mhz = 1200; else
    if (reader->mhz >=961)  reader->mhz =  961; else
    if (reader->mhz >=800)  reader->mhz =  800; else
    if (reader->mhz >=686)  reader->mhz =  686; else
    if (reader->mhz >=600)  reader->mhz =  600; else
    if (reader->mhz >=534)  reader->mhz =  534; else
    if (reader->mhz >=480)  reader->mhz =  480; else
    if (reader->mhz >=436)  reader->mhz =  436; else
    if (reader->mhz >=400)  reader->mhz =  400; else
    if (reader->mhz >=369)  reader->mhz =  369; else
    if (reader->mhz ==368)  reader->mhz =  369; else
    if (reader->mhz >=343)  reader->mhz =  343; else
        reader->mhz =  320;

    smart_fastpoll(reader, TRUE);
    EnableSmartReader(reader, reader->mhz, F, D, N, T, reader->sr_config->inv,reader->sr_config->parity);

    //baud rate not really used in native mode since
    //it's handled by the card, so just set to maximum 3Mb/s
    smartreader_set_baudrate(reader, 3000000);
    smart_fastpoll(reader, FALSE);

  return OK;
}

int32_t SR_SetParity (struct s_reader *reader, uint16_t  parity)
{
    int32_t ret;

    static const char * const parity_str[5]={"NONE", "ODD", "EVEN", "MARK", "SPACE"};
    cs_debug_mask (D_DEVICE, "IO:SR: Setting parity to %s",parity_str[parity]);

    reader->sr_config->parity = parity;
    smart_fastpoll(reader, TRUE);
    ret = smartreader_set_line_property(reader, (enum smartreader_bits_type) 8, STOP_BIT_2, parity);
    smart_fastpoll(reader, FALSE);
    if(ret)
        return ERROR;

  return OK;
}

int32_t SR_Close (struct s_reader *reader)
{
  if (!reader->sr_config) return OK;
  cs_writelock(&sr_lock);
  cs_debug_mask(D_DEVICE, "IO:SR: Closing smartreader\n");

    reader->sr_config->running=FALSE;
    smart_fastpoll(reader, TRUE);
    pthread_join(reader->sr_config->rt,NULL);
    smart_fastpoll(reader, FALSE);
    libusb_release_interface(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#if defined(OS_LINUX)
    libusb_attach_kernel_driver(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#endif
    libusb_close(reader->sr_config->usb_dev_handle);
    init_count--;
    if (!init_count)
    		libusb_exit(NULL);
    cs_writeunlock(&sr_lock);
    free(reader->sr_config);
    reader->sr_config = NULL;
    return OK;
}

int32_t SR_FastReset(struct s_reader *reader, int32_t delay)
{
    unsigned char data[ATR_MAX_SIZE];
    int32_t ret;

    smart_fastpoll(reader, TRUE);
    //Set the DTR HIGH and RTS HIGH
    smartreader_setdtr_rts(reader, 1, 1);
    // A card with an active low reset is reset by maintaining RST in state L for at least 40 000 clock cycles
    // so if we have a base freq of 3.5712MHz : 40000/3690000 = .0112007168458781 seconds, aka 11ms
    // so if we have a base freq of 6.00MHz : 40000/6000000 = .0066666666666666 seconds, aka 6ms
    cs_sleepms(delay);

    //Set the DTR HIGH and RTS LOW
    smartreader_setdtr_rts(reader, 1, 0);

    //Read the ATR
    ret = smart_read(reader,data, ATR_MAX_SIZE,1);
    smart_fastpoll(reader, FALSE);
    return 0;
}

static void EnableSmartReader(S_READER *reader, int32_t clock, uint16_t  Fi, unsigned char Di, unsigned char Ni, unsigned char T, unsigned char inv,int32_t parity) {

    int32_t ret = 0;
    unsigned char FiDi[4];
    uint16_t  freqk;
    unsigned char Freq[3];
    unsigned char N[2];
    unsigned char Prot[2];
    unsigned char Invert[2];
    unsigned char temp_T;

    ret = smartreader_set_baudrate(reader, 9600);
    smartreader_setflowctrl(reader, 0);
    ret = smartreader_set_line_property(reader, (enum smartreader_bits_type) 5, STOP_BIT_2, NONE);

    // command 1, set F and D parameter
    if(!reader->sr_config->irdeto) {
        cs_debug_mask (D_DEVICE, "IO:SR: sending F=%04X (%d) to smartreader",Fi,Fi);
        cs_debug_mask (D_DEVICE, "IO:SR: sending D=%02X (%d) to smartreader",Di,Di);
        FiDi[0]=0x01;
        FiDi[1]=HIBYTE(Fi);
        FiDi[2]=LOBYTE(Fi);
        FiDi[3]=Di;
        ret = smart_write(reader,FiDi, sizeof (FiDi));
    }
    else {
        cs_debug_mask(D_ATR, "Not setting F and D as we're in Irdeto mode");
    }

    // command 2, set the frequency in KHz
    // direct from the source .. 4MHz is the best init frequency for T=0 card, but looks like it's causing issue with some nagra card, reveting to 3.69MHz
    freqk = clock * 10; //clock with type int32_t couldnt hold freq in Hz on all platforms, so I reverted to 10khz units (like mhz) - dingo
    cs_debug_mask (D_DEVICE, "IO:SR: sending Freq=%04X (%d) to smartreader",freqk,freqk);
    Freq[0]=0x02;
    Freq[1]=HIBYTE(freqk);
    Freq[2]=LOBYTE(freqk);
    ret = smart_write(reader, Freq, sizeof (Freq));

    // command 3, set paramter N
    cs_debug_mask (D_DEVICE, "IO:SR: sending N=%02X (%d) to smartreader",Ni,Ni);
    N[0]=0x03;
    N[1]=Ni;
    ret = smart_write(reader, N, sizeof (N));

    // command 4 , set parameter T
    temp_T=T;
    if(T==2) // special trick to get ATR for Irdeto card, we need T=1 at reset, after that oscam takes care of T1 protocol, so we need T=0
    //if(reader->sr_config->irdeto) // special trick to get ATR for Irdeto card, we need T=1 at reset, after that oscam takes care of T1 protocol, so we need T=0
        {
        T=1;
        reader->sr_config->T=1;
        temp_T=1;
        }
    else if (T==1)
        T=0; // T=1 protocol is handled by oscam

    cs_debug_mask (D_DEVICE, "IO:SR: sending T=%02X (%d) to smartreader",T,T);
    Prot[0]=0x04;
    Prot[1]=T;
    ret = smart_write(reader, Prot, sizeof (Prot));

    // command 5, set invert y/n
    cs_debug_mask (D_DEVICE, "IO:SR: sending inv=%02X to smartreader",inv);
    Invert[0]=0x05;
    Invert[1]=inv;
    ret = smart_write(reader, Invert, sizeof (Invert));

    ret = smartreader_set_line_property2(reader, BITS_8, STOP_BIT_2, parity, BREAK_ON);
    //  send break for 350ms, also comes from JoePub debugging.
    cs_sleepms(350);
    if(temp_T==1)
        ret = smartreader_set_line_property2(reader, BITS_8, STOP_BIT_1, parity, BREAK_OFF);
    else
        ret = smartreader_set_line_property2(reader, BITS_8, STOP_BIT_2, parity, BREAK_OFF);

    smart_flush(reader);
}

static bool smartreader_check_endpoint(libusb_device *usb_dev,uint8_t out_endpoint)
{
    struct libusb_device_descriptor desc;
    struct libusb_config_descriptor *configDesc;
    int32_t ret;
    int32_t j,k,l;
    uint8_t tmpEndpointAddress;
    int32_t nb_endpoint_ok;


    nb_endpoint_ok=0;
    ret = libusb_get_device_descriptor(usb_dev, &desc);
    if (ret < 0) {
        cs_log("Smartreader : couldn't read device descriptor, assuming this is not a smartreader");
        return FALSE;
    }
    if (desc.bNumConfigurations) {
        ret=libusb_get_active_config_descriptor(usb_dev,&configDesc);
        if(ret) {
            cs_log("Smartreader : couldn't read config descriptor , assuming this is not a smartreader");
            return FALSE;
        }

        for(j=0; j<configDesc->bNumInterfaces; j++)
            for(k=0; k<configDesc->interface[j].num_altsetting; k++)
                for(l=0; l<configDesc->interface[j].altsetting[k].bNumEndpoints; l++) {
                    tmpEndpointAddress=configDesc->interface[j].altsetting[k].endpoint[l].bEndpointAddress;
                    if((tmpEndpointAddress == 0x1) || (tmpEndpointAddress == out_endpoint))
                        nb_endpoint_ok++;
                }
    }
    if(nb_endpoint_ok!=2)
        return FALSE;
    return TRUE;
}


static struct libusb_device* find_smartreader(const char *busname,const char *devname, uint8_t out_endpoint)
{
    int32_t dev_found;
  libusb_device *dev;
  libusb_device_handle *usb_dev_handle;
  libusb_device **devs;
    ssize_t cnt;
  int32_t i = 0;
  int32_t ret;
    struct libusb_device_descriptor desc;

  cnt = libusb_get_device_list(NULL, &devs);
  if (cnt < 0)
    return NULL;

  while ((dev = devs[i++]) != NULL) {
        dev_found=FALSE;
    ret = libusb_get_device_descriptor(dev, &desc);
    if (ret < 0) {
      cs_log("failed to get device descriptor for device %s on bus %s\n",devname,busname);
      return NULL;
    }

    if (desc.idVendor==0x0403 && desc.idProduct==0x6001) {
            ret=libusb_open(dev,&usb_dev_handle);
            if (ret) {
                cs_log ("coulnd't open device %03d:%03d\n", libusb_get_bus_number(dev), libusb_get_device_address(dev));
                switch(ret) {
                    case LIBUSB_ERROR_NO_MEM:
                        cs_log("libusb_open error LIBUSB_ERROR_NO_MEM : memory allocation failure");
                        break;
                    case LIBUSB_ERROR_ACCESS:
                        cs_log("libusb_open error LIBUSB_ERROR_ACCESS : the user has insufficient permissions");
                        break;
                    case LIBUSB_ERROR_NO_DEVICE:
                        cs_log("libusb_open error LIBUSB_ERROR_NO_DEVICE : the device has been disconnected");
                        break;
                    default:
                        cs_log("libusb_open unknown error : %d", ret);
                        break;
                }
                continue;
            }

            // If the device is specified as "Serial:number", check iSerial
            if(!strcmp(busname,"Serial")) {
                char iserialbuffer[128];
                if(libusb_get_string_descriptor_ascii(usb_dev_handle,desc.iSerialNumber,iserialbuffer,sizeof(iserialbuffer))>0)  {
                    if(!strcmp(iserialbuffer,devname)) {
                        cs_log("Found reader with serial %s at %03d:%03d",devname,libusb_get_bus_number(dev),libusb_get_device_address(dev));
                        if(smartreader_check_endpoint(dev,out_endpoint))
                            dev_found=TRUE;
                    }
                }
            }
            else if(libusb_get_bus_number(dev)==atoi(busname) && libusb_get_device_address(dev)==atoi(devname)) {
                cs_debug_mask(D_DEVICE, "IO:SR: Checking FTDI device: %03d on bus %03d",libusb_get_device_address(dev),libusb_get_bus_number(dev));
                // check for smargo endpoints.
                if(smartreader_check_endpoint(dev,out_endpoint))
                    dev_found=TRUE;
            }
            libusb_close(usb_dev_handle);
        }

    if (dev_found)
        break;
  }

  if(!dev_found) {
        cs_log("Smartreader device %s:%s not found",busname,devname);
     return NULL;
  }
    else
        cs_log("Found smartreader device %s:%s",busname,devname);

    return dev;
}

void smartreader_init(S_READER *reader,uint8_t out_endpoint)
{
    reader->sr_config->usb_dev = NULL;
    reader->sr_config->usb_dev_handle=NULL;
    reader->sr_config->usb_read_timeout = 10000;
    reader->sr_config->usb_write_timeout = 10000;

    reader->sr_config->type = TYPE_BM;    /* chip type */
    reader->sr_config->baudrate = -1;
    reader->sr_config->bitbang_enabled = 0;  /* 0: normal mode 1: any of the bitbang modes enabled */

    reader->sr_config->writebuffer_chunksize = 64;
    reader->sr_config->max_packet_size = 0;

    reader->sr_config->interface = INTERFACE_ANY;
    reader->sr_config->index = INTERFACE_A;
    reader->sr_config->in_ep = 0x02;
    reader->sr_config->out_ep = out_endpoint;
}


static uint32_t  smartreader_determine_max_packet_size(S_READER *reader)
{
    uint32_t  packet_size;
    struct libusb_device_descriptor desc;
    struct libusb_config_descriptor *configDesc;
    struct libusb_interface interface;
    struct libusb_interface_descriptor intDesc;

    int32_t ret;
    // Determine maximum packet size. Init with default value.
    // New hi-speed devices from FTDI use a packet size of 512 bytes
    // but could be connected to a normal speed USB hub -> 64 bytes packet size.
    if (reader->sr_config->type == TYPE_2232H || reader->sr_config->type == TYPE_4232H)
        packet_size = 512;
    else
        packet_size = 64;

    ret = libusb_get_device_descriptor(reader->sr_config->usb_dev, &desc);
    if (ret < 0) {
        cs_log("Smartreader : couldn't read device descriptor , using default packet size");
        return packet_size;
    }
    if (desc.bNumConfigurations)
    {
        ret=libusb_get_active_config_descriptor(reader->sr_config->usb_dev,&configDesc);
        if(ret) {
            cs_log("Smartreader : couldn't read config descriptor , using default packet size");
            return packet_size;
        }

        if (reader->sr_config->interface < configDesc->bNumInterfaces)
        {
            interface=configDesc->interface[reader->sr_config->interface];
            if (interface.num_altsetting > 0)
            {
                intDesc = interface.altsetting[0];
                if (intDesc.bNumEndpoints > 0)
                {
                    packet_size = intDesc.endpoint[0].wMaxPacketSize;
                }
            }
        }
    }

    return packet_size;
}


static int32_t smartreader_usb_close_internal (S_READER *reader)
{
    int32_t ret = 0;

    if (reader->sr_config->usb_dev_handle)
    {
       libusb_close (reader->sr_config->usb_dev_handle);
       reader->sr_config->usb_dev_handle=NULL;
    }

    return ret;
}


int32_t smartreader_usb_reset(S_READER *reader)
{
    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_RESET_REQUEST,
                                SIO_RESET_SIO,
                                reader->sr_config->index,
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("Smartreader reset failed");
        return (-1);
    }


    return 0;
}


int32_t smartreader_usb_open_dev(S_READER *reader)
{
    int32_t detach_errno = 0;
    struct libusb_device_descriptor desc;
    int32_t ret;

#ifdef __WIN32__
    int32_t config;
    int32_t config_val = 1;
#endif

    ret=libusb_open(reader->sr_config->usb_dev,&reader->sr_config->usb_dev_handle);
    if (ret) {
            cs_log ("coulnd't open SmartReader device %03d:%03d\n", libusb_get_bus_number(reader->sr_config->usb_dev), libusb_get_device_address(reader->sr_config->usb_dev));
            switch(ret) {
                case LIBUSB_ERROR_NO_MEM:
                    cs_log("libusb_open error LIBUSB_ERROR_NO_MEM : memory allocation failure");
                    break;
                case LIBUSB_ERROR_ACCESS:
                    cs_log("libusb_open error LIBUSB_ERROR_ACCESS : the user has insufficient permissions");
                    break;
                case LIBUSB_ERROR_NO_DEVICE:
                    cs_log("libusb_open error LIBUSB_ERROR_NO_DEVICE : the device has been disconnected");
                    break;
                default:
                    cs_log("libusb_open unknown error : %d", ret);
                    break;
            }
        return (-4);
    }

#if defined(OS_LINUX)
    // Try to detach ftdi_sio kernel module.
    // Returns ENODATA if driver is not loaded.
    //
    // The return code is kept in a separate variable and only parsed
    // if usb_set_configuration() or usb_claim_interface() fails as the
    // detach operation might be denied and everything still works fine.
    // Likely scenario is a static smartreader_sio kernel module.
    if (libusb_detach_kernel_driver(reader->sr_config->usb_dev_handle, reader->sr_config->interface) != 0 && errno != ENODATA) {
        detach_errno = errno;
        cs_log("Couldn't detach interface from kernel. Please unload the FTDI drivers");
        return(LIBUSB_ERROR_NOT_SUPPORTED);
    }
#endif
    ret = libusb_get_device_descriptor(reader->sr_config->usb_dev, &desc);

#ifdef __WIN32__
    // set configuration (needed especially for windows)
    // tolerate EBUSY: one device with one configuration, but two interfaces
    //    and libftdi sessions to both interfaces (e.g. FT2232)

    if (desc.bNumConfigurations > 0)
    {
        ret=libusb_get_configuration(reader->sr_config->usb_dev_handle,&config);

        // libusb-win32 on Windows 64 can return a null pointer for a valid device
        if (libusb_set_configuration(reader->sr_config->usb_dev_handle, config) &&
            errno != EBUSY)
        {
#if defined(OS_LINUX)
        		if(detach_errno == 0) libusb_attach_kernel_driver(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#endif
            smartreader_usb_close_internal (reader);
            if (detach_errno == EPERM) {
                cs_log("inappropriate permissions on device!");
                return(-8);
            }
            else {
                cs_log("unable to set usb configuration. Make sure smartreader_sio is unloaded!");
                return (-3);
            }
        }
    }
#endif

    ret=libusb_claim_interface(reader->sr_config->usb_dev_handle, reader->sr_config->interface) ;
    if (ret!= 0)
    {
#if defined(OS_LINUX)
    		if(detach_errno == 0) libusb_attach_kernel_driver(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#endif
        smartreader_usb_close_internal (reader);
        if (detach_errno == EPERM) {
            cs_log("inappropriate permissions on device!");
            return (-8);
        }
        else {
            cs_log("unable to claim usb device. Make sure smartreader_sio is unloaded!");
            return (-5);
        }
    }

    if (smartreader_usb_reset (reader) != 0) {
    		libusb_release_interface(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#if defined(OS_LINUX)
    		if(detach_errno == 0) libusb_attach_kernel_driver(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#endif
        smartreader_usb_close_internal (reader);
        cs_log("smartreader_usb_reset failed");
        return (-6);
    }

    // Try to guess chip type
    // Bug in the BM type chips: bcdDevice is 0x200 for serial == 0
    if (desc.bcdDevice == 0x400 || (desc.bcdDevice == 0x200
            && desc.iSerialNumber == 0))
        reader->sr_config->type = TYPE_BM;
    else if (desc.bcdDevice == 0x200)
        reader->sr_config->type = TYPE_AM;
    else if (desc.bcdDevice == 0x500)
        reader->sr_config->type = TYPE_2232C;
    else if (desc.bcdDevice == 0x600)
        reader->sr_config->type = TYPE_R;
    else if (desc.bcdDevice == 0x700)
        reader->sr_config->type = TYPE_2232H;
    else if (desc.bcdDevice == 0x800)
        reader->sr_config->type = TYPE_4232H;

    // Set default interface on dual/quad type chips
    switch(reader->sr_config->type) {
        case TYPE_2232C:
        case TYPE_2232H:
        case TYPE_4232H:
            if (!reader->sr_config->index)
                reader->sr_config->index = INTERFACE_A;
            break;
        default:
            break;
    }

    // Determine maximum packet size
    reader->sr_config->max_packet_size = smartreader_determine_max_packet_size(reader);

    if (smartreader_set_baudrate (reader, 9600) != 0) {
    		libusb_release_interface(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#if defined(OS_LINUX)
    		if(detach_errno == 0) libusb_attach_kernel_driver(reader->sr_config->usb_dev_handle, reader->sr_config->interface);
#endif
        smartreader_usb_close_internal (reader);
        cs_log("set baudrate failed");
        return (-7);
    }

    return (0);
}


int32_t smartreader_usb_purge_rx_buffer(S_READER *reader)
{
    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_RESET_REQUEST,
                                SIO_RESET_PURGE_RX,
                                reader->sr_config->index,
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("FTDI purge of RX buffer failed");
        return (-1);
    }


    return 0;
}

int32_t smartreader_usb_purge_tx_buffer(S_READER *reader)
{
    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_RESET_REQUEST,
                                SIO_RESET_PURGE_TX,
                                reader->sr_config->index,
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("FTDI purge of TX buffer failed");
        return (-1);
    }

    return 0;
}

int32_t smartreader_usb_purge_buffers(S_READER *reader)
{
    int32_t result;

    result = smartreader_usb_purge_rx_buffer(reader);
    if (result < 0)
        return -1;

    result = smartreader_usb_purge_tx_buffer(reader);
    if (result < 0)
        return -2;

    return 0;
}

static int32_t smartreader_convert_baudrate(int32_t baudrate, S_READER *reader, uint16_t  *value, uint16_t  *index)
{
    static const char am_adjust_up[8] = {0, 0, 0, 1, 0, 3, 2, 1};
    static const char am_adjust_dn[8] = {0, 0, 0, 1, 0, 1, 2, 3};
    static const char frac_code[8] = {0, 3, 2, 4, 1, 5, 6, 7};
    int32_t divisor, best_divisor, best_baud, best_baud_diff;
    uint32_t encoded_divisor;
    int32_t i;

    if (baudrate <= 0)
    {
        // Return error
        return -1;
    }

    divisor = 24000000 / baudrate;

    if (reader->sr_config->type == TYPE_AM)
    {
        // Round down to supported fraction (AM only)
        divisor -= am_adjust_dn[divisor & 7];
    }

    // Try this divisor and the one above it (because division rounds down)
    best_divisor = 0;
    best_baud = 0;
    best_baud_diff = 0;
    for (i = 0; i < 2; i++)
    {
        int32_t try_divisor = divisor + i;
        int32_t baud_estimate;
        int32_t baud_diff;

        // Round up to supported divisor value
        if (try_divisor <= 8)
        {
            // Round up to minimum supported divisor
            try_divisor = 8;
        }
        else if (reader->sr_config->type != TYPE_AM && try_divisor < 12)
        {
            // BM doesn't support divisors 9 through 11 inclusive
            try_divisor = 12;
        }
        else if (divisor < 16)
        {
            // AM doesn't support divisors 9 through 15 inclusive
            try_divisor = 16;
        }
        else
        {
            if (reader->sr_config->type == TYPE_AM)
            {
                // Round up to supported fraction (AM only)
                try_divisor += am_adjust_up[try_divisor & 7];
                if (try_divisor > 0x1FFF8)
                {
                    // Round down to maximum supported divisor value (for AM)
                    try_divisor = 0x1FFF8;
                }
            }
            else
            {
                if (try_divisor > 0x1FFFF)
                {
                    // Round down to maximum supported divisor value (for BM)
                    try_divisor = 0x1FFFF;
                }
            }
        }
        // Get estimated baud rate (to nearest integer)
        baud_estimate = (24000000 + (try_divisor / 2)) / try_divisor;
        // Get absolute difference from requested baud rate
        if (baud_estimate < baudrate)
        {
            baud_diff = baudrate - baud_estimate;
        }
        else
        {
            baud_diff = baud_estimate - baudrate;
        }
        if (i == 0 || baud_diff < best_baud_diff)
        {
            // Closest to requested baud rate so far
            best_divisor = try_divisor;
            best_baud = baud_estimate;
            best_baud_diff = baud_diff;
            if (baud_diff == 0)
            {
                // Spot on! No point trying
                break;
            }
        }
    }
    // Encode the best divisor value
    encoded_divisor = (best_divisor >> 3) | (frac_code[best_divisor & 7] << 14);
    // Deal with special cases for encoded value
    if (encoded_divisor == 1)
    {
        encoded_divisor = 0;    // 3000000 baud
    }
    else if (encoded_divisor == 0x4001)
    {
        encoded_divisor = 1;    // 2000000 baud (BM only)
    }
    // Split into "value" and "index" values
    *value = (uint16_t )(encoded_divisor & 0xFFFF);
    if (reader->sr_config->type == TYPE_2232C || reader->sr_config->type == TYPE_2232H || reader->sr_config->type == TYPE_4232H)
    {
        *index = (uint16_t )(encoded_divisor >> 8);
        *index &= 0xFF00;
        *index |= reader->sr_config->index;
    }
    else
        *index = (uint16_t )(encoded_divisor >> 16);

    // Return the nearest baud rate
    return best_baud;
}

int32_t smartreader_set_baudrate(S_READER *reader, int32_t baudrate)
{
    uint16_t  value, index;
    int32_t actual_baudrate;

    if (reader->sr_config->bitbang_enabled)
    {
        baudrate = baudrate*4;
    }

    actual_baudrate = smartreader_convert_baudrate(baudrate, reader, &value, &index);
    if (actual_baudrate <= 0) {
        cs_log("Silly baudrate <= 0.");
        return (-1);
    }

    // Check within tolerance (about 5%)
    if ((actual_baudrate * 2 < baudrate /* Catch overflows */ )
            || ((actual_baudrate < baudrate)
                ? (actual_baudrate * 21 < baudrate * 20)
                : (baudrate * 21 < actual_baudrate * 20))) {
        cs_log("Unsupported baudrate. Note: bitbang baudrates are automatically multiplied by 4");
        return (-1);
    }

    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_SET_BAUDRATE_REQUEST,
                                value,
                                index,
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("Setting new baudrate failed");
        return (-2);
    }

    reader->sr_config->baudrate = baudrate;
    return 0;
}

int32_t smartreader_setdtr_rts(S_READER *reader, int32_t dtr, int32_t rts)
{
    uint16_t  usb_val;

    if (dtr)
        usb_val = SIO_SET_DTR_HIGH;
    else
        usb_val = SIO_SET_DTR_LOW;

    if (rts)
        usb_val |= SIO_SET_RTS_HIGH;
    else
        usb_val |= SIO_SET_RTS_LOW;

    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_SET_MODEM_CTRL_REQUEST,
                                usb_val,
                                reader->sr_config->index,
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("set of rts/dtr failed");
        return (-1);
    }

    return 0;
}

int32_t smartreader_setflowctrl(S_READER *reader, int32_t flowctrl)
{
    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_SET_FLOW_CTRL_REQUEST,
                                0,
                                (flowctrl | reader->sr_config->index),
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("set flow control failed");
        return (-1);
    }

    return 0;
}

int32_t smartreader_set_line_property2(S_READER *reader, enum smartreader_bits_type bits,
                            enum smartreader_stopbits_type sbit, enum smartreader_parity_type parity,
                            enum smartreader_break_type break_type)
{
    uint16_t  value = bits;

    switch (parity)
    {
        case NONE:
            value |= (0x00 << 8);
            break;
        case ODD:
            value |= (0x01 << 8);
            break;
        case EVEN:
            value |= (0x02 << 8);
            break;
        case MARK:
            value |= (0x03 << 8);
            break;
        case SPACE:
            value |= (0x04 << 8);
            break;
    }

    switch (sbit)
    {
        case STOP_BIT_1:
            value |= (0x00 << 11);
            break;
        case STOP_BIT_15:
            value |= (0x01 << 11);
            break;
        case STOP_BIT_2:
            value |= (0x02 << 11);
            break;
    }

    switch (break_type)
    {
        case BREAK_OFF:
            value |= (0x00 << 14);
            break;
        case BREAK_ON:
            value |= (0x01 << 14);
            break;
    }

    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                                FTDI_DEVICE_OUT_REQTYPE,
                                SIO_SET_DATA_REQUEST,
                                value,
                                reader->sr_config->index,
                                NULL,
                                0,
                                reader->sr_config->usb_write_timeout) != 0) {
        cs_log("Setting new line property failed");
        return (-1);
    }

    return 0;
}


int32_t smartreader_set_line_property(S_READER *reader, enum smartreader_bits_type bits,
                           enum smartreader_stopbits_type sbit, enum smartreader_parity_type parity)
{
    return smartreader_set_line_property2(reader, bits, sbit, parity, BREAK_OFF);
}



void smart_flush(S_READER *reader)
{
    smartreader_usb_purge_buffers(reader);

    pthread_mutex_lock(&reader->sr_config->g_read_mutex);
    reader->sr_config->g_read_buffer_size = 0;
    pthread_mutex_unlock(&reader->sr_config->g_read_mutex);
}

static int32_t smartreader_set_latency_timer(S_READER *reader, uint16_t  latency)
{
    uint16_t  usb_val;

    if (latency < 1) {
        cs_log("latency out of range. Only valid for 1-255");
        return (-1);
    }

    usb_val = latency;
    if (libusb_control_transfer(reader->sr_config->usb_dev_handle,
                        FTDI_DEVICE_OUT_REQTYPE,
                        SIO_SET_LATENCY_TIMER_REQUEST,
                        usb_val,
                        reader->sr_config->index,
                        NULL,
                        0,
                        reader->sr_config->usb_write_timeout) != 0) {
        cs_log("unable to set latency timer");
        return (-2);
    }

    return 0;
}

#ifdef OS_CYGWIN32
static WINAPI read_callback(struct libusb_transfer *transfer){
#else
static void read_callback(struct libusb_transfer *transfer){
#endif
    struct s_reader *reader = (struct s_reader*)transfer->user_data;
    int32_t copy_size;
    int32_t ret;

    if(transfer->status == LIBUSB_TRANSFER_COMPLETED) {
        if(transfer->actual_length > 2) {  //FTDI always sends modem status bytes as first 2 chars with the 232BM
            pthread_mutex_lock(&reader->sr_config->g_read_mutex);

            if(reader->sr_config->g_read_buffer_size == sizeof(reader->sr_config->g_read_buffer)) {
                cs_log("IO:SR: buffer full\n");
                //if out read buffer is full then delay
                //slightly and go around again
                ret = libusb_submit_transfer(transfer);
                if(ret!=0)
                    cs_log("IO:SR: submit async transfer failed with error %d\n",ret);
                pthread_cond_signal(&reader->sr_config->g_read_cond);
                pthread_mutex_unlock(&reader->sr_config->g_read_mutex);
                return;
            }
            reader->sr_config->modem_status = transfer->buffer[0];

            copy_size = sizeof(reader->sr_config->g_read_buffer) - reader->sr_config->g_read_buffer_size > (uint32_t )transfer->actual_length-2 ? (uint32_t )transfer->actual_length-2: sizeof(reader->sr_config->g_read_buffer) - reader->sr_config->g_read_buffer_size;
            memcpy(reader->sr_config->g_read_buffer+reader->sr_config->g_read_buffer_size,transfer->buffer+2,copy_size);
            reader->sr_config->g_read_buffer_size += copy_size;

            pthread_cond_signal(&reader->sr_config->g_read_cond);
            pthread_mutex_unlock(&reader->sr_config->g_read_mutex);
        }
        else {
            if(transfer->actual_length==2) {
                pthread_mutex_lock(&reader->sr_config->g_read_mutex);
                reader->sr_config->modem_status=transfer->buffer[0];
                pthread_mutex_unlock(&reader->sr_config->g_read_mutex);
            }
        }

    ret = libusb_submit_transfer(transfer);

  if(ret!=0)
      cs_log("IO:SR: submit async transfer failed with error %d\n",ret);

    }
    else
         cs_log("IO:SR: USB bulk read failed with error %d\n",transfer->status);
}


static void* ReaderThread(void *p)
{
    struct libusb_transfer* usbt[NUM_TXFERS];
    unsigned char usb_buffers[NUM_TXFERS][64];
    struct s_reader *reader;
    int32_t ret,idx;

    reader = (struct s_reader *)p;
    reader->sr_config->running=TRUE;

    for(idx=0; idx<NUM_TXFERS; idx++) {
         usbt[idx] = libusb_alloc_transfer(0);
         libusb_fill_bulk_transfer( usbt[idx],
                                    reader->sr_config->usb_dev_handle,
                                    reader->sr_config->out_ep,
                                    usb_buffers[idx],
                                    64,
                                    (void *)(&read_callback),
                                    p,
                                    0 );

         ret = libusb_submit_transfer(usbt[idx]);
    }

    while(reader->sr_config->running) {
        ret = libusb_handle_events(NULL);
        if(ret!=0)
            cs_log("libusb_handle_events returned with %d\n",ret);

        pthread_mutex_lock(&reader->sr_config->g_usb_mutex);

        if(!reader->sr_config->poll) {
            struct timeval start = {0};
            struct timespec timeout = {0};

            gettimeofday(&start, NULL);
            timeout.tv_sec = start.tv_sec + 1;
            timeout.tv_nsec = start.tv_usec * 1000;

            pthread_cond_timedwait(&reader->sr_config->g_usb_cond, &reader->sr_config->g_usb_mutex, &timeout);
        }
        pthread_mutex_unlock(&reader->sr_config->g_usb_mutex);
    }

    pthread_exit(NULL);
}

static void smart_fastpoll(S_READER *reader, int32_t on)
{
    pthread_mutex_lock(&reader->sr_config->g_usb_mutex);
    //printf("poll stat: %d\n", on);
    reader->sr_config->poll = on;
    pthread_cond_signal(&reader->sr_config->g_usb_cond);
    pthread_mutex_unlock(&reader->sr_config->g_usb_mutex);
}

#endif // HAVE_LIBUSB
