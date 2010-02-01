#if defined(LIBUSB)
/*
		ifd_smartreader.c
		This module provides IFD handling functions for for Argolis smartreader+.
*/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include"ifd_smartreader.h"

#define OK 0
#define ERROR 1
#define LOBYTE(w) ((BYTE)((w) & 0xff))
#define HIBYTE(w) ((BYTE)((w) >> 8))

static struct usb_device * find_smartreader(const char *devname, const char*busname, struct ftdi_context* ftdic);
static void smart_flush(struct s_reader *reader);
static unsigned int smart_read(struct s_reader *reader, unsigned char* buff, int size, int timeout_sec);
static unsigned int smart_write(struct s_reader *reader, unsigned char* buff, int size, int udelay);
static void EnableSmartReader(struct s_reader *reader, int clock, unsigned short Fi, unsigned char Di, unsigned char Ni, unsigned char T,unsigned char inv, int parity);
static void ResetSmartReader(struct s_reader *reader);
static void* ReaderThread(void *p);
static bool smartreader_check_endpoint(struct usb_device *dev);

#ifdef DEBUG_USB_IO
static void sr_hexdump(const unsigned char* data, size_t size, bool single);
#endif

extern int usb_debug;

int SR_Init (struct s_reader *reader)
{
    
    int ret;
    char device[128];
    char *busname;
    char *devname;
    char *search = ":";
    // split the device name from the reader conf into devname and busname
    memcpy(device,reader->device,128);
    busname=strtok(device,search);
    devname=strtok(NULL,search);
    if(!busname || !devname) {
        cs_log("Wrong device format (%s), it should be Device=bus:dev",reader->device);
        return ERROR;
    }
#ifdef DEBUG_USB_IO
    usb_debug=0;
    cs_log("looking for device %s on bus %s",devname,busname);
#endif
    reader->smartreader_usb_dev=NULL;
    if(!(reader->smartreader_usb_dev=find_smartreader((const char *)devname,(const char *)busname, &reader->ftdic)))
        return ERROR;
    //The smartreader has different endpoint addresses
    //compared to a real FT232 device, so change them here,
    //also a good way to compare a real FT232 with a smartreader
    //if you enumarate usb devices
    reader->ftdic.in_ep = 0x1;
    reader->ftdic.out_ep = 0x82;

    ftdi_write_data_set_chunksize(&reader->ftdic,64);
    
    //open the smartreader device if found by find_smartreader
    if ((ret = ftdi_usb_open_dev(&reader->ftdic,reader->smartreader_usb_dev)) < 0) {
        cs_log("unable to open ftdi device %s:%s (ret=%d error=%s)",busname,devname, ret, ftdi_get_error_string(&reader->ftdic));
        return ERROR;
    }
    ftdi_usb_reset(&reader->ftdic);
    
#ifdef DEBUG_USB_IO
    cs_log("IO:SR: Setting smartreader latency timer to 1ms");
#endif
    //Set the FTDI latency timer to 1ms
    ret = ftdi_set_latency_timer(&reader->ftdic, 1);
    if(ret)
        cs_log("IO:SR: ERROR Setting smartreader latency timer to 1ms");

    //Set databits to 8o2
    ret = ftdi_set_line_property(&reader->ftdic, BITS_8, STOP_BIT_2, ODD);

    //Set the DTR LOW and RTS LOW
    ftdi_setdtr_rts(&reader->ftdic, 0, 0);

    //Disable flow control
    ftdi_setflowctrl(&reader->ftdic, 0);
    
    // star the reading thread
    reader->g_read_buffer_size = 0;
    reader->modem_status = 0 ;
    pthread_mutex_init(&reader->g_read_mutex,NULL);
    pthread_mutex_init(&reader->g_usb_mutex,NULL);
    ret = pthread_create(&reader->rt, NULL, ReaderThread, (void *)(reader));
    if (ret) {
        cs_log("ERROR; return code from pthread_create() is %d", ret);
        return ERROR;
    }

	return OK;
}


int SR_GetStatus (struct s_reader *reader, int * in)
{
	int state;

    pthread_mutex_lock(&reader->g_read_mutex);
    state =(reader->modem_status & 0x80) == 0x80 ? 0 : 2;
    pthread_mutex_unlock(&reader->g_read_mutex);

    
	//state = 0 no card, 1 = not ready, 2 = ready
	if (state)
		*in = 1; //CARD, even if not ready report card is in, or it will never get activated
	else
		*in = 0; //NOCARD
	return OK;
}

int SR_Reset (struct s_reader *reader, ATR *atr)
{
    unsigned char data[40];
    int ret;
    int atr_ok;
    int i;
    int parity[3] = {ODD, EVEN, NONE};
    
    if(reader->mhz==reader->cardmhz && reader->cardmhz*10000 > 4000000)
        reader->sr_config.fs=reader->cardmhz*10000; 
    else    
        reader->sr_config.fs=4000000; 
    
    
    for(i=0 ; i<3 ;i++) {
        atr_ok=ERROR;
        memset(data,0,sizeof(data));
        reader->sr_config.parity=parity[i];

        ResetSmartReader(reader);

        //Reset smartcard
    
        //Set the DTR HIGH and RTS HIGH
        ftdi_setdtr_rts(&reader->ftdic, 1, 1);
        // A card with an active low reset is reset by maintaining RST in state L for at least 40 000 clock cycles
        // so if we have a base freq of 3.5712MHz : 40000/4000000 = .0112007168458781 seconds, aka 11ms
        // so if we have a base freq of 6.00MHz : 40000/6000000 = .0066666666666666 seconds, aka 6ms
        // here were doing 200ms .. is it too much ?
        usleep(200000);
        
        //Set the DTR HIGH and RTS LOW
        ftdi_setdtr_rts(&reader->ftdic, 1, 0);
    
        usleep(200000);
        sched_yield();
    
        //Read the ATR
        ret = smart_read(reader,data, 40,1);
#ifdef DEBUG_USB_IO
        cs_log("IO:SR: get ATR ret = %d" , ret);
        if(ret)
            sr_hexdump(data,ATR_MAX_SIZE*2,FALSE);
#endif
        if(data[0]!=0x3B && data[0]!=0x03 && data[0]!=0x3F)
            continue; // this is not a valid ATR.
            
        if(data[0]==0x03) {
#ifdef DEBUG_USB_IO
            cs_log("IO:SR: Inverse convention detected, setting smartreader inv to 1");
#endif
            reader->sr_config.inv=1;
            EnableSmartReader(reader, reader->sr_config.fs, 372, 1, 0, 0, reader->sr_config.inv, reader->sr_config.parity);
        }
        // parse atr
        if(ATR_InitFromArray (atr, data, ret) == ATR_OK) {
#ifdef DEBUG_USB_IO
            cs_log("IO:SR: ATR parsing OK");
#endif
            atr_ok=OK;
        }

        if(atr_ok == OK)
            break;
     }


    return atr_ok;
}

int SR_Transmit (struct s_reader *reader, BYTE * buffer, unsigned size)

{ 
    unsigned int ret;
    ret = smart_write(reader, buffer, size, 0);
    if (ret!=size)
        return ERROR;
        
	return OK;
}

int SR_Receive (struct s_reader *reader, BYTE * buffer, unsigned size)
{ 
    unsigned int ret;
    ret = smart_read(reader, buffer, size, 1);
    if (ret!=size)
        return ERROR;

	return OK;
}	

int SR_SetBaudrate (struct s_reader *reader)
{
    reader->sr_config.fs=reader->mhz*10000; //freq in KHz
    EnableSmartReader(reader, reader->sr_config.fs, reader->sr_config.F, (BYTE)reader->sr_config.D, reader->sr_config.N, reader->sr_config.T, reader->sr_config.inv,reader->sr_config.parity);
    //baud rate not really used in native mode since
    //it's handled by the card, so just set to maximum 3Mb/s
    ftdi_set_baudrate(&reader->ftdic, 3000000);
    sched_yield();

	return OK;
}

int SR_SetParity (struct s_reader *reader)
{
    int ret;
    ret = ftdi_set_line_property(&reader->ftdic, (enum ftdi_bits_type) 8, STOP_BIT_2, reader->sr_config.parity);
    if(ret)
        return ERROR;
        
    sched_yield();

	return OK;
}

int SR_Close (struct s_reader *reader)
{
#ifdef DEBUG_USB_IO
	printf ("IO:SR: Closing smarteader\n");
#endif

    ftdi_deinit(&reader->ftdic);
    reader[ridx].status = 0;
    return OK;

}

static struct usb_device * find_smartreader(const char *devname, const char*busname, struct ftdi_context* ftdic)
{
    bool dev_found;
    struct usb_bus *bus;
    struct usb_device *dev;

    if (ftdi_init(ftdic) < 0) {
        cs_log("ftdi_init failed");
        return NULL;
    }
    usb_init();
    if (usb_find_busses() < 0) {
        cs_log("usb_find_busses() failed");
        return NULL;
    }
    if (usb_find_devices() < 0) {
        cs_log("usb_find_devices() failed");
        return NULL;
    }


    dev_found=FALSE;
    for (bus = usb_get_busses(); bus; bus = bus->next) {
        for (dev = bus->devices; dev; dev = dev->next) {
            if ( (dev->descriptor.idVendor != 0x0403) || (dev->descriptor.idProduct != 0x6001))
                    continue;
#ifdef DEBUG_USB_IO
            cs_log("IO:SR: Checking FTDI device: %s on bus %s", dev->filename,dev->bus->dirname);
#endif
            if(smartreader_check_endpoint(dev)) {
                // compare devname and bussname
                if(strcmp(dev->filename,devname)==0 && strcmp(dev->bus->dirname,busname)==0) {
                    dev_found=TRUE;
                    break;
                }
            }
        }
        if(dev_found) {
            cs_log("Found smartreader device %s:%s",busname,devname);
            break;
        }
    }

    if(!dev_found) {
        cs_log("Smartreader device %s:%s not found",busname,devname);
        ftdi_deinit(ftdic);
        return NULL;
        }

    return dev;
}

static void smart_flush(struct s_reader *reader)
{

    ftdi_usb_purge_buffers(&reader->ftdic);

    pthread_mutex_lock(&reader->g_read_mutex);
    reader->g_read_buffer_size = 0;
    pthread_mutex_unlock(&reader->g_read_mutex);
    sched_yield();
}

static unsigned int smart_read(struct s_reader *reader, unsigned char* buff, int size, int timeout_sec)
{

    int ret = 0;
    int total_read = 0;
    struct timeval start, now, dif = {0,0};
    gettimeofday(&start,NULL);
    

    while(total_read < (int)size && dif.tv_sec < timeout_sec) {

        pthread_mutex_lock(&reader->g_read_mutex);
        if(reader->g_read_buffer_size > 0) {
        
            ret = reader->g_read_buffer_size > size-total_read ? size-total_read : reader->g_read_buffer_size;
#ifdef DEBUG_IO
        if(usb_debug) {
            cs_log("IO:SR: %d byte to read %d, %d bytes read",size, total_read);
        }
#endif

            memcpy(buff+total_read,reader->g_read_buffer,ret);
            reader->g_read_buffer_size -= ret;
            total_read+=ret;
        }
        pthread_mutex_unlock(&reader->g_read_mutex);
       
        gettimeofday(&now,NULL);
        timersub(&now, &start, &dif);
        usleep(50);
        sched_yield();
    }

    
    return total_read;
}

static unsigned int smart_write(struct s_reader *reader, unsigned char* buff, int size, int udelay)
{

    int ret = 0;
    int idx;

    if (udelay == 0) {
        ret = ftdi_write_data(&reader->ftdic, buff, size);
        if(ret<0) {
#ifdef DEBUG_USB_IO
            cs_log("IO:SR: USB write error : %d , %s",ret,reader->ftdic.error_str );
#endif
        }
    }
    else {
        for (idx = 0; idx < size; idx++) {
            if ((ret = ftdi_write_data(&reader->ftdic, &buff[idx], 1)) < 0){
                break;
            }
            usleep(udelay);
        }
    }
    sched_yield();
    return ret;
}

static void EnableSmartReader(struct s_reader *reader, int clock, unsigned short Fi, unsigned char Di, unsigned char Ni, unsigned char T, unsigned char inv,int parity) {

    int ret = 0;
    int delay=50000;
    unsigned char FiDi[4];
    unsigned short freqk;
    unsigned char Freq[3];
    unsigned char N[2];
    unsigned char Prot[2];
    unsigned char Invert[2];
    
    ret = ftdi_set_baudrate(&reader->ftdic, 9600);
    ftdi_setflowctrl(&reader->ftdic, 0);
    ret = ftdi_set_line_property(&reader->ftdic, (enum ftdi_bits_type) 5, STOP_BIT_2, parity);
#ifdef DEBUG_USB_IO
    cs_log("IO:SR: sending F=%04X to smartreader",Fi);
    cs_log("IO:SR: sending D=%02X to smartreader",Di);
#endif
    usleep(delay);
    // command 1, set F and D parameter
    FiDi[0]=0x01;
    FiDi[1]=HIBYTE(Fi);
    FiDi[2]=LOBYTE(Fi);
    FiDi[3]=Di;
    ret = smart_write(reader,FiDi, sizeof (FiDi),0);
    usleep(delay);

    // command 2, set the frequency in KHz
    // direct from the source .. 4MHz is the best init frequency for T=0 card
    // if (clock<4000000 && T==0)
    if (clock<4000000)
        clock=4000000;
    freqk = (unsigned short) (clock / 1000);
#ifdef DEBUG_USB_IO
    cs_log("IO:SR: sending Freq=%d to smartreader",freqk);
#endif
    Freq[0]=0x02;
    Freq[1]=HIBYTE(freqk);
    Freq[2]=LOBYTE(freqk);
    ret = smart_write(reader, Freq, sizeof (Freq),0);
    usleep(delay);

    // command 3, set paramter N
#ifdef DEBUG_USB_IO
    cs_log("IO:SR: sending N=%02X to smartreader",Ni);
#endif
    N[0]=0x03;
    N[1]=Ni;
    ret = smart_write(reader, N, sizeof (N),0);
    usleep(delay);

    // command 4 , set parameter T
#ifdef DEBUG_USB_IO
    cs_log("IO:SR: sending T=%02X to smartreader",T);
#endif
    // this is a test.
    T=0; // protocol is handled by oscam
    // 
    Prot[0]=0x04;
    Prot[1]=T;
    ret = smart_write(reader, Prot, sizeof (Prot),0);
    usleep(delay);

    // command 5, set invert y/n
#ifdef DEBUG_USB_IO
    cs_log("IO:SR: sending inv=%02X to smartreader",inv);
#endif
    Invert[0]=0x05;
    Invert[1]=inv;
    ret = smart_write(reader, Invert, sizeof (Invert),0);
    usleep(delay);

    ret = ftdi_set_line_property2(&reader->ftdic, BITS_8, STOP_BIT_2, parity, BREAK_ON);
    //  send break for 350ms, also comes from JoePub debugging.
    usleep(350000);
    ret = ftdi_set_line_property2(&reader->ftdic, BITS_8, STOP_BIT_2, parity, BREAK_OFF);

    smart_flush(reader);
}

static void ResetSmartReader(struct s_reader *reader) 
{

    smart_flush(reader);
    // set smartreader+ default values 
    reader->sr_config.F=372; 
    reader->sr_config.D=1.0; 
    if(reader->mhz==reader->cardmhz && reader->cardmhz*10000 > 4000000)
        reader->sr_config.fs=reader->cardmhz*10000; 
    else    
        reader->sr_config.fs=4000000; 
    reader->sr_config.N=0; 
    reader->sr_config.T=0; 
    reader->sr_config.inv=0; 
    
    EnableSmartReader(reader, reader->sr_config.fs, reader->sr_config.F, (BYTE)reader->sr_config.D, reader->sr_config.N, reader->sr_config.T, reader->sr_config.inv,reader->sr_config.parity);
    sched_yield();

}

static void* ReaderThread(void *p)
{

    struct s_reader *reader;
    bool running = TRUE;
    int ret;
    int copy_size;
    unsigned char local_buffer[64];  //64 is max transfer size of FTDI bulk pipe

    reader = (struct s_reader *)p;

    while(running){

        if(reader->g_read_buffer_size == sizeof(reader->g_read_buffer)){
            //if out read buffer is full then delay
            //slightly and go around again
            usleep(20000);
            continue;
        }

        ret = usb_bulk_read(reader->ftdic.usb_dev,reader->ftdic.out_ep,(char*)local_buffer,64,1000);
        if(ret<0) {
#ifdef DEBUG_USB_IO
            cs_log("IO:SR: usb_bulk_read read error %d",ret);
#endif
        }
        sched_yield();
#ifdef DEBUG_IO
        if(usb_debug) {
            cs_log("IO:SR: usb_bulk_read read %d bytes",ret);
        }
#endif
        if(ret>2) {  //FTDI always sends modem status bytes as first 2 chars with the 232BM
            pthread_mutex_lock(&reader->g_read_mutex);
            reader->modem_status=local_buffer[0];
            copy_size = (int)sizeof(reader->g_read_buffer) - reader->g_read_buffer_size > ret-2 ? ret-2 : (int)sizeof(reader->g_read_buffer) - reader->g_read_buffer_size;
            memcpy(reader->g_read_buffer+reader->g_read_buffer_size,local_buffer+2,copy_size);
            reader->g_read_buffer_size += copy_size;            
            pthread_mutex_unlock(&reader->g_read_mutex);
        } 
        else {
            if(ret==2) {
                pthread_mutex_lock(&reader->g_read_mutex);
                reader->modem_status=local_buffer[0];
                pthread_mutex_unlock(&reader->g_read_mutex);
            }
        }
    }

    pthread_exit(NULL);
}


static bool smartreader_check_endpoint(struct usb_device *dev)
{
    int nb_interfaces;
    int i,j,k,l;
    u_int8_t tmpEndpointAddress;
    int nb_endpoint_ok;

    if (!dev->config) {
#ifdef DEBUG_USB_IO
        cs_log("IO:SR:  Couldn't retrieve descriptors");
#endif
        return FALSE;
    }
        
    nb_interfaces=dev->config->bNumInterfaces;
    // smartreader only has 1 interface
    if(nb_interfaces!=1) {
#ifdef DEBUG_USB_IO
        cs_log("IO:SR:  Couldn't retrieve interfaces");
#endif
        return FALSE;
    }

    nb_endpoint_ok=0;
    for (i = 0; i < dev->descriptor.bNumConfigurations; i++)
        for (j = 0; j < dev->config[i].bNumInterfaces; j++)
            for (k = 0; k < dev->config[i].interface[j].num_altsetting; k++)
                for (l = 0; l < dev->config[i].interface[j].altsetting[k].bNumEndpoints; l++) {
                    tmpEndpointAddress=dev->config[i].interface[j].altsetting[k].endpoint[l].bEndpointAddress;
#ifdef DEBUG_USB_IO
                    // cs_log("IO:SR:  checking endpoint address %02X on bus %03X of device %03x",tmpEndpointAddress,dev->);
                    cs_log("IO:SR:  checking endpoint address %02X",tmpEndpointAddress);
#endif
                    if((tmpEndpointAddress== 0x1) || (tmpEndpointAddress== 0x82))
                        nb_endpoint_ok++;
                }

    if(nb_endpoint_ok!=2)
        return FALSE;
    return TRUE;
}

#ifdef DEBUG_USB_IO
static void sr_hexdump(const unsigned char* data, size_t size, bool single)
{
    unsigned int idx;
    unsigned int i;
    char buffer[512];

    memset(buffer,0,512);
    i=0;
    for (idx = 0; idx < size; idx++) {
        if(!single && idx % 16 == 0 && idx != 0){
            cs_log("IO:SR: %s",buffer);
            memset(buffer,0,512);
            i=0;
        }
        if((i+1)*3 >= 509) {
            cs_log("IO:SR: %s",buffer);
            memset(buffer,0,512);
            i=0;
        }

        sprintf(buffer+i*3,"%02X ", data[idx]);
        i++;
    }
}
#endif

#endif // HAVE_LIBUSB && USE_PTHREAD
