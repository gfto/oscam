/*
 * libusb example program to list devices on the bus
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#ifdef __FreeBSD__
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif
#define FALSE 0
#define TRUE 1

int out_endpoint;

static int smartreader_check_endpoint(libusb_device *usb_dev)
{
    struct libusb_device_descriptor desc;
    struct libusb_config_descriptor *configDesc;
    int ret;
    int j,k,l;
    u_int8_t tmpEndpointAddress;  
    int nb_endpoint_ok;

    nb_endpoint_ok=0;
    
    ret = libusb_get_device_descriptor(usb_dev, &desc);
    if (ret < 0) {
        printf("Smartreader : couldn't read device descriptor, assuming this is not a smartreader");
        return FALSE;        
    }
    if (desc.bNumConfigurations) {
        ret=libusb_get_active_config_descriptor(usb_dev,&configDesc);
        if(ret) {
            printf("Smartreader : couldn't read config descriptor , assuming this is not a smartreader");
            return FALSE;
        }

        for(j=0; j<configDesc->bNumInterfaces; j++) 
            for(k=0; k<configDesc->interface[j].num_altsetting; k++)
                for(l=0; l<configDesc->interface[j].altsetting[k].bNumEndpoints; l++) {
                    tmpEndpointAddress=configDesc->interface[j].altsetting[k].endpoint[l].bEndpointAddress;
                    if((tmpEndpointAddress== 0x1) || (tmpEndpointAddress== 0x81) || (tmpEndpointAddress== 0x82))
                    	{
                            if(tmpEndpointAddress == 0x1 || tmpEndpointAddress==out_endpoint)
                            {
                                nb_endpoint_ok++;
                            }
                      }
                }
    }
    
    if(nb_endpoint_ok!=2)
        return FALSE;
    return TRUE;
}

static void print_devs(libusb_device **devs)
{
	libusb_device *dev;
	libusb_device_handle *handle;
	int i = 0;
	int ret;
    int busid, devid;
    unsigned char iserialbuffer[128];
    
	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return;
		}
		if (desc.idVendor==0x0403 && desc.idProduct==0x6001) {
            
            ret=libusb_open(dev,&handle);
            if (ret) {
                printf ("coulnd't open device %03d:%03d\n", libusb_get_bus_number(dev), libusb_get_device_address(dev));
                continue;
            }
            // check for smargo endpoints.
            if(smartreader_check_endpoint(dev)) {
            busid=libusb_get_bus_number(dev);
            devid=libusb_get_device_address(dev);
            libusb_get_string_descriptor_ascii(handle,desc.iSerialNumber,iserialbuffer,sizeof(iserialbuffer));
            printf("bus %03d, device %03d : %04x:%04x Smartreader (Device=%03d:%03d EndPoint=0x%2X insert in oscam.server 'Device = Serial:%s')\n",
                            busid, devid,
                            desc.idVendor, desc.idProduct,
                            busid, devid, out_endpoint, iserialbuffer);
            }
            
            libusb_close(handle);
        }
        
	}
}

int main(int argc, char **argv)
{
	libusb_device **devs;
	int r;
	ssize_t cnt;

	r = libusb_init(NULL);
	if (r < 0)
		return r;
    
    out_endpoint=0x82;
    if(argc==2) {
        sscanf(argv[1],"%x",&out_endpoint);
    }
    else
        out_endpoint=0x82;

    printf("Looking for smartreader with an out endpoint = 0x%02x :\n",out_endpoint);
    
	cnt = libusb_get_device_list(NULL, &devs);
	if (cnt < 0) 
		return (int) cnt;
    

    print_devs(devs);
	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);
	return 0;
}

