#include "globals.h"

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#include <ifaddrs.h>
#elif defined(__SOLARIS__)
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/sockio.h>
#else
#include <net/if.h>
#endif

#include "oscam-conf.h"
#include "oscam-conf-chk.h"

#define cs_srvr "oscam.server"

void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	int32_t i;
	char *ptr, *ptr2, *ptr3, *saveptr1 = NULL;
	/*
	 *  case sensitive first
	 */
	if (!strcmp(token, "device")) {
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
			trim(ptr);
			switch(i) {
				case 0:
					cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
					break;

				case 1:
					rdr->r_port = atoi(ptr);
					break;

				case 2:
					rdr->l_port = atoi(ptr);
					break;
			}
		}
		return;
	}

#ifdef WITH_LIBUSB
	if (!strcmp(token, "device_out_endpoint")) {
		if (strlen(value) > 0) {
			sscanf(value, "0x%2X", &i);
			rdr->device_endpoint = i;
		} else {
			rdr->device_endpoint = 0;
		}
		return;
	}
#endif

	if (!strcmp(token, "key")) {
		if (strlen(value) == 0){
			return;
		} else if (key_atob_l(value, rdr->ncd_key, 28)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			memset(rdr->ncd_key, 0, sizeof(rdr->ncd_key));
		}
		return;
	}

	if (!strcmp(token, "password")) {
		cs_strncpy(rdr->r_pwd, value, sizeof(rdr->r_pwd));
		return;
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(rdr->r_usr, value, sizeof(rdr->r_usr));
		return;
	}

#ifdef WEBIF
	if (!strcmp(token, "description")) {
		NULLFREE(rdr->description);
		if(strlen(value) > 0 && cs_malloc(&rdr->description, strlen(value)+1, -1)){
			cs_strncpy(rdr->description, value, strlen(value)+1);
		}
		return;
	}
#endif

  if (!strcmp(token, "mg-encrypted")) {
    uchar key[16];
    uchar mac[6];
    char tmp_dbg[13];
    uchar *buf = NULL;
    int32_t len = 0;

    memset(&key, 0, 16);
    memset(&mac, 0, 6);

    for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
      trim(ptr);
      switch(i) {
        case 0:
          len = strlen(ptr) / 2 + (16 - (strlen(ptr) / 2) % 16);
          if(!cs_malloc(&buf,len, -1)) return;
          key_atob_l(ptr, buf, strlen(ptr));
          cs_log("enc %d: %s", len, ptr);
          break;

        case 1:
          key_atob_l(ptr, mac, 12);
          cs_log("mac: %s", ptr);
          break;
      }
    }

    if (!memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6)) {
#if defined(__APPLE__) || defined(__FreeBSD__)
      // no mac address specified so use mac of en0 on local box
      struct ifaddrs *ifs, *current;

      if (getifaddrs(&ifs) == 0)
      {
         for (current = ifs; current != 0; current = current->ifa_next)
         {
            if (current->ifa_addr->sa_family == AF_LINK && strcmp(current->ifa_name, "en0") == 0)
            {
               struct sockaddr_dl *sdl = (struct sockaddr_dl *)current->ifa_addr;
               memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
               break;
            }
         }
         freeifaddrs(ifs);
      }
#elif defined(__SOLARIS__)
			// no mac address specified so use first filled mac
			int32_t j, sock, niccount;
			struct ifreq nicnumber[16];
			struct ifconf ifconf;
			struct arpreq arpreq;

			if ((sock=socket(AF_INET,SOCK_DGRAM,0)) > -1){
				ifconf.ifc_buf = (caddr_t)nicnumber;
				ifconf.ifc_len = sizeof(nicnumber);
				if (!ioctl(sock,SIOCGIFCONF,(char*)&ifconf)){
					niccount = ifconf.ifc_len/(sizeof(struct ifreq));
					for(i = 0; i < niccount, ++i){
						memset(&arpreq, 0, sizeof(arpreq));
						((struct sockaddr_in*)&arpreq.arp_pa)->sin_addr.s_addr = ((struct sockaddr_in*)&nicnumber[i].ifr_addr)->sin_addr.s_addr;
						if (!(ioctl(sock,SIOCGARP,(char*)&arpreq))){
							for (j = 0; j < 6; ++j)
								mac[j] = (unsigned char)arpreq.arp_ha.sa_data[j];
							if(check_filled(mac, 6) > 0) break;
						}
					}
				}
				close(sock);
			}
#else
      // no mac address specified so use mac of eth0 on local box
      int32_t fd = socket(PF_INET, SOCK_STREAM, 0);

      struct ifreq ifreq;
      memset(&ifreq, 0, sizeof(ifreq));
      snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "eth0");

      ioctl(fd, SIOCGIFHWADDR, &ifreq);
      memcpy(mac, ifreq.ifr_ifru.ifru_hwaddr.sa_data, 6);

      close(fd);
#endif
			cs_debug_mask(D_TRACE, "Determined local mac address for mg-encrypted as %s", cs_hexdump(1, mac, 6, tmp_dbg, sizeof(tmp_dbg)));
    }

    // decrypt encrypted mgcamd gbox line
    for (i = 0; i < 6; i++)
      key[i * 2] = mac[i];

    AES_KEY aeskey;
    AES_set_decrypt_key(key, 128, &aeskey);
    for (i = 0; i < len; i+=16)
      AES_decrypt(buf + i,buf + i, &aeskey);

    // parse d-line
    for (i = 0, ptr = strtok_r((char *)buf, " {", &saveptr1); (i < 5) && (ptr); ptr = strtok_r(NULL, " {", &saveptr1), i++) {
      trim(ptr);
      switch(i) {
        case 1:    // hostname
          cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
          break;
        case 2:   // local port
          cfg.gbox_port = atoi(ptr);  // ***WARNING CHANGE OF GLOBAL LISTEN PORT FROM WITHIN READER!!!***
          break;
        case 3:   // remote port
          rdr->r_port = atoi(ptr);
          break;
        case 4:   // password
          cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
          break;
      }
    }

    free(buf);
    return;
  }

	//legacy parameter containing account=user,pass
	if (!strcmp(token, "account")) {
		if (strstr(value, ",")) {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				trim(ptr);
				switch(i) {
					case 0:
						cs_strncpy(rdr->r_usr, ptr, sizeof(rdr->r_usr));
						break;

					case 1:
						cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
						break;
				}
			}
		} else {
			cs_strncpy(rdr->r_usr, value, sizeof(rdr->r_usr));
		}
		return;
	}

	if (!strcmp(token, "pincode")) {
		cs_strncpy(rdr->pincode, value, sizeof(rdr->pincode));
		return;
	}

	if (!strcmp(token, "readnano")) {
		NULLFREE(rdr->emmfile);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(rdr->emmfile), strlen(value) + 1, -1)) return;
			memcpy(rdr->emmfile, value, strlen(value) + 1);
		}
		return;
	}

	/*
	 *  case insensitive
	 */
	strtolower(value);

	if (!strcmp(token, "enable")) {
		rdr->enable  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "services")) {
		if(strlen(value) == 0) {
			rdr->sidtabok = 0;
			rdr->sidtabno = 0;
			rdr->changes_since_shareupdate = 1;
			return;
		} else {
			chk_services(value, &rdr->sidtabok, &rdr->sidtabno);
			rdr->changes_since_shareupdate = 1;
			return;
		}
	}

	if (!strcmp(token, "inactivitytimeout")) {
		rdr->tcp_ito  = strToIntVal(value, rdr->typ == R_CCCAM?30:DEFAULT_INACTIVITYTIMEOUT);
		return;
	}

	if (!strcmp(token, "resetcycle")) {
		rdr->resetcycle  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "reconnecttimeout")) {
		rdr->tcp_rto  = strToIntVal(value, DEFAULT_TCP_RECONNECT_TIMEOUT);
		return;
	}

	if (!strcmp(token, "disableserverfilter")) {
		rdr->ncd_disable_server_filt  = strToIntVal(value, 0);
		return;
	}

	//FIXME workaround for Smargo until native mode works
	if (!strcmp(token, "smargopatch")) {
		rdr->smargopatch  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "sc8in1_dtrrts_patch")) {
		rdr->sc8in1_dtrrts_patch  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "label")) {
		int32_t found = 0;
		for(i = 0; i < (int)strlen(value); i++) {
			if (value[i] == ' ') {
				value[i] = '_';
				found++;
			}
		}

		if (found) fprintf(stderr, "Configuration reader: corrected label to %s\n",value);
		cs_strncpy(rdr->label, value, sizeof(rdr->label));
		return;
	}

	if (!strcmp(token, "fallback")) {
		rdr->fallback  = strToIntVal(value, 0);
		return;
	}

#ifdef CS_CACHEEX
	if (!strcmp(token, "cacheex")) {
		rdr->cacheex  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cacheex_maxhop")) {
		rdr->cacheex_maxhop  = strToIntVal(value, 0);
		return;
	}
#endif

	if (!strcmp(token, "logport")) {
		rdr->log_port  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "caid")) {
		if(strlen(value) == 0) {
			clear_caidtab(&rdr->ctab);
			rdr->changes_since_shareupdate = 1;
			return;
		} else {
			chk_caidtab(value, &rdr->ctab);
			rdr->changes_since_shareupdate = 1;
			return;
		}
	}

  if (!strcmp(token, "boxid")) {
    if(strlen(value) == 0) {
      rdr->boxid = 0;
      return;
    } else {
      rdr->boxid = a2i(value, 4);
      return;
    }
  }

  if (!strcmp(token, "fix9993")) {
    rdr->fix_9993 = strToIntVal(value, 0);
    return;
  }

	if (!strcmp(token, "rsakey")) {
		int32_t len = strlen(value);
		if(len != 128 && len != 240) {
			memset(rdr->rsa_mod, 0, 120);
			return;
		} else {
			if (key_atob_l(value, rdr->rsa_mod, len)) {
				fprintf(stderr, "Configuration reader: Error in rsakey\n");
				memset(rdr->rsa_mod, 0, sizeof(rdr->rsa_mod));
			}
			return;
		}
	}

	if (!strcmp(token, "ins7e")) {
		int32_t len = strlen(value);
		if (len != 0x1A*2 || key_atob_l(value, rdr->ins7E, len)) {
			if (len > 0)
				fprintf(stderr, "Configuration reader: Error in ins7E\n");
			memset(rdr->ins7E, 0, sizeof(rdr->ins7E));
		}
		else
			rdr->ins7E[0x1A] = 1; // found and correct
		return;
	}

	if (!strcmp(token, "ins7e11")) {
		int32_t len = strlen(value);
		if (len != 0x01*2 || key_atob_l(value, rdr->ins7E11, len)) {
			if (len > 0)
				fprintf(stderr, "Configuration reader: Error in ins7E11\n");
			memset(rdr->ins7E11, 0, sizeof(rdr->ins7E11));
		}
		else
			rdr->ins7E11[0x01] = 1; // found and correct
		return;
	}

	if (!strcmp(token, "boxkey")) {
		if(strlen(value) != 16 ) {
			memset(rdr->nagra_boxkey, 0, 16);
			return;
		} else {
			if (key_atob_l(value, rdr->nagra_boxkey, 16)) {
				fprintf(stderr, "Configuration reader: Error in boxkey\n");
				memset(rdr->nagra_boxkey, 0, sizeof(rdr->nagra_boxkey));
			}
			return;
		}
	}

	if (!strcmp(token, "force_irdeto")) {
		rdr->force_irdeto  = strToIntVal(value, 0);
		return;
	}


	if ((!strcmp(token, "atr"))) {
		memset(rdr->atr, 0, sizeof(rdr->atr));
		rdr->atrlen = strlen(value);
		if(rdr->atrlen == 0) {
			return;
		} else {
			if(rdr->atrlen > (int32_t)sizeof(rdr->atr) * 2)
				rdr->atrlen = (int32_t)sizeof(rdr->atr) * 2;
			key_atob_l(value, rdr->atr, rdr->atrlen);
			return;
		}
	}

	if (!strcmp(token, "ecmwhitelist")) {
		struct s_ecmWhitelist *tmp, *last;
		struct s_ecmWhitelistIdent *tmpIdent, *lastIdent;
		struct s_ecmWhitelistLen *tmpLen, *lastLen;
		for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
			for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
				for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
					add_garbage(tmpLen);
				}
				add_garbage(tmpIdent);
			}
			add_garbage(tmp);
		}
		rdr->ecmWhitelist = NULL;
		if(strlen(value) > 0){
			char *saveptr1=NULL, *saveptr2 = NULL;
			for (ptr = strtok_r(value, ";", &saveptr1); ptr; ptr = strtok_r(NULL, ";", &saveptr1)) {
				int16_t caid = 0, len;
				uint32_t ident = 0;
				ptr2=strchr(ptr,':');
				if(ptr2 != NULL){
					ptr2[0] = '\0';
					++ptr2;
					ptr3=strchr(ptr,'@');
					if(ptr3 != NULL){
						ptr3[0] = '\0';
						++ptr3;
						ident = (uint32_t)a2i(ptr3, 6);
					}
					caid = (int16_t)dyn_word_atob(ptr);
				} else ptr2 = ptr;
				for (ptr2 = strtok_r(ptr2, ",", &saveptr2); ptr2; ptr2 = strtok_r(NULL, ",", &saveptr2)) {
					len = (int16_t)dyn_word_atob(ptr2);
					last = NULL, tmpIdent = NULL, lastIdent = NULL, tmpLen = NULL, lastLen = NULL;
					for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
						last = tmp;
						if(tmp->caid == caid){
							for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
								lastIdent = tmpIdent;
								if(tmpIdent->ident == ident){
									for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
										lastLen = tmpLen;
										if(tmpLen->len == len) break;
									}
									break;
								}
							}
						}
					}
					if(tmp == NULL){
						if (cs_malloc(&tmp, sizeof(struct s_ecmWhitelist), -1)) {
							tmp->caid = caid;
							tmp->idents = NULL;
							tmp->next = NULL;
							if(last == NULL){
								rdr->ecmWhitelist = tmp;
							} else {
								last->next = tmp;
							}
						}
					}
					if(tmp != NULL && tmpIdent == NULL){
						if (cs_malloc(&tmpIdent, sizeof(struct s_ecmWhitelistIdent), -1)) {
							tmpIdent->ident = ident;
							tmpIdent->lengths = NULL;
							tmpIdent->next = NULL;
							if(lastIdent == NULL){
								tmp->idents = tmpIdent;
							} else {
								lastIdent->next = tmpIdent;
							}
						}
					}
					if(tmp != NULL && tmpIdent != NULL && tmpLen == NULL){
						if (cs_malloc(&tmpLen, sizeof(struct s_ecmWhitelistLen), -1)) {
							tmpLen->len = len;
							tmpLen->next = NULL;
							if(lastLen == NULL){
								tmpIdent->lengths = tmpLen;
							} else {
								lastLen->next = tmpLen;
							}
						}
					}
				}
			}
		}
		return;
	}

	if (!strcmp(token, "ecmheaderwhitelist")) {
                struct s_ecmHeaderwhitelist *tmp, *last = NULL;
                if(strlen(value) == 0) { 
                        for(tmp = rdr->ecmHeaderwhitelist; tmp; tmp=tmp->next) add_garbage(tmp); 
                        rdr->ecmHeaderwhitelist = NULL; 
                        return; 
                } else { 
			char *ptr4, *ptr5, *ptr6, *saveptr = NULL, *saveptr4 = NULL, *saveptr5 = NULL, *saveptr6 = NULL;
			uint16_t caid = 0;
			uint32_t provid = 0;
			int16_t len = 0;
			for (ptr = strtok_r(value, ";", &saveptr); ptr; ptr = strtok_r(NULL, ";", &saveptr)) { 				
				caid = 0;
				provid = 0;
				ptr2 = strchr(ptr, '@'); 
				ptr3 = strchr(ptr, ':');
				if (ptr2 == NULL && ptr3 == NULL) { //no Caid no Provid
					for (ptr4 = strtok_r(ptr, ",", &saveptr4); ptr4; ptr4 = strtok_r(NULL, ",", &saveptr4)) {
						if (cs_malloc(&tmp, sizeof(struct s_ecmHeaderwhitelist), -1)) { 
							ptr4 = trim(ptr4);						
							len = strlen(ptr4);
							key_atob_l(ptr4, tmp->header, len);
							tmp->len = len;
							tmp->caid = 0;
							tmp->provid = 0;
							tmp->next = NULL;
							if(last == NULL){ 
                                              		rdr->ecmHeaderwhitelist = tmp; 
                                        		} else { 
	                                            		last->next = tmp; 
	                                       		} 
	                                       		last = tmp;
						}             
					}
				}


				if (ptr3 != NULL && ptr2 == NULL) { // only with Caid					
					ptr3[0] = '\0';
					++ptr3;
					caid = (int16_t)dyn_word_atob(ptr);
					for (ptr5 = strtok_r(ptr3, ",", &saveptr5); ptr5; ptr5 = strtok_r(NULL, ",", &saveptr5)) {
						if (cs_malloc(&tmp, sizeof(struct s_ecmHeaderwhitelist), -1)) { 
							tmp->caid = caid;
							tmp->provid = 0;
							ptr5 = trim(ptr5);
							len = strlen(ptr5);
							key_atob_l(ptr5, tmp->header, len);
							tmp->len = len;
							tmp->next = NULL;
							if(last == NULL){ 
                                       	       			rdr->ecmHeaderwhitelist = tmp; 
                                       			} else { 
                                       				last->next = tmp; 
                                      			} 
                                      			last = tmp;
													
						}
					}
				}

				if (ptr3 != NULL && ptr2 != NULL) { // with Caid & Provid
					ptr2[0] = '\0';
					++ptr2; // -> provid					
					ptr3[0] = '\0';
					++ptr3; // -> headers
					caid = (int16_t)dyn_word_atob(ptr);
					provid = (uint32_t)a2i(ptr2, 6);
					for (ptr6 = strtok_r(ptr3, ",", &saveptr6); ptr6; ptr6 = strtok_r(NULL, ",", &saveptr6)) {
						if (cs_malloc(&tmp, sizeof(struct s_ecmHeaderwhitelist), -1)) { 
							tmp->caid = caid;
							tmp->provid = provid;
							ptr6 = trim(ptr6);
							len = strlen(ptr6);
							key_atob_l(ptr6, tmp->header, len);
							tmp->len = len;
							tmp->next = NULL;
							if(last == NULL){ 
                                       	       			rdr->ecmHeaderwhitelist = tmp; 
                                       			} else { 
                                       	      				last->next = tmp; 
                                      			} 
                                      			last = tmp;
						}
					}
				}
			}
			return;
		}
		
	} 

/*	if (rdr->ecmHeaderwhitelist != NULL) { // debug
		cs_log("**********Begin ECM Header List for Reader: %s **************", rdr->label);

		struct s_ecmHeaderwhitelist *tmp;
		for(tmp = rdr->ecmHeaderwhitelist; tmp; tmp=tmp->next){
			cs_log("Caid: %i Provid: %i Header: %02X Len: %i", tmp->caid, tmp->provid, tmp->header[0], tmp->len);
		}
		cs_log("***********End ECM Header List for Reader: %s ***************", rdr->label);
	} */

	if (!strcmp(token, "detect")) {
		for (i = 0; RDR_CD_TXT[i]; i++) {
			if (!strcmp(value, RDR_CD_TXT[i])) {
				rdr->detect = i;
			}
			else {
				if ((value[0] == '!') && (!strcmp(value+1, RDR_CD_TXT[i])))
					rdr->detect = i|0x80;
			}
		}
		return;
	}

	if (!strcmp(token, "nagra_read")) {
		rdr->nagra_read  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "mhz")) {
		rdr->mhz  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cardmhz")) {
		rdr->cardmhz  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "protocol")) {

		for (i=0; i<CS_MAX_MOD; i++) {
			if (cardreader[i].desc && strcmp(value, cardreader[i].desc) == 0) {
				rdr->crdr = cardreader[i];
				rdr->crdr.active = 1;
				rdr->typ = cardreader[i].typ; //FIXME
				return;
			}
		}

		if (!strcmp(value, "mp35")) {
			rdr->typ = R_MP35;
			return;
		}

		if (!strcmp(value, "mouse")) {
			rdr->typ = R_MOUSE;
			return;
		}

		if (!strcmp(value, "sc8in1")) {
			rdr->typ = R_SC8in1;
			return;
		}

		if (!strcmp(value, "smartreader")) {
			rdr->typ = R_SMART;
			return;
		}

		if (!strcmp(value, "internal")) {
			rdr->typ = R_INTERNAL;
			return;
		}

#ifdef WITH_PCSC
		if (!strcmp(value, "pcsc")) {
			rdr->typ = R_PCSC;
			return;
		}
#endif

		if (!strcmp(value, "serial")) {
			rdr->typ = R_SERIAL;
			return;
		}

		if (!strcmp(value, "camd35")) {
			rdr->typ = R_CAMD35;
			return;
		}

		if (!strcmp(value, "cs378x")) {
			rdr->typ = R_CS378X;
			return;
		}

		if (!strcmp(value, "cs357x")) {
			rdr->typ = R_CAMD35;
			return;
		}

		if (!strcmp(value, "gbox")) {
			rdr->typ = R_GBOX;
			return;
		}

		if (!strcmp(value, "cccam") || !strcmp(value, "cccam ext")) {
			rdr->typ = R_CCCAM;
			//strcpy(value, "1");
			//chk_caidtab(value, &rdr->ctab);
			//this is a MAJOR hack for auto multiple caid support (not currently working due to ncd table issue)
			return;
		}

		if (!strcmp(value, "constcw")) {
			rdr->typ = R_CONSTCW;
			return;
		}

		if (!strcmp(value, "radegast")) {
			rdr->typ = R_RADEGAST;
			return;
		}

		if (!strcmp(value, "newcamd") || !strcmp(value, "newcamd525")) {
			rdr->typ = R_NEWCAMD;
			rdr->ncd_proto = NCD_525;
			return;
		}

		if (!strcmp(value, "newcamd524")) {
			rdr->typ = R_NEWCAMD;
			rdr->ncd_proto = NCD_524;
			return;
		}

		fprintf(stderr, "WARNING: value '%s' in protocol-line not recognized, assuming MOUSE\n",value);
		rdr->typ = R_MOUSE;
		return;
	}
#ifdef WITH_COOLAPI
	if (!strcmp(token, "cool_timeout_init")) {
		rdr->cool_timeout_init  = strToIntVal(value, 50);
		return;
	}
	if (!strcmp(token, "cool_timeout_after_init")) {
		rdr->cool_timeout_after_init  = strToIntVal(value, 150);
		return;
	}
#endif
	if (!strcmp(token, "ident")) {
		if(strlen(value) == 0) {
			clear_ftab(&rdr->ftab);
			rdr->changes_since_shareupdate = 1;
			return;
		} else {
			chk_ftab(value, &rdr->ftab,"reader",rdr->label,"provid");
			rdr->changes_since_shareupdate = 1;
			return;
		}
	}

	if (!strcmp(token, "class")) {
		chk_cltab(value, &rdr->cltab);
		return;
	}

	if (!strcmp(token, "chid")) {
		chk_ftab(value, &rdr->fchid,"reader",rdr->label,"chid");
		rdr->changes_since_shareupdate = 1;
		return;
	}

	if (!strcmp(token, "group")) {
		rdr->grp = 0;
		for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr);
			if ((g>0) && (g<65)) {
				rdr->grp |= (((uint64_t)1)<<(g-1));
			}
		}
		return;
	}

	if (!strcmp(token, "cooldown")) {
		if(strlen(value) == 0) {
			rdr->cooldown[0] = 0;
			rdr->cooldown[1] = 0;
			return;
		} else {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				switch(i) {
				case 0:
					rdr->cooldown[0] = atoi(ptr);
					break;

				case 1:
					rdr->cooldown[1] = atoi(ptr);
					break;
				}
			}

			if (!rdr->cooldown[0] || !rdr->cooldown[1]) {
				fprintf(stderr, "cooldown must have 2 values (x,y) set values %d,%d ! cooldown deactivated\n",
						rdr->cooldown[0], rdr->cooldown[1]);

				rdr->cooldown[0] = 0;
				rdr->cooldown[1] = 0;
			}

		}
		return;
	}

	if (!strcmp(token, "emmcache")) {
		if(strlen(value) == 0) {
			rdr->cachemm = 0;
			rdr->rewritemm = 0;
			rdr->logemm = 0;
			return;
		} else {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				switch(i)
				{
					case 0:
						rdr->cachemm = atoi(ptr);
						break;

					case 1:
						rdr->rewritemm = atoi(ptr);
						break;

					case 2: rdr->logemm = atoi(ptr);
					break;
				}
			}

			if (rdr->rewritemm <= 0) {
				fprintf(stderr, "Notice: Setting EMMCACHE to %i,1,%i instead of %i,%i,%i. ",
						rdr->cachemm, rdr->logemm,
						rdr->cachemm, rdr->rewritemm,
						rdr->logemm);

				fprintf(stderr, "Zero or negative number of rewrites is silly\n");
				rdr->rewritemm = 1;
			}
			return;
		}
	}

	if (!strcmp(token, "blocknano")) {
		rdr->b_nano = 0;
		if (strlen(value) > 0) {
			if (!strcmp(value,"all")) {
				rdr->b_nano = 0xFFFF;
			} else {
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						rdr->b_nano |= (1 << i);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "savenano")) {
		rdr->s_nano = 0;
		if (strlen(value) > 0) {
			if (!strcmp(value,"all")) {
				rdr->s_nano = 0xFFFF;
			} else {
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						rdr->s_nano |= (1 << i);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "blockemm-unknown")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_UNKNOWN))
			rdr->blockemm -= EMM_UNKNOWN;
		if (i)
			rdr->blockemm |= EMM_UNKNOWN;
		return;
	}

	if (!strcmp(token, "blockemm-u")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_UNIQUE))
			rdr->blockemm -= EMM_UNIQUE;
		if (i)
			rdr->blockemm |= EMM_UNIQUE;
		return;
	}

	if (!strcmp(token, "blockemm-s")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_SHARED))
			rdr->blockemm -= EMM_SHARED;
		if (i)
			rdr->blockemm |= EMM_SHARED;
		return;
	}

	if (!strcmp(token, "blockemm-g")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_GLOBAL))
			rdr->blockemm -= EMM_GLOBAL;
		if (i)
			rdr->blockemm |= EMM_GLOBAL;
		return;
	}

	if (!strcmp(token, "saveemm-unknown")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_UNKNOWN))
			rdr->saveemm -= EMM_UNKNOWN;
		if (i)
			rdr->saveemm |= EMM_UNKNOWN;
		return;
	}

	if (!strcmp(token, "saveemm-u")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_UNIQUE))
			rdr->saveemm -= EMM_UNIQUE;
		if (i)
			rdr->saveemm |= EMM_UNIQUE;
		return;
	}

	if (!strcmp(token, "saveemm-s")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_SHARED))
			rdr->saveemm -= EMM_SHARED;
		if (i)
			rdr->saveemm |= EMM_SHARED;
		return;
	}

	if (!strcmp(token, "saveemm-g")) {
		i=atoi(value);
		if (!i && (rdr->saveemm & EMM_GLOBAL))
			rdr->saveemm -= EMM_GLOBAL;
		if (i)
			rdr->saveemm |= EMM_GLOBAL;
		return;
	}

	if (!strcmp(token, "blockemm-bylen")) {
		for (i = 0; i < CS_MAXEMMBLOCKBYLEN; i++)
			rdr->blockemmbylen[i] = 0;
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < CS_MAXEMMBLOCKBYLEN) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
			rdr->blockemmbylen[i] = atoi(ptr);

		return;
	}

#ifdef WITH_LB
	if (!strcmp(token, "lb_weight")) {
		if(strlen(value) == 0) {
			rdr->lb_weight = 100;
			return;
		} else {
			rdr->lb_weight = atoi(value);
			if (rdr->lb_weight > 1000) rdr->lb_weight = 1000;
			else if (rdr->lb_weight <= 0) rdr->lb_weight = 100;
			return;
		}
	}
#endif

#ifdef MODULE_CCCAM
	if (!strcmp(token, "cccversion")) {
		// cccam version
		memset(rdr->cc_version, 0, sizeof(rdr->cc_version));
		if (strlen(value) > sizeof(rdr->cc_version) - 1) {
			fprintf(stderr, "cccam config: version too long.\n");
		}	else
			cs_strncpy(rdr->cc_version, value, sizeof(rdr->cc_version));
		return;
	}

	if (!strcmp(token, "cccmaxhop") || !strcmp(token, "cccmaxhops")) { //Schlocke: cccmaxhops is better!
		// cccam max card distance
		rdr->cc_maxhops = strToIntVal(value, DEFAULT_CC_MAXHOPS);
		return;
	}

	if (!strcmp(token, "cccmindown") ) {
		// cccam min downhops
		rdr->cc_mindown  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cccwantemu")) {
		rdr->cc_want_emu  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "ccckeepalive")) {
		rdr->cc_keepalive  = strToIntVal(value, DEFAULT_CC_KEEPALIVE);
		return;
	}

	if (!strcmp(token, "ccchopsaway") || !strcmp(token, "cccreshar")  || !strcmp(token, "cccreshare")) {
		rdr->cc_reshare = strToIntVal(value, DEFAULT_CC_RESHARE);
		return;
	}

	if (!strcmp(token, "ccchop")) {
		rdr->cc_hop = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cccreconnect")) {
		rdr->cc_reconnect = strToIntVal(value, DEFAULT_CC_RECONNECT);
		return;
	}

#endif

#ifdef MODULE_PANDORA
	if (!strcmp(token, "pand_send_ecm")) {
		rdr->pand_send_ecm = strToIntVal(value, 0);
		return;
	}

#endif
	if (!strcmp(token, "deprecated")) {
		rdr->deprecated  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "audisabled")) {
		rdr->audisabled  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "auprovid")) {
		if (strlen(value) == 0) {
			rdr->auprovid = 0;
			return;
		} else {
			rdr->auprovid = a2i(value, 3);
			return;
		}
	}
	// new code for multiple aes key per reader
	if (!strcmp(token, "aeskeys")) {
		parse_aes_keys(rdr,value);
		return;
	}

	if (!strcmp(token, "ndsversion")) {
		rdr->ndsversion = strToIntVal(value, 0);
		return;
	}


#ifdef WITH_AZBOX
	if (!strcmp(token, "mode")) {
		rdr->azbox_mode = strToIntVal(value, -1);
		return;
	}
#endif

	//ratelimit
	if (!strcmp(token, "ratelimitecm")) {
		if (strlen(value) == 0) {
			rdr->ratelimitecm = 0;
			return;
		} else {
			rdr->ratelimitecm = atoi(value);
			int32_t h;
			for (h=0; h < MAXECMRATELIMIT; h++) { // reset all slots
				rdr->rlecmh[h].srvid = -1;
				rdr->rlecmh[h].last = -1;
				return;
			}
		}
	}
	if (!strcmp(token, "ratelimitseconds")) {
		if (strlen(value) == 0) {
			if (rdr->ratelimitecm > 0) {
				rdr->ratelimitseconds = 10;
			} else {
				rdr->ratelimitseconds = 0;
			}
			return;
		} else {
			rdr->ratelimitseconds = atoi(value);
			return;
		}
	}

	// cooldown
	if (!strcmp(token, "cooldowndelay")) {
		if (strlen(value) == 0) {
			rdr->cooldown[0] = 0;
			return;
		} else {
			rdr->cooldown[0] = atoi(value);
			return;
		}
	}
	if (!strcmp(token, "cooldowntime")) {
		if (strlen(value) == 0) {
			rdr->cooldown[1] = 0; 
			return;
		} else {
			rdr->cooldown[1] = atoi(value);
			return;
		}
	}
	
	if (!strcmp(token, "dropbadcws")) {
		rdr->dropbadcws = strToIntVal(value, 0);
		return;
	}

    if (!strcmp(token, "disablecrccws")) {
        rdr->disablecrccws = strToIntVal(value, 0);
        return;
    }

	if (!strcmp(token, "use_gpio")) {
		rdr->use_gpio = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n",token);
}


void reader_set_defaults(struct s_reader *rdr) {
	int i;
	rdr->enable = 1;
	rdr->tcp_rto = DEFAULT_TCP_RECONNECT_TIMEOUT;
	rdr->tcp_ito = DEFAULT_INACTIVITYTIMEOUT;
	rdr->mhz = 357;
	rdr->cardmhz = 357;
#ifdef WITH_AZBOX
	rdr->azbox_mode = -1;
#endif
#ifdef MODULE_CCCAM
	rdr->cc_reshare = DEFAULT_CC_RESHARE;
	rdr->cc_maxhops = DEFAULT_CC_MAXHOPS;
	rdr->cc_reconnect = DEFAULT_CC_RECONNECT;
#endif
#ifdef WITH_LB
	rdr->lb_weight = 100;
#endif
	cs_strncpy(rdr->pincode, "none", sizeof(rdr->pincode));
	for (i=1; i<CS_MAXCAIDTAB; rdr->ctab.mask[i++]=0xffff);
}

int32_t init_readerdb(void)
{
	configured_readers = ll_create("configured_readers");

	FILE *fp = open_config_file(cs_srvr);
	if (!fp)
		return 1;

	int32_t tag = 0;
	char *value, *token;

	if(!cs_malloc(&token, MAXLINESIZE, -1)) return 1;

	struct s_reader *rdr;
	cs_malloc(&rdr, sizeof(struct s_reader), SIGINT);

	ll_append(configured_readers, rdr);
	while (fgets(token, MAXLINESIZE, fp)) {
		int32_t l;
		if ((l = strlen(trim(token))) < 3)
			continue;
		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l-1] = 0;
			tag = (!strcmp("reader", strtolower(token+1)));
			if (rdr->label[0] && rdr->typ) {
				struct s_reader *newreader;
				if(cs_malloc(&newreader, sizeof(struct s_reader), -1)){
					ll_append(configured_readers, newreader);
					rdr = newreader;
				}
			}
			reader_set_defaults(rdr);
			continue;
		}

		if (!tag)
			continue;
		if (!(value=strchr(token, '=')))
			continue;
		*value++ ='\0';
		chk_reader(trim(strtolower(token)), trim(value), rdr);
	}
	free(token);
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) { //build active readers list
		int32_t i;
		if (is_cascading_reader(rdr)) {
			for (i=0; i<CS_MAX_MOD; i++) {
				if (ph[i].num && rdr->typ==ph[i].num) {
					rdr->ph=ph[i];
					if(rdr->device[0]) rdr->ph.active=1;
				}
			}
		}
	}
	fclose(fp);
	return(0);
}

void free_reader(struct s_reader *rdr)
{
	NULLFREE(rdr->emmfile);

	struct s_ecmWhitelist *tmp;
	struct s_ecmWhitelistIdent *tmpIdent;
	struct s_ecmWhitelistLen *tmpLen;
	for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
		for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
			for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
				add_garbage(tmpLen);
			}
			add_garbage(tmpIdent);
		}
		add_garbage(tmp);
	}
	rdr->ecmWhitelist = NULL;

	struct s_ecmHeaderwhitelist *tmp1;
	for(tmp1 = rdr->ecmHeaderwhitelist; tmp1; tmp1=tmp1->next){
		add_garbage(tmp1);
	}
	rdr->ecmHeaderwhitelist = NULL;

	clear_ftab(&rdr->ftab);

#ifdef WITH_LB
	if (rdr->lb_stat) {
		cs_lock_destroy(&rdr->lb_stat_lock);
		ll_destroy_data(rdr->lb_stat);
		rdr->lb_stat = NULL;
	}

#endif
	add_garbage(rdr);
}

int32_t write_server(void)
{
	int32_t j;
	char *value;
	FILE *f = create_config_file(cs_srvr);
	if (!f)
		return 1;

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if ( rdr->label[0]) {
			int32_t isphysical = !is_network_reader(rdr);
			char *ctyp = reader_get_type_desc(rdr, 0);

			fprintf(f,"[reader]\n");

			fprintf_conf(f, "label", "%s\n", rdr->label);

#ifdef WEBIF
			if (rdr->description || cfg.http_full_cfg)
				fprintf_conf(f, "description", "%s\n", rdr->description?rdr->description:"");
#endif

			if (rdr->enable == 0 || cfg.http_full_cfg)
				fprintf_conf(f, "enable", "%d\n", rdr->enable);

			fprintf_conf(f, "protocol", "%s\n", ctyp);
			fprintf_conf(f, "device", "%s", rdr->device); // it should not have \n at the end

			if ((rdr->r_port || cfg.http_full_cfg) && !isphysical)
				fprintf(f, ",%d", rdr->r_port);
			if ((rdr->l_port || cfg.http_full_cfg) && !isphysical && strncmp(ctyp, "cccam", 5))
				fprintf(f, ",%d", rdr->l_port);
			fprintf(f, "\n");

#ifdef WITH_LIBUSB
			if (isphysical)
				if (rdr->device_endpoint || cfg.http_full_cfg)
					fprintf_conf(f, "device_out_endpoint", "0x%2X\n", rdr->device_endpoint);
#endif

			if (rdr->ncd_key[0] || rdr->ncd_key[13] || cfg.http_full_cfg) {
				fprintf_conf(f, "key", "%s", ""); // it should not have \n at the end
				if(rdr->ncd_key[0] || rdr->ncd_key[13]){
					for (j = 0; j < 14; j++) {
						fprintf(f, "%02X", rdr->ncd_key[j]);
					}
				}
				fprintf(f, "\n");
			}

			if ((rdr->r_usr[0] || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "user", "%s\n", rdr->r_usr);

			if (strlen(rdr->r_pwd) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "password", "%s\n", rdr->r_pwd);

			if(strcmp(rdr->pincode, "none") || cfg.http_full_cfg)
				fprintf_conf(f, "pincode", "%s\n", rdr->pincode);

			if ((rdr->emmfile || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "readnano", "%s\n", rdr->emmfile?rdr->emmfile:"");

			value = mk_t_service((uint64_t)rdr->sidtabok, (uint64_t)rdr->sidtabno);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "services", "%s\n", value);
			free_mk_t(value);

			if (((rdr->typ != R_CCCAM && rdr->tcp_ito != DEFAULT_INACTIVITYTIMEOUT) || (rdr->typ == R_CCCAM && rdr->tcp_ito != 30) || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "inactivitytimeout", "%d\n", rdr->tcp_ito);

			if ((rdr->resetcycle != 0 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "resetcycle", "%d\n", rdr->resetcycle);

			if ((rdr->tcp_rto != DEFAULT_TCP_RECONNECT_TIMEOUT || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "reconnecttimeout", "%d\n", rdr->tcp_rto);

			if ((rdr->ncd_disable_server_filt || cfg.http_full_cfg) && rdr->typ == R_NEWCAMD)
				fprintf_conf(f, "disableserverfilter", "%d\n", rdr->ncd_disable_server_filt);

			if ((rdr->smargopatch || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "smargopatch", "%d\n", rdr->smargopatch);

			if ((rdr->sc8in1_dtrrts_patch || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "sc8in1_dtrrts_patch", "%d\n", rdr->sc8in1_dtrrts_patch);

			if (rdr->fallback || cfg.http_full_cfg)
				fprintf_conf(f, "fallback", "%d\n", rdr->fallback);

#ifdef CS_CACHEEX
			if (rdr->cacheex || cfg.http_full_cfg)
				fprintf_conf(f, "cacheex", "%d\n", rdr->cacheex);

			if (rdr->cacheex_maxhop || cfg.http_full_cfg)
				fprintf_conf(f, "cacheex_maxhop", "%d\n", rdr->cacheex_maxhop);
#endif

#ifdef WITH_COOLAPI
			if (rdr->cool_timeout_init != 50 || cfg.http_full_cfg)
				fprintf_conf(f, "cool_timeout_init", "%d\n", rdr->cool_timeout_init);
			if (rdr->cool_timeout_after_init != 150 || cfg.http_full_cfg)
				fprintf_conf(f, "cool_timeout_after_init", "%d\n", rdr->cool_timeout_after_init);
#endif
			if (rdr->log_port || cfg.http_full_cfg)
				fprintf_conf(f, "logport", "%d\n", rdr->log_port);

			value = mk_t_caidtab(&rdr->ctab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "caid", "%s\n", value);
			free_mk_t(value);

			if (rdr->boxid && isphysical)
				fprintf_conf(f, "boxid", "%08X\n", rdr->boxid);
			else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "boxid", "\n");

			if((rdr->fix_9993 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "fix9993", "%d\n", rdr->fix_9993);

			// rsakey
			int32_t len = check_filled(rdr->rsa_mod, 120);
			if (len > 0 && isphysical) {
				if(len > 64) len = 120;
				else len = 64;
				char tmp[len*2+1];
				fprintf_conf(f, "rsakey", "%s\n", cs_hexdump(0, rdr->rsa_mod, len, tmp, sizeof(tmp)));
			} else if(cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "rsakey", "\n");

			if (rdr->ins7E[0x1A] && isphysical) {
				char tmp[0x1A*2+1];
				fprintf_conf(f, "ins7e", "%s\n", cs_hexdump(0, rdr->ins7E, 0x1A, tmp, sizeof(tmp)));
			} else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "ins7e", "\n");

			if (rdr->ins7E11[0x01] && isphysical) {
				char tmp[0x01*2+1];
				fprintf_conf(f, "ins7e11", "%s\n", cs_hexdump(0, rdr->ins7E11, 0x01, tmp, sizeof(tmp)));
			} else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "ins7e11", "\n");

			if ((rdr->force_irdeto || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "force_irdeto", "%d\n", rdr->force_irdeto);
			}

			len = check_filled(rdr->nagra_boxkey, 8);
			if ((len > 0 || cfg.http_full_cfg) && isphysical){
				char tmp[17];
				fprintf_conf(f, "boxkey", "%s\n", len>0?cs_hexdump(0, rdr->nagra_boxkey, 8, tmp, sizeof(tmp)):"");
			}

			if ((rdr->atr[0] || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "atr", "%s", ""); // it should not have \n at the end
				if(rdr->atr[0]){
					for (j=0; j < rdr->atrlen/2; j++) {
						fprintf(f, "%02X", rdr->atr[j]);
					}
				}
				fprintf(f, "\n");
			}

			value = mk_t_ecmwhitelist(rdr->ecmWhitelist);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ecmwhitelist", "%s\n", value);
			free_mk_t(value);

			value = mk_t_ecmheaderwhitelist(rdr->ecmHeaderwhitelist); 
                        if (strlen(value) > 0 || cfg.http_full_cfg) {
					fprintf_conf(f, "ecmheaderwhitelist", "%s\n", value);
			}
                        free_mk_t(value); 

			if (isphysical) {
				if (rdr->detect&0x80)
					fprintf_conf(f, "detect", "!%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
				else
					fprintf_conf(f, "detect", "%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
			}

			if ((rdr->nagra_read || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "nagra_read", "%d\n", rdr->nagra_read);

			if ((rdr->mhz || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "mhz", "%d\n", rdr->mhz);

			if ((rdr->cardmhz || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "cardmhz", "%d\n", rdr->cardmhz);

#ifdef WITH_AZBOX
			if ((rdr->azbox_mode != -1 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "mode", "%d\n", rdr->azbox_mode);
#endif

			value = mk_t_ftab(&rdr->ftab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ident", "%s\n", value);
			free_mk_t(value);

			//Todo: write reader class

			value = mk_t_ftab(&rdr->fchid);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "chid", "%s\n", value);
			free_mk_t(value);

			value = mk_t_cltab(&rdr->cltab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "class", "%s\n", value);
			free_mk_t(value);

			value = mk_t_aeskeys(rdr);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "aeskeys", "%s\n", value);
			free_mk_t(value);

			value = mk_t_group(rdr->grp);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "group", "%s\n", value);
			free_mk_t(value);

			if (rdr->cachemm || cfg.http_full_cfg)
				fprintf_conf(f, "emmcache", "%d,%d,%d\n", rdr->cachemm, rdr->rewritemm, rdr->logemm);

			if ((rdr->blockemm & EMM_UNKNOWN) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-unknown", "%d\n", (rdr->blockemm & EMM_UNKNOWN) ? 1: 0);

			if ((rdr->blockemm & EMM_UNIQUE) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-u", "%d\n", (rdr->blockemm & EMM_UNIQUE) ? 1: 0);

			if ((rdr->blockemm & EMM_SHARED) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-s", "%d\n", (rdr->blockemm & EMM_SHARED) ? 1: 0);

			if ((rdr->blockemm & EMM_GLOBAL) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-g", "%d\n", (rdr->blockemm & EMM_GLOBAL) ? 1: 0);

			if ((rdr->saveemm & EMM_UNKNOWN) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-unknown", "%d\n", (rdr->saveemm & EMM_UNKNOWN) ? 1: 0);

			if ((rdr->saveemm & EMM_UNIQUE) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-u", "%d\n", (rdr->saveemm & EMM_UNIQUE) ? 1: 0);

			if ((rdr->saveemm & EMM_SHARED) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-s", "%d\n", (rdr->saveemm & EMM_SHARED) ? 1: 0);

			if ((rdr->saveemm & EMM_GLOBAL) || cfg.http_full_cfg)
				fprintf_conf(f, "saveemm-g", "%d\n", (rdr->saveemm & EMM_GLOBAL) ? 1: 0);

			value = mk_t_emmbylen(rdr);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-bylen", "%s\n", value);
			free_mk_t(value);

#ifdef WITH_LB
			if (rdr->lb_weight != 100 || cfg.http_full_cfg)
				fprintf_conf(f, "lb_weight", "%d\n", rdr->lb_weight);
#endif

			//savenano
			value = mk_t_nano(rdr, 0x02);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "savenano", "%s\n", value);
			free_mk_t(value);

			//blocknano
			value = mk_t_nano(rdr, 0x01);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "blocknano", "%s\n", value);
			free_mk_t(value);

			if (rdr->dropbadcws)
				fprintf_conf(f, "dropbadcws", "%d\n", rdr->dropbadcws);

            if (rdr->disablecrccws)
                fprintf_conf(f, "disablecrccws", "%d\n", rdr->disablecrccws);

			if (rdr->use_gpio)
				fprintf_conf(f, "use_gpio", "%d\n", rdr->use_gpio);

#ifdef MODULE_CCCAM
			if (rdr->typ == R_CCCAM) {
				if (rdr->cc_version[0] || cfg.http_full_cfg)
					fprintf_conf(f, "cccversion", "%s\n", rdr->cc_version);

				if (rdr->cc_maxhops != DEFAULT_CC_MAXHOPS || cfg.http_full_cfg)
					fprintf_conf(f, "cccmaxhops", "%d\n", rdr->cc_maxhops);

				if (rdr->cc_mindown > 0 || cfg.http_full_cfg)
					fprintf_conf(f, "cccmindown", "%d\n", rdr->cc_mindown);

				if (rdr->cc_want_emu || cfg.http_full_cfg)
					fprintf_conf(f, "cccwantemu", "%d\n", rdr->cc_want_emu);

				if (rdr->cc_keepalive != DEFAULT_CC_KEEPALIVE || cfg.http_full_cfg)
					fprintf_conf(f, "ccckeepalive", "%d\n", rdr->cc_keepalive);

				if (rdr->cc_reshare != DEFAULT_CC_RESHARE || cfg.http_full_cfg)
					fprintf_conf(f, "cccreshare", "%d\n", rdr->cc_reshare);

				if (rdr->cc_reconnect != DEFAULT_CC_RECONNECT || cfg.http_full_cfg)
					fprintf_conf(f, "cccreconnect", "%d\n", rdr->cc_reconnect);
			}
			else if (rdr->cc_hop > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ccchop", "%d\n", rdr->cc_hop);
#endif

#ifdef MODULE_PANDORA
			if (rdr->typ == R_PANDORA)
			{
				if (rdr->pand_send_ecm || cfg.http_full_cfg)
					fprintf_conf(f, "pand_send_ecm", "%d\n", rdr->pand_send_ecm);
			}
#endif

			if ((rdr->deprecated || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "deprecated", "%d\n", rdr->deprecated);

			if (rdr->audisabled || cfg.http_full_cfg)
				fprintf_conf(f, "audisabled", "%d\n", rdr->audisabled);

			if (rdr->auprovid)
				fprintf_conf(f, "auprovid", "%06X\n", rdr->auprovid);
			else if (cfg.http_full_cfg)
				fprintf_conf(f, "auprovid", "\n");

			if ((rdr->ndsversion || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "ndsversion", "%d\n", rdr->ndsversion);

			if ((rdr->ratelimitecm || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "ratelimitecm", "%d\n", rdr->ratelimitecm);
				fprintf_conf(f, "ratelimitseconds", "%d\n", rdr->ratelimitseconds);
			}

			if ((rdr->cooldown[0] || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "cooldown", "%d,%d\n", rdr->cooldown[0], rdr->cooldown[1]);
			}

			fprintf(f, "\n");
		}
	}

	return flush_config_file(f, cs_srvr);
}
