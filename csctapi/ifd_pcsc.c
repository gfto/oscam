#ifdef HAVE_PCSC

#include "ifd_pcsc.h"
int32_t pcsc_reader_init(struct s_reader *pcsc_reader, char *device)
{
    ULONG rv;
    DWORD dwReaders;
    LPSTR mszReaders = NULL;
    char *ptr, **readers = NULL;
    int32_t nbReaders;
    int32_t reader_nb;

    pcsc_reader->pcsc_has_card=0;
    pcsc_reader->hCard=0;
    pcsc_reader->hContext=0;
     
    cs_debug_mask(D_DEVICE, "PCSC establish context for PCSC reader %s", device);
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pcsc_reader->hContext);
    if ( rv == SCARD_S_SUCCESS ) {
        // here we need to list the pcsc readers and get the name from there,
        // the pcsc_reader->device should contain the reader number
        // and after the actual device name is copied in pcsc_reader->pcsc_name .
        rv = SCardListReaders(pcsc_reader->hContext, NULL, NULL, &dwReaders);
        if( rv != SCARD_S_SUCCESS ) {
            cs_debug_mask(D_DEVICE, "PCSC failed listing readers [1] : (%lx)", rv);
            return  2;
        }
        mszReaders = malloc(sizeof(char)*dwReaders);
        if (mszReaders == NULL) {
            cs_debug_mask(D_DEVICE, "PCSC failed malloc");
            return  2;
        }
        rv = SCardListReaders(pcsc_reader->hContext, NULL, mszReaders, &dwReaders);
        if( rv != SCARD_S_SUCCESS ) {
            cs_debug_mask(D_DEVICE, "PCSC failed listing readers [2]: (%lx)", rv);
            free(mszReaders);
            return  2;
        }
        /* Extract readers from the null separated string and get the total
         * number of readers 
         */
        nbReaders = 0;
        ptr = mszReaders;
        while (*ptr != '\0') {
            ptr += strlen(ptr)+1;
            nbReaders++;
        }
        
        if (nbReaders == 0) {
            cs_log("PCSC : no reader found");
            free(mszReaders);
            return  2;
        }

        readers = calloc(nbReaders, sizeof(char *));
        if (readers == NULL) {
            cs_log("PCSC failed calloc");
            return  2;
        }

        /* fill the readers table */
        nbReaders = 0;
        ptr = mszReaders;
        while (*ptr != '\0') {
            cs_debug_mask(D_DEVICE, "PCSC reader %d: %s", nbReaders, ptr);
            readers[nbReaders] = ptr;
            ptr += strlen(ptr)+1;
            nbReaders++;
        }

        reader_nb=atoi((const char *)&pcsc_reader->device);
        if (reader_nb < 0 || reader_nb >= nbReaders) {
            cs_log("Wrong reader index: %d", reader_nb);
            free(mszReaders);
            free(readers);
            return  2;
        }

        snprintf(pcsc_reader->pcsc_name,sizeof(pcsc_reader->pcsc_name),"%s",readers[reader_nb]);
        free(mszReaders);
        free(readers);
    }
    else {
        cs_log("PCSC failed establish context (%lx)", rv);
        return 2;
    }
    return 0;
}

int32_t pcsc_reader_do_api(struct s_reader *pcsc_reader, const uchar *buf, uchar *cta_res, uint16_t *cta_lr, int32_t l)
{
     LONG rv;
     DWORD dwSendLength, dwRecvLength;

    if(!l) {
        cs_log("ERROR : data length to be send to the reader is %d" , l);
        return ERR_INVALID;
    }

		char tmp[520];
    dwRecvLength = CTA_RES_LEN;
    *cta_lr = 0;

    if(pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0) {
        //  explanantion as to why we do the test on buf[4] :
        // Issuing a command without exchanging data :
        //To issue a command to the card that does not involve the exchange of data (either sent or received), the send and receive buffers must be formatted as follows.
        //The pbSendBuffer buffer must contain the CLA, INS, P1, and P2 values for the T=0 operation. The P3 value is not sent. (This is to differentiate the header from the case where 256 bytes are expected to be returned.)
        //The cbSendLength parameter must be set to four, the size of the T=0 header information (CLA, INS, P1, and P2).
        //The pbRecvBuffer will receive the SW1 and SW2 status codes from the operation.
        //The pcbRecvLength should be at least two and will be set to two upon return.
        if(buf[4])
            dwSendLength = l;
        else
            dwSendLength = l-1;
        cs_debug_mask(D_DEVICE, "sending %d bytes to PCSC : %s", dwSendLength,cs_hexdump(1,buf,l, tmp, sizeof(tmp)));
        rv = SCardTransmit((SCARDHANDLE)(pcsc_reader->hCard), SCARD_PCI_T0, (LPCBYTE) buf, dwSendLength, NULL, (LPBYTE) cta_res, (LPDWORD) &dwRecvLength);
        *cta_lr=dwRecvLength;
    }
    else  if(pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T1) {
        dwSendLength = l;
        cs_debug_mask(D_DEVICE, "sending %d bytes to PCSC : %s", dwSendLength,cs_hexdump(1,buf,l, tmp, sizeof(tmp)));
        rv = SCardTransmit((SCARDHANDLE)(pcsc_reader->hCard), SCARD_PCI_T1, (LPCBYTE) buf, dwSendLength, NULL, (LPBYTE) cta_res, (LPDWORD) &dwRecvLength);
        *cta_lr=dwRecvLength;
    }
    else {
        cs_debug_mask(D_DEVICE, "PCSC invalid protocol (T=%d)", pcsc_reader->dwActiveProtocol);
        return ERR_INVALID;
    }

     cs_debug_mask(D_DEVICE, "received %d bytes from PCSC with rv=%lx : %s", *cta_lr, rv,cs_hexdump(1,cta_res,*cta_lr, tmp, sizeof(tmp)));

     cs_debug_mask(D_DEVICE, "PCSC doapi (%lx ) (T=%d), %d", rv, ( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1), *cta_lr );

     if ( rv  == SCARD_S_SUCCESS ){
         return OK;
     }
     else {
         return ERR_INVALID;
     }

}

int32_t pcsc_activate_card(struct s_reader *pcsc_reader, uchar *atr, uint16_t *atr_size)
{
    LONG rv;
    DWORD dwState, dwAtrLen, dwReaderLen;
    BYTE pbAtr[64];
    char tmp[sizeof(pbAtr)*3+1];
    
    cs_debug_mask(D_DEVICE, "PCSC initializing card in (%s)", pcsc_reader->pcsc_name);
    dwAtrLen = sizeof(pbAtr);
    dwReaderLen=0;
    
    cs_debug_mask(D_DEVICE, "PCSC resetting card in (%s) with handle %lu", pcsc_reader->pcsc_name,(SCARDHANDLE)(pcsc_reader->hCard));
    rv = SCardReconnect((SCARDHANDLE)(pcsc_reader->hCard), SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,  SCARD_RESET_CARD, &pcsc_reader->dwActiveProtocol);

    if ( rv != SCARD_S_SUCCESS )  {
        cs_debug_mask(D_DEVICE, "Error PCSC failed to reset card (%lx)", rv);
        return(0);
    }
    
    cs_debug_mask(D_DEVICE, "PCSC resetting done on card in (%s)", pcsc_reader->pcsc_name);
    cs_debug_mask(D_DEVICE, "PCSC Protocol (T=%d)",( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
    
    cs_debug_mask(D_DEVICE, "PCSC getting ATR for card in (%s)", pcsc_reader->pcsc_name);
    rv = SCardStatus((SCARDHANDLE)(pcsc_reader->hCard),NULL, &dwReaderLen, &dwState, &pcsc_reader->dwActiveProtocol, pbAtr, &dwAtrLen);
    if ( rv == SCARD_S_SUCCESS ) {
        cs_debug_mask(D_DEVICE, "PCSC Protocol (T=%d)",( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
        memcpy(atr, pbAtr, dwAtrLen);
        *atr_size=dwAtrLen;
        pcsc_reader->init_history_pos=0;

        cs_log("%s ATR: %s",pcsc_reader->label, cs_hexdump(1, (uchar *)pbAtr, dwAtrLen, tmp, sizeof(tmp)));
    	memcpy(pcsc_reader->card_atr, pbAtr, dwAtrLen);
    	pcsc_reader->card_atr_length = dwAtrLen;
        return(1);
    }
    else {
        cs_debug_mask(D_DEVICE, "Error PCSC failed to get ATR for card (%lx)", rv);
    }

    return(0);
}


int32_t pcsc_check_card_inserted(struct s_reader *pcsc_reader)
{
    DWORD dwState, dwAtrLen, dwReaderLen;
    BYTE pbAtr[64];
    LONG rv;
    
    dwAtrLen = sizeof(pbAtr);
    rv=0;
    dwState=0;
    dwReaderLen=0;
        
    // Do we have a card ?
    if (!pcsc_reader->pcsc_has_card && !(SCARDHANDLE)(pcsc_reader->hCard)) {
        // try connecting to the card
        rv = SCardConnect(pcsc_reader->hContext, pcsc_reader->pcsc_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &pcsc_reader->hCard, &pcsc_reader->dwActiveProtocol);
        if (rv==SCARD_E_NO_SMARTCARD) {
            // no card in reader
            pcsc_reader->pcsc_has_card=0;
            if((SCARDHANDLE)(pcsc_reader->hCard)) {
                SCardDisconnect((SCARDHANDLE)(pcsc_reader->hCard),SCARD_RESET_CARD);
                pcsc_reader->hCard=0;
            }
            // cs_debug_mask(D_DEVICE, "PCSC card in %s removed / absent [dwstate=%lx rv=(%lx)]", pcsc_reader->pcsc_name, dwState, rv );
            return 0;
        }
        else if( rv == SCARD_W_UNRESPONSIVE_CARD ) {
            // there is a problem with the card in the reader
            pcsc_reader->pcsc_has_card=0;
            pcsc_reader->hCard=0;
            cs_log("PCSC card in %s is unresponsive. Eject and re-insert please.", pcsc_reader->pcsc_name);
            return 0;
        }
        else if( rv == SCARD_S_SUCCESS ) {
            // we have a card
            pcsc_reader->pcsc_has_card=1;
        }
        else {
            // if we get here we have a bigger problem -> display status and debug
            // cs_debug_mask(D_DEVICE, "PCSC reader %s status [dwstate=%lx rv=(%lx)]", pcsc_reader->pcsc_name, dwState, rv );
            return 0;
        }
        
    }

    // if we get there the card is ready, check its status
    rv = SCardStatus((SCARDHANDLE)(pcsc_reader->hCard), NULL, &dwReaderLen, &dwState, &pcsc_reader->dwActiveProtocol, pbAtr, &dwAtrLen);

    if (rv == SCARD_S_SUCCESS && (dwState & (SCARD_PRESENT | SCARD_NEGOTIABLE | SCARD_POWERED ) )) {
        return CARD_INSERTED;
    } 
    else {
        SCardDisconnect((SCARDHANDLE)(pcsc_reader->hCard),SCARD_RESET_CARD);
        pcsc_reader->hCard=0;
        pcsc_reader->pcsc_has_card=0;
    }
    
    return 0;
}

void pcsc_close(struct s_reader *pcsc_reader)
{
    cs_debug_mask (D_IFD, "PCSC : Closing device %s", pcsc_reader->device);
    SCardDisconnect((SCARDHANDLE)(pcsc_reader->hCard),SCARD_RESET_CARD);
    SCardReleaseContext(pcsc_reader->hContext);
    pcsc_reader->hCard=0;
    pcsc_reader->pcsc_has_card=0;
}
#endif

