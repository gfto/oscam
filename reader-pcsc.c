#ifdef HAVE_PCSC

#include "reader-pcsc.h"
int pcsc_reader_init(struct s_reader *pcsc_reader, char *device)
{
    ULONG rv;
    DWORD dwReaders;
    LPSTR mszReaders = NULL;
    char *ptr, **readers = NULL;
    int nbReaders;
    int reader_nb;
    
    cs_debug("PCSC establish context for PCSC reader %s", device);
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pcsc_reader->hContext);
    if ( rv == SCARD_S_SUCCESS ) {
        // here we need to list the pcsc readers and get the name from there,
        // the pcsc_reader->device should contain the reader number
        // and after the actual device name is copied in pcsc_reader->pcsc_name .
        rv = SCardListReaders(pcsc_reader->hContext, NULL, NULL, &dwReaders);
        if( rv != SCARD_S_SUCCESS ) {
            cs_debug("PCSC failed listing readers [1] : (%lx)", rv);
            return  0;
        }
        mszReaders = malloc(sizeof(char)*dwReaders);
        if (mszReaders == NULL) {
            cs_debug("PCSC failed malloc");
            return  0;
        }
        rv = SCardListReaders(pcsc_reader->hContext, NULL, mszReaders, &dwReaders);
        if( rv != SCARD_S_SUCCESS ) {
            cs_debug("PCSC failed listing readers [2]: (%lx)", rv);
            return  0;
        }
        /* Extract readers from the null separated string and get the total
         * number of readers */
        nbReaders = 0;
        ptr = mszReaders;
        while (*ptr != '\0') {
            ptr += strlen(ptr)+1;
            nbReaders++;
        }
        
        if (nbReaders == 0) {
            cs_debug("PCSC : no reader found");
            return  0;
        }

        readers = calloc(nbReaders, sizeof(char *));
        if (readers == NULL) {
            cs_debug("PCSC failed malloc");
            return  0;
        }

        /* fill the readers table */
        nbReaders = 0;
        ptr = mszReaders;
        while (*ptr != '\0') {
            cs_debug("PCSC reader %d: %s", nbReaders, ptr);
            readers[nbReaders] = ptr;
            ptr += strlen(ptr)+1;
            nbReaders++;
        }

        reader_nb=atoi((const char *)&pcsc_reader->device);
        if (reader_nb < 0 || reader_nb >= nbReaders) {
            cs_debug("Wrong reader index: %d\n", reader_nb);
            return  0;
        }

        snprintf(pcsc_reader->pcsc_name,sizeof(pcsc_reader->pcsc_name),"%s",readers[reader_nb]);
        cs_log("PCSC initializing reader (%s)", &pcsc_reader->pcsc_name);
        rv = SCardConnect(pcsc_reader->hContext, &pcsc_reader->pcsc_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &pcsc_reader->hCard, &pcsc_reader->dwActiveProtocol);
        cs_debug("PCSC initializing result (%lx) protocol (T=%lx)", rv, ( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
        if (rv==SCARD_S_SUCCESS) {
            pcsc_reader->pcsc_has_card=1;
            return 0;
        }
        else if (rv==SCARD_E_NO_SMARTCARD) {
            pcsc_reader->pcsc_has_card=0;
            return 0;
        }
        else {
            pcsc_reader->pcsc_has_card=0;
            return 2;
        }
            
    }
    else {
        cs_debug("PCSC failed establish context (%lx)", rv);
    }

    return 0;
}

int pcsc_reader_do_api(struct s_reader *pcsc_reader, uchar *buf, uchar *cta_res, ushort *cta_lr, int l, int dbg)
{
     ULONG rv;
     SCARD_IO_REQUEST pioRecvPci;
     DWORD dwSendLength, dwRecvLength;

     dwSendLength = l;
     dwRecvLength = 512;

     //cs_ddump(buf, dwSendLength, "sending %d bytes to PCSC", dwSendLength);

     if(pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0)
         rv = SCardTransmit(pcsc_reader->hCard, SCARD_PCI_T0, buf, dwSendLength, &pioRecvPci, cta_res, &dwRecvLength);
     else  if(pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T1)
         rv = SCardTransmit(pcsc_reader->hCard, SCARD_PCI_T1, buf, dwSendLength, &pioRecvPci, cta_res, &dwRecvLength);
     else {
         cs_debug("PCSC invalid protocol (T=%d)", ( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
         return ERR_INVALID;
     }

     *cta_lr=dwRecvLength;
     //cs_ddump(cta_res, *cta_lr, "received %d bytes from PCSC with rv=%lx", *cta_lr, rv);

     cs_debug("PCSC doapi (%lx ) (T=%d), %d", rv, ( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1), dwRecvLength );
     if ( rv  == SCARD_S_SUCCESS ){
         return OK;
     }
     else {
         return ERR_INVALID;
     }

}

int pcsc_activate_card(struct s_reader *pcsc_reader, uchar *atr, ushort *atr_size)
{
    ULONG rv;
    DWORD dwState, dwAtrLen, dwReaderLen;
    BYTE pbAtr[64];
    
    cs_debug("PCSC initializing card in (%s)", pcsc_reader->pcsc_name);
    dwAtrLen = sizeof(pbAtr);
    
    cs_debug("PCSC resetting card in (%s)", pcsc_reader->pcsc_name);
    rv = SCardReconnect(pcsc_reader->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,  SCARD_RESET_CARD, &pcsc_reader->dwActiveProtocol);
    cs_debug("PCSC resetting done on card in (%s)", pcsc_reader->pcsc_name);
    cs_debug("PCSC Protocol (T=%d)",( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));

    if ( rv != SCARD_S_SUCCESS )  {
        cs_debug("Error PCSC failed to reset card (%lx)", rv);
        return(0);
    }

    rv=SCardBeginTransaction(pcsc_reader->hCard);
    if (rv!=SCARD_S_SUCCESS) {
        cs_log("PCSC reader %s Failed to begin transaction", pcsc_reader->pcsc_name);
        return 0;
    }

    cs_debug("PCSC getting ATR for card in (%s)", pcsc_reader->pcsc_name);
    rv = SCardStatus(pcsc_reader->hCard, NULL, &dwReaderLen, &dwState, &pcsc_reader->dwActiveProtocol, pbAtr, &dwAtrLen);
    if ( rv == SCARD_S_SUCCESS ) {
        cs_debug("PCSC Protocol (T=%d)",( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
        memcpy(atr, pbAtr, dwAtrLen);
        *atr_size=dwAtrLen;
#ifdef CS_RDR_INIT_HIST
        pcsc_reader->init_history_pos=0;
        memset(pcsc_reader->init_history, 0, sizeof(pcsc_reader->init_history));
#endif
        cs_ri_log("ATR: %s", cs_hexdump(1, (uchar *)pbAtr, dwAtrLen));
        return(1);
    }
    else {
        cs_debug("Error PCSC failed to get ATR for card (%lx)", rv);
    }

    return(0);
}


int pcsc_check_card_inserted(struct s_reader *pcsc_reader)
{
    DWORD dwState, dwAtrLen, dwReaderLen;
    BYTE pbAtr[64];
    ULONG rv;
    
    dwAtrLen = sizeof(pbAtr);
    
    // this is to take care of the case of a reader being started with no card ... we need something better.
    if (!pcsc_reader->pcsc_has_card) {
        rv = SCardConnect(pcsc_reader->hContext, &pcsc_reader->pcsc_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &pcsc_reader->hCard, &pcsc_reader->dwActiveProtocol);
        if (rv==SCARD_E_NO_SMARTCARD) {
            pcsc_reader->pcsc_has_card=0;
            cs_debug("PCSC card in %s removed / absent [dwstate=%lx rv=(%lx)]", pcsc_reader->pcsc_name, dwState, rv );
            return 0;
        }
        else if( rv == SCARD_S_SUCCESS ) {
            pcsc_reader->pcsc_has_card=1;
        }
        
    }

    rv = SCardStatus(pcsc_reader->hCard, NULL, &dwReaderLen, &dwState, &pcsc_reader->dwActiveProtocol, pbAtr, &dwAtrLen);
    cs_debug("PCSC reader %s dwstate=%lx rv=(%lx)", pcsc_reader->pcsc_name, dwState, rv );

    if(rv==SCARD_E_INVALID_HANDLE){
          SCardEndTransaction(pcsc_reader->hCard,SCARD_LEAVE_CARD);
          SCardDisconnect(pcsc_reader->hCard,SCARD_LEAVE_CARD);
    }
    else if (rv == SCARD_S_SUCCESS && (dwState & (SCARD_PRESENT | SCARD_NEGOTIABLE | SCARD_POWERED ) )) {
        cs_debug("PCSC card IS inserted in %s card state [dwstate=%lx rv=(%lx)]", pcsc_reader->pcsc_name, dwState,rv);
        return 3;
    } 
    else {
        if ( (rv==SCARD_W_RESET_CARD) && (dwState == 0) ) {
            cs_debug("PCSC check card reinserted in %s [dwstate=%lx rv=(%lx)]", pcsc_reader->pcsc_name, dwState, rv );
            SCardDisconnect(pcsc_reader->hCard,SCARD_LEAVE_CARD);
            rv = SCardConnect(pcsc_reader->hContext, &pcsc_reader->pcsc_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &pcsc_reader->hCard, &pcsc_reader->dwActiveProtocol);
            return  ((rv != SCARD_S_SUCCESS) ? 2 : 0);
        } 
        else  if ( rv == SCARD_W_REMOVED_CARD && (dwState | SCARD_ABSENT) ) {
             cs_debug("PCSC card in %s removed / absent [dwstate=%lx rv=(%lx)]", pcsc_reader->pcsc_name, dwState, rv );
        }
        else {
             cs_debug("PCSC card inserted FAILURE in %s (%lx) card state (%x) (T=%d)", pcsc_reader->pcsc_name, rv, dwState, ( pcsc_reader->dwActiveProtocol == SCARD_PROTOCOL_T0 ? 0 :  1));
        }

    }
    
    return 0;
}
#endif

