#ifndef READER_IRDETO_H_
#define READER_IRDETO_H_

#ifdef READER_IRDETO
void irdeto_add_emm_header(EMM_PACKET *ep);
#else
static inline void irdeto_add_emm_header(EMM_PACKET *ep) { }
#endif

#endif
