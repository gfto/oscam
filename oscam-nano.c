//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"

//#define CS_NANO_GEO   0x9F
#define CS_NANO_CLASS 0xE2

int find_nano(uchar *ecm, int l, uchar nano, int s)
{
  uchar *snano;

  if( s >= l ) return 0;
  if( !s ) s=(ecm[4]==0xD2) ? 12 : 9;	// tpsflag -> offset+3
  snano = ecm + s;

  while( (*snano!=nano) && (s<l) )
  {
    if( *snano == 0xEA ) return 0;
    snano++;
    s++;
  }

  return (s<l)?++s:0;
}

int chk_class(ECM_REQUEST *er, CLASSTAB *clstab, const char *type, const char *name)
{
  int i, j, an, cl_n, l;
  uchar ecm_class;

  if( er->caid!=0x0500 ) return 1;
  if( !clstab->bn && !clstab->an ) return 1;

  j=an=cl_n=l=0;
  while( (j=find_nano(er->ecm, er->l, CS_NANO_CLASS, j)) > 0 )
  {
    l = er->ecm[j];
    ecm_class = er->ecm[j+l];
    cs_debug("ecm class=%02X", ecm_class);
    for( i=0; i<clstab->bn; i++ )  // search in blocked
      if( ecm_class==clstab->bclass[i] ) 
      {
        cs_debug("class %02X rejected by %s '%s' !%02X filter", 
                 ecm_class, type, name, ecm_class);
        return 0;
      }

    cl_n++;
    for( i=0; i<clstab->an; i++ )  // search in allowed
      if( ecm_class==clstab->aclass[i] ) 
      {
        an++;
        break;
      }
    j+=l;
  }

  if( cl_n && clstab->an )
  {
    if( an ) 
      cs_debug("ECM classes allowed by %s '%s' filter", type, name);
    else {
      cs_debug("ECM classes don't match %s '%s' filter, rejecting", type, name);
      return 0;
    }
  }

  return 1;
}

/*
int chk_geo(ECM_REQUEST *er, int el, unsigned char *rclass, int cl)
{

  return 1;
}
*/
