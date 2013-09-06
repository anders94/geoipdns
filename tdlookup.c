#include "uint16.h"
#include "logger.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <alloc.h>
#include "str.h"
#include <string.h>
#include <stdlib.h>
#include "open.h"
#include "tai.h"
#include "cdb.h"
#include "byte.h"
#include "case.h"
#include "dns.h"
#include "seek.h"
#include "response.h"
#include "ipdb.h"
#include "env.h"
#include "scan.h"
#include "prot.h"
#include "strerr.h"
#include "qlog.h"
#include "uint64.h"
#include "evq.h"
#define FATAL "tdlookup: fatal: "


static int want(const char *owner,const char type[2])
{
  unsigned int pos;
  static char *d;
  char x[10];
  uint16 datalen;

  pos = dns_packet_skipname(response,response_len,12); if (!pos) return 0;
  pos += 4;

  while (pos < response_len) {
    pos = dns_packet_getname(response,response_len,pos,&d); if (!pos) return 0;
    pos = dns_packet_copy(response,response_len,pos,x,10); if (!pos) return 0;
    if (dns_domain_equal(d,owner))
      if (byte_equal(type,2,x))
        return 0;
    uint16_unpack_big(x + 8,&datalen);
    pos += datalen;
  }
  return 1;
}

static char *d1;

//static char clientloc[2];
static uint32 clientloc;
static struct tai now;
static struct cdb c;
static int cfd;
static int evfd;
#if defined(__ev_bsd)
static struct timespec nowait = { .tv_sec = 0, .tv_nsec = 0 };
#endif
event_t evbuf;
static char data[32767];
static uint32 dlen;
static unsigned int dpos;
static char type[2];
static uint32 ttl;

static int find(char *d,int flagwild)
{
  int r;
  char ch;
  struct tai cutoff;
  char ttd[8];
  char ttlstr[4];
  //char recordloc[2];
	char recordloc[4];
	uint32 u = 0;
  double newttl;
  for (;;) {
    r = cdb_findnext(&c,d,dns_domain_length(d));
    if (r <= 0) {
			return r;
		}
    dlen = cdb_datalen(&c);
    if (dlen > sizeof data) return -1;
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return -1;
    dpos = dns_packet_copy(data,dlen,0,type,2); if (!dpos) return -1;
    dpos = dns_packet_copy(data,dlen,dpos,&ch,1); if (!dpos) return -1;
    if ((ch == '=' + 1) || (ch == '*' + 1)) {
      --ch;
      dpos = dns_packet_copy(data,dlen,dpos,recordloc,4); if (!dpos) return -1;
			uint32_unpack(recordloc,&u);
			//TODO: checkthis - maybe unpack_big first and != after
      //if (byte_diff(recordloc,4,clientloc)) continue;
			if (u != clientloc) continue;
    }
    if (flagwild != (ch == '*')) continue;
    dpos = dns_packet_copy(data,dlen,dpos,ttlstr,4); if (!dpos) return -1;
    uint32_unpack_big(ttlstr,&ttl);
    dpos = dns_packet_copy(data,dlen,dpos,ttd,8); if (!dpos) return -1;
    if (byte_diff(ttd,8,"\0\0\0\0\0\0\0\0")) {
      tai_unpack(ttd,&cutoff);
      if (ttl == 0) {
	if (tai_less(&cutoff,&now)) continue;
	tai_sub(&cutoff,&cutoff,&now);
	newttl = tai_approx(&cutoff);
	if (newttl <= 2.0) newttl = 2.0;
	if (newttl >= 3600.0) newttl = 3600.0;
	ttl = newttl;
      }
      else
	if (!tai_less(&cutoff,&now)) continue;
    }
    return 1;
  }
}

static int dobytes(unsigned int len)
{
  char buf[20];
  if (len > 20) return 0;
  dpos = dns_packet_copy(data,dlen,dpos,buf,len);
  if (!dpos) return 0;
  return response_addbytes(buf,len);
}

static int doname(void)
{
  dpos = dns_packet_getname(data,dlen,dpos,&d1);
  if (!dpos) return 0;
  return response_addname(d1);
}
static int doit(char *q,char qtype[2])
{
  unsigned int bpos;
  unsigned int anpos;
  unsigned int aupos;
  unsigned int arpos;
  char *control;
  char *wild;
  int flaggavesoa;
  int flagfound;
  int r;
  int flagns;
  int flagauthoritative;
  char x[20];
  uint16 u16;
  char addr[8][4];
  int addrnum;
  uint32 addrttl;
  int i;
  anpos = response_len;

  control = q;
  for (;;) {
    flagns = 0;
    flagauthoritative = 0;
    cdb_findstart(&c);
    while (r = find(control,0)) {
      if (r == -1) return 0;
			if (byte_equal(type,2,DNS_T_SOA)) { /*dbger("SOA type requested");*/ flagauthoritative = 1;}
			if (byte_equal(type,2,DNS_T_NS)) flagns = 1;
    }
    if (flagns) break;
    if (!*control) return 0; /* q is not within our bailiwick */
    control += *control;
    control += 1;
  }

  if (!flagauthoritative) {
    response[2] &= ~4;
    goto AUTHORITY; /* q is in a child zone */
		/*dbger("goto childzone search");*/
  }


  flaggavesoa = 0;
  flagfound = 0;
  wild = q;

  for (;;) {
    addrnum = 0;
    addrttl = 0;
    cdb_findstart(&c);
    while (r = find(wild,wild != q)) {
      if (r == -1) return 0;
      flagfound = 1;
      if (flaggavesoa && byte_equal(type,2,DNS_T_SOA)) continue;
      if (byte_diff(type,2,qtype) && byte_diff(qtype,2,DNS_T_ANY) && byte_diff(type,2,DNS_T_CNAME)) continue;
      if (byte_equal(type,2,DNS_T_A) && (dlen - dpos == 4)) {
				addrttl = ttl;
				i = dns_random(addrnum + 1);
				if (i < 8) {
	  			if ((i < addrnum) && (addrnum < 8))
	    			byte_copy(addr[addrnum],4,addr[i]);
	  			byte_copy(addr[i],4,data + dpos);
				}
				if (addrnum < 1000000) ++addrnum;
				continue;
      }
      if (!response_rstart(q,type,ttl)) return 0;
      if (byte_equal(type,2,DNS_T_NS) || byte_equal(type,2,DNS_T_CNAME) || byte_equal(type,2,DNS_T_PTR)) {
				if (!doname()) return 0;
      } else if (byte_equal(type,2,DNS_T_MX)) {
				if (!dobytes(2)) return 0;
				if (!doname()) return 0;
      }
      else if (byte_equal(type,2,DNS_T_SOA)) {
				if (!doname()) return 0;
				if (!doname()) return 0;
				if (!dobytes(20)) return 0;
        flaggavesoa = 1;
      } else {
        if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
			}
      response_rfinish(RESPONSE_ANSWER);
    }
    for (i = 0;i < addrnum;++i) {
      if (i < 8) {
				if (!response_rstart(q,DNS_T_A,addrttl)) return 0;
				if (!response_addbytes(addr[i],4)) return 0;
				response_rfinish(RESPONSE_ANSWER);
      }
		}
    if (flagfound) break;
    if (wild == control) break;
    if (!*wild) break; /* impossible */
    wild += *wild;
    wild += 1;
  }

  if (!flagfound) {
		//dbger("RET: NXdomain");
    response_nxdomain();
	}


  AUTHORITY:
  aupos = response_len;

  if (flagauthoritative && (aupos == anpos)) {
    cdb_findstart(&c);
    while (r = find(control,0)) {
      if (r == -1) return 0;
      if (byte_equal(type,2,DNS_T_SOA)) {
        if (!response_rstart(control,DNS_T_SOA,ttl)) return 0;
				if (!doname()) return 0;
				if (!doname()) return 0;
				if (!dobytes(20)) return 0;
        response_rfinish(RESPONSE_AUTHORITY);
        break;
      }
    }
  }
  else
    if (want(control,DNS_T_NS)) {
      cdb_findstart(&c);
      while (r = find(control,0)) {
        if (r == -1) return 0;
        if (byte_equal(type,2,DNS_T_NS)) {
          if (!response_rstart(control,DNS_T_NS,ttl)) return 0;
	  			if (!doname()) return 0;
          response_rfinish(RESPONSE_AUTHORITY);
        }
      }
    }

  arpos = response_len;

  bpos = anpos;
  while (bpos < arpos) {
    bpos = dns_packet_skipname(response,arpos,bpos); if (!bpos) return 0;
    bpos = dns_packet_copy(response,arpos,bpos,x,10); if (!bpos) return 0;
    if (byte_equal(x,2,DNS_T_NS) || byte_equal(x,2,DNS_T_MX)) {
      if (byte_equal(x,2,DNS_T_NS)) {
        if (!dns_packet_getname(response,arpos,bpos,&d1)) return 0;
      }
      else
        if (!dns_packet_getname(response,arpos,bpos + 2,&d1)) return 0;
      case_lowerb(d1,dns_domain_length(d1));
      if (want(d1,DNS_T_A)) {
	cdb_findstart(&c);
	while (r = find(d1,0)) {
          if (r == -1) return 0;
	  if (byte_equal(type,2,DNS_T_A)) {
            if (!response_rstart(d1,DNS_T_A,ttl)) return 0;
	    if (!dobytes(4)) return 0;
            response_rfinish(RESPONSE_ADDITIONAL);
	  }
        }
      }
    }
    uint16_unpack_big(x + 8,&u16);
    bpos += u16;
  }

  if (flagauthoritative && (response_len > 512)) {
    byte_zero(response + RESPONSE_ADDITIONAL,2);
    response_len = arpos;
    if (response_len > 512) {
      byte_zero(response + RESPONSE_AUTHORITY,2);
      response_len = aupos;
    }
  }

  return 1;
}

int datare(void)
{
	dbger("datare(): closing cdb ...\n");
    cdb_free(&c);
	close(cfd);
	dbger("datare(): reopening cdb ...\n");
	cfd = open_read("data.cdb");
	if (cfd == -1) return 0;
	cdb_init(&c,cfd);
	return 1;
}

int datachk(void)
{
	//event_t evbuf;
#ifdef __ev_linux
	int msglen = -1;
	evbuf.mask = 0;
	if (ioctl(evfd,FIONREAD,&msglen) < 0) {
		dbger("bad ioctl\n");
		return 0;
	}
	if (msglen == 0) {
		dbger("no pending events\n");
		return 1;
	}
	//we're watching the same set of events on the same file so multiple events should be merged into a single one
	//but until im checking it by hand i wont trust it. better throw error if manpage lies
	if (msglen != EVBUF_LEN) {
		dbger("bad event buffer length %d should be %d\n", msglen,sizeof(event_t));
		return 0;
	}
	if (read(evfd,&evbuf,msglen) != msglen) {
		dbger("trucated evbuf read!\n");
		return 0; //should never test positive
	}
	if (evbuf.mask & IN_Q_OVERFLOW) {
		dbger("IN_Q_OVERFLOW,");
		return 0;
	}
	if (evbuf.mask & IN_OPEN) dbger("IN_OPEN,");
	if (evbuf.mask & IN_DELETE_SELF)  dbger("IN_DELETE_SELF,");
	if (!datare()) return 0;
	//reinstall event (its a new inode)
	inotify_add_watch(evfd,"data.cdb",EV_MASK|IN_ONESHOT);
#else
	int rc;
  dbger("datachk(): evfd=%d,cfd=%d\n",evfd,cfd);
	rc = kevent(evfd,NULL,0,&evbuf,1,&nowait);
	if (rc < 0)  {
		dbger("error querying for pending events\n");
		return 0;
	}
	if (rc == 0) {
		return 1;
	}
	// same thing, multiple events matchin the same filter get to be aggregated into one
	if (rc != 1) /*wtf*/ return 0;
	dbger("datachk(): pending events to process. reloading data ...\n");
	if (!datare()) return 0;
	//with kqueue() we need to reinstall the event because we've closed the fd
	//EV_ONESHOT may help and shouldnt do any harm in this case not sure how kq works
	EV_SET(&evbuf,cfd,EVFILT_VNODE,EV_ADD|EV_ONESHOT,EV_MASK,0,NULL);
	if (kevent(evfd,&evbuf,1,NULL,0,(struct timespec *)0) < 0) return 0;
#endif
	return 1;
}


/* this gets called once when the server is started 
 * we open the data.cdb and register ourselves to get notified 
 * on data.cdb changes
 * */
int dataini(void)
{
	int rc;
	cfd = open_read("data.cdb");
	if (cfd == -1) return 0;
	cdb_init(&c,cfd);
#if defined(__ev_linux)
	dbger("INIT_inotify():\n");
	evfd = inotify_init();
#else
	dbger("INIT_kqueue()\n");
	evfd = kqueue();
#endif
	if (evfd == -1) return 0;
#if defined(__ev_linux)
	dbger("inotify_fd=%d\n", inotify_add_watch(evfd,"data.cdb",EV_MASK|IN_ONESHOT));
#else
	EV_SET(&evbuf,cfd,EVFILT_VNODE,EV_ADD|EV_ONESHOT,EV_MASK,0,NULL);
	if ( (rc = kevent(evfd,&evbuf,1,NULL,0,NULL)) < 0) return 0;
	dbger("adding fs watch on data.cdb ... evfd=%d,cfd=%d,rc=%d\n",evfd,cfd,rc);
#endif
	return 1;
}

/* this should be called once before we die but its not really a necessity */
void datafini(void)
{
	cdb_free(&c);
	close(cfd);
	/* blah-blah's, remove event listeners, etc - not really needed kernel will cleanup on process exit */
}

#ifdef USE_LOCMAPS
//static const char defloc[2] = { '~', '~' };
//static const uint32 defloc = UINT32_MAX;
static const uint32 defloc = NOMATCH_HASH; // 'nomatch' hash val
#endif

int respond(char *q,char qtype[2],char ip[4])
{
	char out[255];
#ifdef USE_LOCMAPS
	uint32 uid = 0;
	uint32 mid = 0;
	int r = 0;
	//char t[255];
	//int l_idx[63]; //labels indexed in fqdn,including first pos (0)
	char z[260]; /* t.maxlen+4*/
	char u[8];
	unsigned int l = 256; /*safe error mode */
	int len;
#endif
	
	if (!datachk()) return 0;
  tai_now(&now);
#ifndef USE_LOCMAPS
	clientloc = 0U;
	//clientloc[0] = 0;
	//clientloc[1] = 0;
	return doit(q,qtype);
#else
	//clientloc[0] = defloc[0];
	//clientloc[1] = defloc[1];
	clientloc = defloc;
	z[0] = '\0';
	z[1] = '?';
/*
	if (byte_equal(qtype,2,DNS_T_CNAME)) {
		dbger("lookup LOQ for CNAME record\n");
	}
	if (byte_equal(qtype,2,DNS_T_A)) {
		dbger("lookup LOQ for A record %s",fqdn_read(out,q));
	}
*/
	z[2] = qtype[0];
	z[3] = qtype[1];
	l = dns_domain_length(q);
	if (l > 255) return 0; /* it's safe. label,bytelen|dot*/
	byte_copy(z+4,l,q);
	r = cdb_find(&c,z,l+4);
	if (r == -1) return 0;
	if (r == 0) {
		//dbger("no loq for %s",fqdn_read(out,q));
		//clientloc = 0U;
		return doit(q,qtype);
	}
	len = cdb_datalen(&c);
	if (cdb_read(&c,u,len,cdb_datapos(&c)) == -1) return 0;
	uint32_unpack(u,&mid);
	uint32_unpack(u+4,&uid);
	//dbger("found mid=%u uid=%u\n",mid,uid);
	if (!ipdb_get(&c,ip,&clientloc,mid,uid)) return 0;
	//dbger("found loq loc=%u,mid=%u,uid=%u for q=%s,defaultloc=%u",clientloc,mid,uid,fqdn_read(out,q),defloc);
  return doit(q,qtype);
#endif
}
