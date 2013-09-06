#ifndef EVQ_H
#define EVQ_H

#if defined(linux) || defined(__linux) || defined(__linux__)
#include <linux/version.h>
#ifndef LINUX_VERSION_CODE
#error "can't find LINUX_VERSION_CODE definition"
#endif
#if (KERNEL_VERSION(2,6,16) > LINUX_VERSION_CODE)
#error "unsupported linux kernel version. must be greater or equal to 2.6.16!"
#else
#warning "kernel version OK"
#endif
#define __ev_linux 1
#include <sys/ioctl.h>
#include <sys/inotify.h>
#define EVBUF_LEN	sizeof(struct inotify_event)
//#define EVQ_WATCH(evfd,events,maxevents) epoll_wait(evfd,events,maxevents,-1)
typedef struct inotify_event event_t;
/* we're watching IN_ATTRIB because one may force data reload by 'touch'-ing the cdb file */
//#define EV_MASK IN_ATTRIB|IN_MODIFY|IN_DELETE
#ifdef USE_TOUCH_RELOADS
#warning "using touch reloads"
#define EV_MASK IN_DELETE_SELF|IN_ATTRIB
#else
#define EV_MASK IN_DELETE_SELF
#endif
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define __ev_bsd 1
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#define EVBUF_LEN sizeof(struct kevent)
typedef struct kevent event_t;
#ifdef USE_TOUCH_RELOADS
#define EV_MASK NOTE_DELETE|NOTE_ATTRIB
#else
#define EV_MASK NOTE_DELETE
#endif
//#define EV_MASK NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_DELETE
//#define EVQ_WATCH(evfd,events,maxevents) kqueue(evfd,NULL,0,events,maxevents,NULL)
#else
#error "no support for other platform than linux or *BSD"
#endif


#endif
