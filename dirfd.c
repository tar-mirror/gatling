#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/inotify.h>
#endif
#include "mmap.h"
#include "dirfd.h"
#include <stdio.h>

int maxlngdelta=10;

#if __GNUC__ < 3
#define __expect(foo,bar) (foo)
#else
#define __expect(foo,bar) __builtin_expect((long)(foo),bar)
#endif
#define __likely(foo) __expect((foo),1)
#define __unlikely(foo) __expect((foo),0)

size_t cchash(const char* key) {
  size_t i,h;
  for (i=h=0; key[i]; ++i)
    h=((h<<5)+h)^key[i];
  return h;
}

const size_t primes[] = { 257, 521, 1031, 2053, 4099, 8209, 16411, 32771, 65537, 131101, 262147, 524309, 1048583, 2097169, 4194319 };
const size_t numprimes = sizeof(primes)/sizeof(primes[0])-1;

struct hashtable dc;

#ifdef __linux__
int rootwd;
#endif

/* initialize a hashtable as empty */
int initdircache(void) {
  dc.ht=calloc(dc.slots=257,sizeof(dc.ht[0]));
  if (!dc.ht) return -1;
  dc.members=0;
#ifdef __linux__
  ifd=inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
  if (ifd!=-1)
    rootwd=inotify_add_watch(ifd,".",IN_DELETE|IN_CREATE|IN_MOVED_FROM|IN_MOVED_TO);
#endif
  return 0;
}

void deinitdircacheentry(struct dircacheentry* d) {
  if (d->fd!=-1) close(d->fd);
  if (d->htaccess_global) mmap_unmap(d->htaccess_global,d->htaccess_global_len);
}

struct dircacheentry** hashtable_lookup(const char* restrict key,size_t hashval) {
  size_t slot=hashval % dc.slots;
  struct dircacheentry** restrict cur;
//  printf("hashtable_lookup(\"%s\") -> hashval %x -> slot %x\n",key,hashval,slot);
  for (cur=&dc.ht[slot]; *cur; cur=&(*cur)->next)
    if ((*cur)->hashval == hashval && !strcmp(key,(*cur)->dirname))
      break;
  return cur;
}

void dc_resize() {
  if (dc.slots < primes[numprimes] && dc.members > dc.slots+(dc.slots/2)) {
    size_t i,newslots;
    struct dircacheentry** newtab;
    for (i=0; i<numprimes && primes[i]<dc.members; ++i) ;
    newslots=primes[i];
    newtab=calloc(newslots,sizeof(newtab[0]));
    if (!newtab) return;	/* do not resize if out of memory */
    for (i=0; i<dc.slots; ++i) {
      struct dircacheentry* cur,* next;
      for (cur=dc.ht[i]; cur; cur=next) {
	size_t newslot=cur->hashval % newslots;
	next=cur->next;
	cur->next=newtab[newslot];
	newtab[newslot]=cur;
      }
    }
    free(dc.ht);
    dc.ht=newtab;
    dc.slots=newslots;
  }
}

struct dircacheentry* getdir(const char* name,time_t now) {
  size_t hashval=cchash(name);
  struct dircacheentry** hnp=hashtable_lookup(name,hashval);
  struct dircacheentry* h;
  struct dircacheentry* next=0;
  if (*hnp) {
    if (now-(*hnp)->lng>maxlngdelta) {
      /* need to expire */
//      printf("expire(\"%s\")\n",(*hnp)->dirname);
      deinitdircacheentry(*hnp);
#if 0
#ifdef __linux__
      if ((*hnp)->inwd)
	inotify_rm_watch(ifd,(*hnp)->inwd);
#endif
#endif
      next=(*hnp)->next;
      goto expired;
    }
    return *hnp;
  }
  /* if not there, make new entry */
  *hnp=malloc(sizeof(**hnp)+strlen(name));
  if (!*hnp) return 0;
expired:
  h=*hnp;
  memset(h,0,sizeof(*h));
  h->next=next;
  strcpy(h->dirname,name);
  h->hashval=hashval;
  h->lng=now;
#ifndef O_PATH
#define O_PATH 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
  h->fd=open(name,O_RDONLY|O_DIRECTORY|O_PATH|O_CLOEXEC);
//  printf("getdir(\"%s\") -> %d\n",name,h->fd);
#if 0
#ifdef __linux__
  if (h->fd!=-1)
    h->inwd=inotify_add_watch(ifd,name,IN_DELETE|IN_CREATE|IN_MOVED_FROM|IN_MOVED_TO);
#endif
#endif
  if (dc.slots < primes[numprimes] && dc.members > dc.slots+(dc.slots/2)) {
//    printf("  RESIZE\n");
    dc_resize();
  }
  return h;
}

/* return value belonging to key or -1 if not found */
int getdirfd(const char* restrict key,time_t now) {
  struct dircacheentry* hn=getdir(key,now);
  return hn?hn->fd:-1;
}

/* return value belonging to key or -1 if not found */
int getdirfd2(const char* restrict key,time_t now,struct dircacheentry** x) {
  struct dircacheentry* hn=getdir(key,now);
  *x=hn;
  return hn?hn->fd:-1;
}


/* traverse hash table: return first element (NULL if no elements) */
struct dircacheentry* hashtable_findfirst() {
  size_t i;
  for (i=0; i<dc.slots; ++i)
    if (dc.ht[i]) return dc.ht[i];
  return 0;
}

/* traverse hash table: return next element (NULL if no more elements) */
struct dircacheentry* hashtable_findnext(struct dircacheentry* restrict hn) {
  size_t slot;
  if (hn->next) return hn->next;
  slot=hn->hashval % dc.slots;
  for (++slot; slot<dc.slots; ++slot)
    if (dc.ht[slot]) return dc.ht[slot];
  return 0;
}

/* delete key+value from hash table */
/* calls ff on key+value first, unless NULL is passed */
/* return -1 if key not found, 0 if key deleted OK */
int hashtable_delete(const char* restrict key) {
  struct dircacheentry** cur=hashtable_lookup(key,cchash(key));
  struct dircacheentry* tmp;
  if (!*cur) return -1;
#if 0
#ifdef __linux__
  if ((*cur)->inwd>=0)
    inotify_rm_watch(ifd,(*cur)->inwd);
#endif
#endif
  if ((*cur)->fd!=-1)
    deinitdircacheentry(*cur);
  tmp=(*cur);
  *cur=tmp->next;
  free(tmp);
  --dc.members;
  return 0;
}

/* free whole hash table, calling ff on each node if ff is non-NULL */
void hashtable_free(void) {
  size_t i;
  for (i=0; i<dc.slots; ++i) {
    struct dircacheentry* cur,* next;
    for (cur=dc.ht[i]; cur; cur=next) {
      next=cur->next;

#if 0
#ifdef __linux__
      if (cur->inwd>=0)
	inotify_rm_watch(ifd,cur->inwd);
#endif
#endif
      if (cur->fd!=-1)
	deinitdircacheentry(cur);

      free(cur);
    }
  }
  free(dc.ht);
}

void expiredirfd(const char* dirname) {
  hashtable_delete(dirname);
}

#ifdef __linux__
void handle_inotify_events(void) {
  char buf[2048];
  struct inotify_event* ie=(struct inotify_event*)buf;
  ssize_t n=read(ifd,buf,sizeof(buf));
  if (n<=0) return;
  if (ie->wd==rootwd) {
    /* a vhost disappeared or was added */
//    if (ie->mask & (IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE|IN_CREATE))
    expiredirfd(ie->name);
  }
}
#endif

#ifdef TEST

#include <stdio.h>
#include <time.h>

int main() {
  time_t now=time(0);
  if (initdircache()) {
    perror("dircache init failed");
    return 1;
  }
  handle_inotify_events();
  printf("localhost:80 -> %d\n",getdirfd("localhost:80",now));
  handle_inotify_events();
  symlink("default","localhost:80");
  handle_inotify_events();
  printf("localhost:80 -> %d\n",getdirfd("localhost:80",now));
  handle_inotify_events();
  return 0;
}
#endif
