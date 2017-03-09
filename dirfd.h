#ifndef DIRFD_H
#define DIRFD_H

/* gatling currently does
 *
 *   chdir("www.fefe.de:80");
 *   chdir("default");
 *   open(".htaccess_global", ...)
 *   stat(".proxy", ...)
 *   open(".htaccess", ...)
 *   fd=open("index.html", ...)
 *   fstat(fd, ...)
 *
 * for each "GET /" request.
 * Optimization strategy:
 *   - change open and stat to openat and statat, change chdir to using
 *      the right fd.
 *   - cache fd for directories
 *
 * This API is for the directory fd cache. You can ask for an fd for a
 * given dir, and it will return the fd or -1 on error. */

#ifdef __linux__
int ifd;	/* inotify fd */
#endif

struct dircacheentry {
  struct dircacheentry* next;
  const char* htaccess_global;
  size_t htaccess_global_len, hashval;
  int fd;	/* fd of the directory, for use with openat() */
  int proxy;	/* -1 = not there, 0 = don't know, 1 = there */
#if 0
#ifdef __linux__
  int inwd;	/* inotify descriptor */
#endif
#endif
  time_t lng;	/* last known good */
  char dirname[1];
};

struct hashtable {
  struct dircacheentry** ht;
  size_t members, slots;	/* if members > slots, allocate larger table */
};

int initdircache(void);
struct dircacheentry* getdir(const char* name,time_t now);
int getdirfd(const char* dirname,time_t now);
int getdirfd2(const char* dirname,time_t now,struct dircacheentry** x);
void expiredirfd(const char* dirname);

void handle_inotify_events(void);

extern int maxlngdelta /* =10 */;	/* expire entries after 10 seconds */

#endif
