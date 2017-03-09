#ifndef _GATLING_H
#define _GATLING_H

#define _FILE_OFFSET_BITS 64

#include "gatling_features.h"
#include "io.h"
#include "iob.h"
#include "array.h"
#include "buffer.h"
#include "uint16.h"
#include "uint32.h"
#include "uint64.h"

#include <sys/stat.h>
#include <regex.h>
#include <sys/un.h>

#include <time.h>

#ifdef STATE_DEBUG
#include <stdio.h>
#endif

#ifdef SUPPORT_FTP
enum ftpstate {
  GREETING,
  WAITINGFORUSER,
  LOGGEDIN,
  WAITCONNECT,
  DOWNLOADING,
  UPLOADING,
};

extern int askforpassword;
#endif

#ifdef SUPPORT_PROXY
enum proxyprotocol {
  HTTP,
  FASTCGI,
  SCGI,
};
#endif

enum encoding {
  NORMAL=0,
  GZIP=1,
#ifdef SUPPORT_BZIP2
  BZIP2=2,
#endif
#ifdef SUPPORT_BROTLI
  BROTLI=3,
#endif
};

enum conntype {
  UNUSED,

  HTTPSERVER6,	/* call socket_accept6() */
  HTTPSERVER4,	/* call socket_accept4() */
  HTTPREQUEST,	/* read and handle http request */

#ifdef SUPPORT_FTP
  FTPSERVER6,	/* call socket_accept6() */
  FTPSERVER4,	/* call socket_accept4() */
  FTPCONTROL6,	/* read and handle ftp commands */
  FTPCONTROL4,	/* read and handle ftp commands */
  FTPPASSIVE,	/* accept a slave connection */
  FTPACTIVE,	/* still need to connect slave connection */
  FTPSLAVE,	/* send/receive files */
#endif

#ifdef SUPPORT_SMB
  SMBSERVER6,	/* call socket_accept6() */
  SMBSERVER4,	/* call socket_accept4() */
  SMBREQUEST,	/* read and handle SMB request */
#endif

#ifdef SUPPORT_PROXY
  PROXYSLAVE,	/* write-to-proxy connection. */
		/* write HTTP header; switch type to PROXYPOST */
  PROXYPOST,	/* while still_to_copy>0: write POST data; relay answer */
  HTTPPOST,	/* type of HTTP request with POST data
		   read post data and write them to proxy (ctx->buddy) */
#endif

#ifdef SUPPORT_HTTPS
  HTTPSSERVER4,	/* call socket_accept6() */
  HTTPSSERVER6,	/* call socket_accept4() */
  HTTPSACCEPT,	/* call SSL_accept() */
  HTTPSACCEPT_CHECK,	/* check whether input looks like SSL, then call SSL_accept() */
  HTTPSREQUEST,	/* read and handle https request */
  HTTPSRESPONSE,	/* write response to https request */
  HTTPSPOST,	/* like HTTPPOST but using SSL */
#endif

  PUNISHMENT,	/* if we detected a DoS and tarpit someone */

  LAST_UNUNSED
};

#ifdef SUPPORT_HTTPS

#ifdef USE_POLARSSL
#undef USE_OPENSSL
#else
#define USE_OPENSSL
#endif

#ifdef USE_OPENSSL
/* in ssl.c */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
extern int init_serverside_tls(SSL** ssl,int sock);
#endif

#ifdef USE_POLARSSL
/* in pssl.c */
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
#include <mbedtls/error.h>
#include "pssl.h"

#endif

void free_tls_memory(void);

#endif

/* the tree id is always 1 (we export exactly one tree in TreeConnectAndX)
 * the user id is always 1, too (we hand it out in SessionSetupAndX)
 * we need to hand out file handles relative to the PID though */
struct handle {
  uint32_t pid,handle;
  int fd;
  off_t size,cur;
  unsigned short* filename;
};

struct handles {
  size_t u,a;	/* used, allocated */
  struct handle* h;
};

#ifdef SUPPORT_PROXY

static const unsigned long long UNKNOWN=-1;
static const unsigned long long CHUNKED=-2;

struct httpstreamstate {
  enum {
    HSS_HEADER,		// have not seen full header yet

    HSS_HEADER_C,	// inside header, saw \nC
    HSS_HEADER_CO,	// inside header, saw \nCo
    HSS_HEADER_CON,	// inside header, saw \nCon
    HSS_HEADER_CONT,	// inside header, saw \nCont
    HSS_HEADER_CONTE,	// inside header, saw \nConte
    HSS_HEADER_CONTEN,	// inside header, saw \nConten
    HSS_HEADER_CONTENT,	// inside header, saw \nContent
    HSS_HEADER_CONTENT_,	// inside header, saw \nContent-
    HSS_HEADER_CONTENT_L,	// inside header, saw \nContent-L
    HSS_HEADER_CONTENT_LE,	// inside header, saw \nContent-Le
    HSS_HEADER_CONTENT_LEN,	// inside header, saw \nContent-Len
    HSS_HEADER_CONTENT_LENG,	// inside header, saw \nContent-Leng
    HSS_HEADER_CONTENT_LENGT,	// inside header, saw \nContent-Lengt
    HSS_HEADER_CONTENT_LENGTH,	// inside header, saw \nContent-Length
    HSS_HEADER_CONTENT_LENGTH_,	// inside header, saw \nContent-Length:
    HSS_HEADER_CONTENT_LENGTH_NUM,	// inside header, saw \nContent-Length: *[0-9]

    HSS_HEADER_T,	// inside header, saw \nT
    HSS_HEADER_TR,	// inside header, saw \nTr
    HSS_HEADER_TRA,	// inside header, saw \nTra
    HSS_HEADER_TRAN,	// inside header, saw \nTran
    HSS_HEADER_TRANS,	// inside header, saw \nTrans
    HSS_HEADER_TRANSF,	// inside header, saw \nTransf
    HSS_HEADER_TRANSFE,	// inside header, saw \nTransfe
    HSS_HEADER_TRANSFER,	// inside header, saw \nTransfer
    HSS_HEADER_TRANSFER_,	// inside header, saw \nTransfer-
    HSS_HEADER_TRANSFER_E,	// inside header, saw \nTransfer-E
    HSS_HEADER_TRANSFER_EN,	// inside header, saw \nTransfer-En
    HSS_HEADER_TRANSFER_ENC,	// inside header, saw \nTransfer-Enc
    HSS_HEADER_TRANSFER_ENCO,	// inside header, saw \nTransfer-Enco
    HSS_HEADER_TRANSFER_ENCOD,	// inside header, saw \nTransfer-Encod
    HSS_HEADER_TRANSFER_ENCODI,	// inside header, saw \nTransfer-Encodi
    HSS_HEADER_TRANSFER_ENCODIN,	// inside header, saw \nTransfer-Encodin
    HSS_HEADER_TRANSFER_ENCODING,	// inside header, saw \nTransfer-Encoding
    HSS_HEADER_TRANSFER_ENCODING_,	// inside header, saw \nTransfer-Encoding:
    HSS_HEADER_TRANSFER_ENCODING_C,	// inside header, saw \nTransfer-Encoding: *c
    HSS_HEADER_TRANSFER_ENCODING_CH,	// inside header, saw \nTransfer-Encoding: *ch
    HSS_HEADER_TRANSFER_ENCODING_CHU,	// inside header, saw \nTransfer-Encoding: *chu
    HSS_HEADER_TRANSFER_ENCODING_CHUN,	// inside header, saw \nTransfer-Encoding: *chun
    HSS_HEADER_TRANSFER_ENCODING_CHUNK,	// inside header, saw \nTransfer-Encoding: *chunk
    HSS_HEADER_TRANSFER_ENCODING_CHUNKE,	// inside header, saw \nTransfer-Encoding: *chunke
    HSS_HEADER_TRANSFER_ENCODING_CHUNKED,	// inside header, saw \nTransfer-Encoding: *chunked

    HSS_HEADER_OTHER,	// inside some other header line

    HSS_HEADER_CR,	// inside header, saw \r
    HSS_HEADER_CRLF,	// inside header, saw \r\n
    HSS_HEADER_CRLFCR,	// inside header, saw \r\n\r
    HSS_KNOWLENGTH,	// have seen header, know number of bytes left
    HSS_INFINITE,	// neither content-length nor chunked encoding found

    HSS_HEADER_CHUNKED,	// reading chunked encoding header
    HSS_HEADER_CHUNKED_CR,	// reading chunked encoding header, saw \r
    HSS_HEADER_CHUNKED_CRLF,	// reading chunked encoding header, saw \r\n
    HSS_HEADER_CHUNKED_CRLF_NUM,	// reading chunked encoding header, saw \r\n[0-9]+
    HSS_HEADER_CHUNKED_CRLF_NUM_CR,	// reading chunked encoding header, saw \r\n[0-9]+\r

    HSS_KNOWLENGTH_CHUNKED,	// read chunk header, know length of it, and it's > 0

    HSS_DONE		// we saw all we need
  } state;
  enum {
    DONTKNOW=0,
    REQUEST=1,
    POSTREQUEST=2,
    RESPONSE_MAYBE=3,
    RESPONSE=4,
  } type;
  unsigned long long bytesleft;
};

void httpstream_initstate(struct httpstreamstate* hss);
int httpstream_update(struct httpstreamstate* hss,char c);
size_t httpstream(struct httpstreamstate* hss,
		  const char* buf, size_t len);
#endif

struct http_data {
  enum conntype t;
#ifdef SUPPORT_FTP
  enum ftpstate f;
#endif
  array r;
  io_batch iob;
  char myip[16];	/* this is needed for virtual hosting */
  uint32 myscope_id;	/* in the absence of a Host header */
  uint16 myport,peerport;
  uint16 destport;	/* port on remote system, used for active FTP */
  char* hdrbuf,* bodybuf;
  const char *mimetype;
  int hlen,blen;	/* hlen == length of hdrbuf, blen == length of bodybuf */
  int keepalive;	/* 1 if we want the TCP connection to stay connected */
			/* this is always 1 for FTP except after the client said QUIT */
  int filefd;		/* -1 or the descriptor of the file we are sending out */
  int buddy;		/* descriptor for the other connection, used for FTP and proxy/CGI */
  char peerip[16];	/* needed for active FTP */
  unsigned long long received,sent;
  enum encoding encoding;
#if defined(SUPPORT_FTP) || defined(SUPPORT_SMB)
  char* ftppath;	/* for FTP we store the path here, for SMB the last FIRST_FIRST2 glob expression */
#endif
#ifdef SUPPORT_SMB
  uint32_t smbattrs;	/* attributes from FIND_FIRST2 so FIND_NEXT2 knows whether to return directories */
#endif
#ifdef SUPPORT_FTP
  uint64 ftp_rest;	/* offset to start transfer at */
#endif
  uint64 sent_until,prefetched_until;
#ifdef SUPPORT_PROXY
  enum proxyprotocol proxyproto;
  unsigned long long still_to_copy;	/* for POST/PUT requests */
  int havefirst;	/* first read contains cgi header */
  char* oldheader;	/* old, unmodified request */
  struct httpstreamstate hss;
#endif
#ifdef SUPPORT_HTTPS
#ifdef USE_POLARSSL
  struct ssl_data* ssldata;
#endif
#ifdef USE_OPENSSL
  SSL* ssl;
#endif
#if 0
  int writefail;
#endif
#endif
#ifdef SUPPORT_SMB
  struct handles h;
#endif
#ifdef SUPPORT_THREADED_OPEN
  int try_encoding;
  int cwd;
  char* name_of_file_to_open;
  struct stat ss;
#endif
#ifdef STATE_DEBUG
  int myfd;
#endif
};

#ifdef STATE_DEBUG
extern const char* state2string(enum conntype t);
#endif

static inline void changestate(struct http_data* x,enum conntype t) {
#ifdef STATE_DEBUG
  if (x->t==UNUSED)
    printf("STATE: new fd %d: state %s\n",x->myfd,state2string(t));
  else
    printf("STATE: fd %d: state change from %s to %s\n",x->myfd,state2string(x->t),state2string(t));
#endif
  x->t=t;
}

#ifdef SUPPORT_HTTPS
extern char* sshd;
#endif

extern size_t max_handles;

extern struct handle* alloc_handle(struct handles* h);
extern struct handle* deref_handle(struct handles* h,uint32_t handle);
extern void close_handle(struct handle* h);
extern void close_all_handles(struct handles* h);

extern int virtual_hosts;
extern int transproxy;
extern int directory_index;
extern int logging;
extern int nouploads;
extern int chmoduploads;
extern const char months[];
#ifdef __MINGW32__
extern char origdir[PATH_MAX];
#else
extern int64 origdir;
#endif

typedef struct de {
  long name;	/* offset within b */
  struct stat ss;
  int todir;
} de;
extern char* base;

extern int sort_name_a(de* x,de* y);
extern int sort_name_d(de* x,de* y);
extern int sort_mtime_a(de* x,de* y);
extern int sort_mtime_d(de* x,de* y);
extern int sort_size_a(de* x,de* y);
extern int sort_size_d(de* x,de* y);

extern unsigned long connections;
extern unsigned long http_connections, https_connections, ftp_connections, smb_connections;
extern unsigned long cps,cps1;	/* connections per second */
extern unsigned long rps,rps1;	/* requests per second */
extern unsigned long eps,eps1;	/* events per second */
extern unsigned long long tin,tin1;	/* traffic inbound */
extern unsigned long long tout,tout1;	/* traffic outbound */

extern int open_for_reading(int64* fd,const char* name,struct stat* SS,int dirfd);
extern unsigned int fmt_2digits(char* dest,int i);
extern int canonpath(char* s);
extern int open_for_writing(int64* fd,const char* name,int dirfd);

#ifdef SUPPORT_FTP
extern void ftpresponse(struct http_data* h,int64 s);
extern void handle_read_ftppassive(int64 i,struct http_data* H);
extern void handle_write_ftpactive(int64 i,struct http_data* h);
#endif

#if defined(SUPPORT_PROXY) || defined(SUPPORT_CGI)
/* You configure a list of regular expressions, and if a request matches
 * one of them, the request is forwarded to some other IP:port.  You can
 * run another httpd there that can handle CGI, PHP, JSP and whatnot. */
struct cgi_proxy {
  regex_t r;
  int file_executable;
  char ip[16];
  uint32 port,scope_id;
  struct sockaddr_un uds;
  struct cgi_proxy* next;
#ifdef SUPPORT_PROXY
  enum proxyprotocol proxyproto;
#endif
};
extern struct cgi_proxy* last,* cgis;
extern char** _envp;
#endif

#ifdef SUPPORT_CGI
extern int forksock[2];
#endif

extern void httpresponse(struct http_data* h,int64 s,long headerlen);
extern char* http_header(struct http_data* r,char* h);

/* returns dirfd for openat (or -2 for error) */
extern int ip_vhost(struct http_data* h);

#ifdef SUPPORT_FALLBACK_REDIR
extern const char* redir;
#endif

extern tai6464 now,next;
extern unsigned long timeout_secs;
extern const char* mimetypesfilename;
extern const char* mimetype(const char* filename,int fd);

extern int add_proxy(const char* c);
extern int handle_read_proxypost(int64 i,struct http_data* H);
extern void handle_read_httppost(int64 i,struct http_data* H);
extern int handle_write_proxypost(int64 i,struct http_data* h);
extern void handle_write_httppost(int64 i,struct http_data* h);
extern void handle_write_proxyslave(int64 i,struct http_data* h);

extern void cleanup(int64 sock);
extern size_t header_complete(struct http_data* r,int64 sock);

extern void httperror_realm(struct http_data* r,const char* title,const char* message,const char* realm,int nobody);
extern void httperror(struct http_data* r,const char* title,const char* message,int nobody);

extern int buffer_putlogstr(buffer* b,const char* s);

extern char fsbuf[8192];
extern void forkslave(int fd,buffer* in,int savedir,const char* chroot_to);

#ifdef USE_ZLIB
#include <zlib.h>
#endif

#ifdef SUPPORT_SMB
extern int smbresponse(struct http_data* h,int64 s);

extern char workgroup[20];
extern int wglen;
extern char workgroup_utf16[100];
extern int wglen16;
#endif

extern int64 origdir;

#include "version.h"
#define RELEASE "Gatling/" VERSION

extern unsigned int max_requests_per_minute;

/* call this function when a request comes in, with the peer's IP
 * address as argument */
int new_request_from_ip(const char ip[16],time_t now);
/* returns 0 if the request was added and should be serviced.
 * returns 1 if a denial of service attack from this IP was detected and
 *           the request should not be serviced
 * returns -1 if we ran out of memory trying to add the request */

#ifdef SUPPORT_HTTPS
extern int64 https_write_callback(int64 sock,const void* buf,uint64 n);
extern int handle_ssl_error_code(int sock,int code,int reading);
#endif

extern char* magicelfvalue;
extern char serverroot[];
extern char* defaultindex;

#ifdef DEBUG_EVENTS
#include "fmt.h"

static void new_io_wantwrite(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  char c[100];
#ifdef STATE_DEBUG
  struct http_data* h=io_getcookie(s);
  if (h)
    c[fmt_strm(c," [state ",state2string(h->t),"]")]=0;
  else
    strcpy(c," [cookie is NULL]");
#else
  c[0]=0;
#endif
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_wantwrite(",a,")",c,"\n");
  io_wantwrite(s);
}

static void new_io_dontwantwrite(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  char c[100];
#ifdef STATE_DEBUG
  struct http_data* h=io_getcookie(s);
  if (h)
    c[fmt_strm(c," [state ",state2string(h->t),"]")]=0;
  else
    strcpy(c," [cookie is NULL]");
#else
  c[0]=0;
#endif
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_dontwantwrite(",a,")",c,"\n");
  io_dontwantwrite(s);
}

static void new_io_wantread(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  char c[100];
#ifdef STATE_DEBUG
  struct http_data* h=io_getcookie(s);
  if (h)
    c[fmt_strm(c," [state ",state2string(h->t),"]")]=0;
  else
    strcpy(c," [cookie is NULL]");
#else
  c[0]=0;
#endif
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_wantread(",a,")",c,"\n");
  io_wantread(s);
}

static void new_io_dontwantread(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  struct http_data* h=io_getcookie(s);
  char c[100];
  c[0]=0;
#ifdef STATE_DEBUG
  if (h)
    c[fmt_strm(c," [state ",state2string(h->t),"]")]=0;
  else
    strcpy(c," [cookie is NULL]");
#endif
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_dontwantread(",a,")",c,"\n");
  io_dontwantread(s);
}

#define io_wantwrite(s) new_io_wantwrite(s,__FILE__,__LINE__)
#define io_wantread(s) new_io_wantread(s,__FILE__,__LINE__)
#define io_dontwantwrite(s) new_io_dontwantwrite(s,__FILE__,__LINE__)
#define io_dontwantread(s) new_io_dontwantread(s,__FILE__,__LINE__)
#endif

#ifndef HAVE_EAGAIN_READWRITE
#warning you are building gatling against an old version of libowfat
static inline void io_eagain_read(int64 d) { io_eagain(d); }
static inline void io_eagain_write(int64 d) { io_eagain(d); }
#endif

#endif
