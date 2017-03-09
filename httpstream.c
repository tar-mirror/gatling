#include <stddef.h>
#include "gatling.h"

#ifdef SUPPORT_PROXY

void httpstream_initstate(struct httpstreamstate* hss) {
  hss->state=HSS_HEADER;
  hss->bytesleft=0;
  hss->type=DONTKNOW;
}

int httpstream_update(struct httpstreamstate* hss,char c) {
  switch (hss->state) {

  case HSS_HEADER_CRLF:
    if (c=='\r') {
      hss->state=HSS_HEADER_CRLFCR;
      break;
    }
    goto new_header_line;
    // else fall through

  case HSS_HEADER:
    if (hss->type == DONTKNOW) {
      if (c=='H') hss->type=RESPONSE_MAYBE;
      else if (c=='P') hss->type=POSTREQUEST;
      else hss->type=REQUEST;
    }
    else if (hss->type == RESPONSE_MAYBE) {
      if (c=='T')
	hss->type=RESPONSE;	/* "HTTP/2.0 OK" */
      else
	hss->type=REQUEST;	/* "HEAD /foo HTTP/1.1" */
    }
new_header_line:
    if ((c|0x20)=='c') hss->state=HSS_HEADER_C;
    else if ((c|0x20)=='t') hss->state=HSS_HEADER_T;
    else {
shared:
      if (c=='\r') hss->state=HSS_HEADER_CR;
      else hss->state=HSS_HEADER_OTHER;
    }
    break;

  case HSS_HEADER_C:
    if ((c|0x20)=='o') { hss->state=HSS_HEADER_CO; break; }
    else goto shared;

  case HSS_HEADER_CO:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_CON; break; }
    else goto shared;

  case HSS_HEADER_CON:
    if ((c|0x20)=='t') { hss->state=HSS_HEADER_CONT; break; }
    else goto shared;

  case HSS_HEADER_CONT:
    if ((c|0x20)=='e') { hss->state=HSS_HEADER_CONTE; break; }
    else goto shared;

  case HSS_HEADER_CONTE:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_CONTEN; break; }
    else goto shared;

  case HSS_HEADER_CONTEN:
    if ((c|0x20)=='t') { hss->state=HSS_HEADER_CONTENT; break; }
    else goto shared;

  case HSS_HEADER_CONTENT:
    if (c=='-') { hss->state=HSS_HEADER_CONTENT_; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_:
    if ((c|0x20)=='l') { hss->state=HSS_HEADER_CONTENT_L; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_L:
    if ((c|0x20)=='e') { hss->state=HSS_HEADER_CONTENT_LE; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LE:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_CONTENT_LEN; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LEN:
    if ((c|0x20)=='g') { hss->state=HSS_HEADER_CONTENT_LENG; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LENG:
    if ((c|0x20)=='t') { hss->state=HSS_HEADER_CONTENT_LENGT; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LENGT:
    if ((c|0x20)=='h') { hss->state=HSS_HEADER_CONTENT_LENGTH; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LENGTH:
    if (c==':') { hss->state=HSS_HEADER_CONTENT_LENGTH_; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LENGTH_:
    if (c==' '||c=='\t') break;	// skip whitespace without changing state
    if (c>='0' && c<='9') { hss->bytesleft=c-'0'; hss->state=HSS_HEADER_CONTENT_LENGTH_NUM; break; }
    else goto shared;

  case HSS_HEADER_CONTENT_LENGTH_NUM:
//    printf("<bs=%ld, c=%c, bs=%ld>",hss->bytesleft,c,hss->bytesleft*10+c-'0');
    if (c>='0' && c<='9') { hss->bytesleft=hss->bytesleft*10+c-'0'; break; }
    else if (c!='\r') hss->bytesleft=UNKNOWN;
    goto shared;

  case HSS_HEADER_T:
    if ((c|0x20)=='r') { hss->state=HSS_HEADER_TR; break; }
    else goto shared;

  case HSS_HEADER_TR:
    if ((c|0x20)=='a') { hss->state=HSS_HEADER_TRA; break; }
    else goto shared;

  case HSS_HEADER_TRA:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_TRAN; break; }
    else goto shared;

  case HSS_HEADER_TRAN:
    if ((c|0x20)=='s') { hss->state=HSS_HEADER_TRANS; break; }
    else goto shared;

  case HSS_HEADER_TRANS:
    if ((c|0x20)=='f') { hss->state=HSS_HEADER_TRANSF; break; }
    else goto shared;

  case HSS_HEADER_TRANSF:
    if ((c|0x20)=='e') { hss->state=HSS_HEADER_TRANSFE; break; }
    else goto shared;

  case HSS_HEADER_TRANSFE:
    if ((c|0x20)=='r') { hss->state=HSS_HEADER_TRANSFER; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER:
    if (c=='-') { hss->state=HSS_HEADER_TRANSFER_; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_:
    if ((c|0x20)=='e') { hss->state=HSS_HEADER_TRANSFER_E; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_E:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_TRANSFER_EN; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_EN:
    if ((c|0x20)=='c') { hss->state=HSS_HEADER_TRANSFER_ENC; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENC:
    if ((c|0x20)=='o') { hss->state=HSS_HEADER_TRANSFER_ENCO; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCO:
    if ((c|0x20)=='d') { hss->state=HSS_HEADER_TRANSFER_ENCOD; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCOD:
    if ((c|0x20)=='i') { hss->state=HSS_HEADER_TRANSFER_ENCODI; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODI:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_TRANSFER_ENCODIN; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODIN:
    if ((c|0x20)=='g') { hss->state=HSS_HEADER_TRANSFER_ENCODING; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING:
    if (c==':') { hss->state=HSS_HEADER_TRANSFER_ENCODING_; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_:
    if (c==' ' || c=='\t') break;	/* skip whitespace */
    if ((c|0x20)=='c') { hss->state=HSS_HEADER_TRANSFER_ENCODING_C; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_C:
    if ((c|0x20)=='h') { hss->state=HSS_HEADER_TRANSFER_ENCODING_CH; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_CH:
    if ((c|0x20)=='u') { hss->state=HSS_HEADER_TRANSFER_ENCODING_CHU; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_CHU:
    if ((c|0x20)=='n') { hss->state=HSS_HEADER_TRANSFER_ENCODING_CHUN; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_CHUN:
    if ((c|0x20)=='k') { hss->state=HSS_HEADER_TRANSFER_ENCODING_CHUNK; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_CHUNK:
    if ((c|0x20)=='e') { hss->state=HSS_HEADER_TRANSFER_ENCODING_CHUNKE; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_CHUNKE:
    if ((c|0x20)=='d') { hss->state=HSS_HEADER_TRANSFER_ENCODING_CHUNKED; break; }
    else goto shared;

  case HSS_HEADER_TRANSFER_ENCODING_CHUNKED:
    hss->state=HSS_HEADER_OTHER;
    if (c==' ' || c=='\t' || c==';' || c=='\r' || c=='\n')
      hss->bytesleft=CHUNKED;
    goto shared;

  case HSS_HEADER_OTHER:
    goto shared;

  case HSS_HEADER_CR:
    if (c=='\n') { hss->state=HSS_HEADER_CRLF; break; }
    else goto shared;

  case HSS_HEADER_CRLFCR:
    if (c=='\n') {
      // end of header found.
      if (hss->type==REQUEST) {
	// if it's a GET request, ignore content-length and chunked
	// encoding.
	hss->bytesleft=0;
	hss->state=HSS_DONE;
	return 1;
      }
      // Now we either have found a content-length or the chunked
      // encoding marker or neither.
      if (hss->bytesleft==CHUNKED) {
	// chunked encoding; read chunked header next.
	hss->state=HSS_HEADER_CHUNKED_CRLF;
      } else if (hss->bytesleft==UNKNOWN || hss->bytesleft==0) {
	// neither chunked encoding nor content length
	// only way to end the stream is to drop the connection
	hss->state=HSS_INFINITE;
      } else {
	// found positive content length
	hss->state=HSS_KNOWLENGTH;
      }
      break;
    }
    else goto shared;

  case HSS_KNOWLENGTH:
    if (--hss->bytesleft==0) {
      hss->state=HSS_DONE;
      return 1;
    }
    break;

  case HSS_HEADER_CHUNKED:
    if (c=='\r')
      hss->state=HSS_HEADER_CHUNKED_CR;
    break;

  case HSS_HEADER_CHUNKED_CR:
    if (c=='\n')
      hss->state=HSS_HEADER_CHUNKED_CRLF;
    break;

  case HSS_HEADER_CHUNKED_CRLF:
    hss->bytesleft=0;
    // fall through
  case HSS_HEADER_CHUNKED_CRLF_NUM:
    if (c>='0' && c<='9')
      hss->bytesleft=hss->bytesleft*10+c-'0';
    else if (c>='a' && c<='f')
      hss->bytesleft=hss->bytesleft*10+c-'a'+10;
    else if (c>='A' && c<='F')
      hss->bytesleft=hss->bytesleft*10+c-'A'+10;
    else if (c=='\r' && hss->state==HSS_HEADER_CHUNKED_CRLF_NUM) {
      hss->state=HSS_HEADER_CHUNKED_CRLF_NUM_CR;
      break;
    }
//    printf("[bl=%d]",hss->bytesleft);
    hss->state=HSS_HEADER_CHUNKED_CRLF_NUM;
    break;

  case HSS_HEADER_CHUNKED_CRLF_NUM_CR:
    if (c=='\n') {
      if (hss->bytesleft==0) {
	hss->state=HSS_DONE;
	return 1;
      }
      hss->state=HSS_KNOWLENGTH_CHUNKED;
    }
    break;

  case HSS_KNOWLENGTH_CHUNKED:
    if (--hss->bytesleft==0)
      /* chunk is done; read next one */
      hss->state=HSS_HEADER_CHUNKED;
    break;

  case HSS_INFINITE:
    break;

  case HSS_DONE:
    return 1;
  }
  return 0;
}

size_t httpstream(struct httpstreamstate* hss,
		  const char* buf, size_t len) {
  // buf is part of a http request or reply
  // this is meant to be called from a proxy loop that keeps reading
  // data from a socket and writing it to another socket.  For each
  // chunk of data that is coming in, the code calls this function on
  // each chunk.  This function then parses the chunk and says how many
  // bytes in it belong to the http stream.  Basically, it will return
  // len until the stream is finished (request + POST data received or
  // reply + content data received).

  size_t i;
  if (hss->state==HSS_DONE)
    return 0;
  for (i=0; i<len; ++i)
    if (httpstream_update(hss,buf[i]))
      return i+1;
  return len;
}

#if NEED_MAIN
#include <stdio.h>

int main() {
  struct httpstreamstate hss;
//  char buf[]="POST / HTTP/1.0\r\nHost: localhost:80\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfnord\r\n0\r\nhalali";
  char buf[10000];
  size_t i,l;
  FILE* f;
  f=fopen("/tmp/a/blubber","r");
  l=fread(buf,1,sizeof(buf),f);
  httpstream_initstate(&hss);

  for (i=0; i<l; ++i) {
    printf("%c",buf[i]);
    if (httpstream_update(&hss,buf[i]))
      break;
    printf("[%d,bl=%ld]",hss.state,hss.bytesleft);
  }

  httpstream_initstate(&hss);
  printf("%zu\n",httpstream(&hss,buf,l));

  return 0;
}
#endif

#endif
