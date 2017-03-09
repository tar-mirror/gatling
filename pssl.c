#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <fcntl.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/net.h>
#include <mbedtls/dhm.h>
#include "mmap.h"
#include <ctype.h>
#include "pssl.h"
#include <fmt.h>

static int library_inited;

const char* ssl_server_cert="server.pem";
const char* ssl_client_crl="clientcrl.pem";
const char* ssl_client_ca="clientca.pem";
const char* ssl_ciphers="DEFAULT";
const char* ssl_client_cert="clientcert.pem";
const char* ssl_dhparams="dhparams.pem";

const unsigned char ssl_default_dhparams[]="-----BEGIN DH PARAMETERS-----\n"
"MIIBCAKCAQEAhS4NySChob9OZmB7WOUbOIxurRRbItWnKmC2fq1pJHRft/r72/qq\n"
"g8qquhYAmikXgX4+uZEgfLBWPlx1d8wHggnKtEJ+0KzlGpxek7QORwN2j9872jXC\n"
"25iZar+Om4hUXREuVyGU02GmGHgfemVT1mOvZMbBxzTfmaUdP9Q304oKz4RUYV1w\n"
"+Jv3iO6MYySz6bhsc7lSyayUIJxXJoaqgz6EJVImU6LwXo8gUbD5GUVXhEzDHuRG\n"
"fbKleVvLf1MC7TT6H5PAFFOkfFET//C9QJkSmUsg3u5GtwvKNZhwrggqNzchXSkS\n"
"FDQXPlpTK7h3BlR8vDadEpT68OcdLr2+owIBAg==\n"
"-----END DH PARAMETERS-----\n";

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_cache_context cache;

int ciphersuites[] =
{
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
  MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
  MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
  MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
  MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
  MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
  MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
//  TLS_RSA_WITH_RC4_128_SHA,
//  TLS_RSA_WITH_RC4_128_MD5,
  0
};

static int parse_cert( const char* filename, mbedtls_x509_crt* srvcert, mbedtls_pk_context* key ) {
  mbedtls_x509_crt_init(srvcert);
  mbedtls_pk_init(key);

  if (mbedtls_x509_crt_parse_file(srvcert,filename) ||
      mbedtls_pk_parse_keyfile(key,filename,NULL))
    return -1;
  return 0;
}

static char makevaliddns(char c) {
  if (c>='A' && c<='Z') return c-'A'+'a';
  if (isalnum(c)) return c;
  switch (c) {
  case '.':
  case '-':
  case '_':
    return c;
  }
  return -1;
}

static int sni_callback( void* p_info, mbedtls_ssl_context* ssl, const unsigned char* name, size_t namelen) {
  char fn[136];
  unsigned int i;
  int r=-1;
  struct ssl_data* sd=(struct ssl_data*)p_info;
  sd->snidata=malloc(sizeof(*sd->snidata));
  if (!sd->snidata) return -1;
  if (namelen<1 || namelen>128 || name[0]=='.' || name[0]=='-')
    return -1;
  for (i=0; i<namelen; ++i) {
    char c;
    if ((c = makevaliddns(name[i])) == -1)
      return -1;
    fn[i]=c;
    if (c=='-' && (i+1 >= namelen || name[i+1]=='.'))
      return -1;
  }
  if (fn[i-1]=='-')
    return -1;
  strcpy(fn+i,".pem");
  if (parse_cert(fn, &sd->snidata->crt, &sd->snidata->key))
    return 0;	/* if we failed to parse the certificate, then we fall back on the build-in one */
  r=mbedtls_ssl_conf_own_cert( &sd->conf, &sd->snidata->crt, &sd->snidata->key);
  return r;
}

static void my_debug( void* ctx, int level, const char* file, int line, const char* str) {
  char buf[10];
  struct iovec v[] = { { (char*)file, strlen(file) }, { ":",1 }, { buf,strlen(buf) }, {": ",2}, { (char*)str,strlen(str) } };
  buf[fmt_ulong(buf,line)]=0;
  writev(1,v,sizeof(v)/sizeof(v[0]));
}

int init_serverside_tls(struct ssl_data* d,int sock) {
  if (!library_inited) {
    library_inited=1;
    if (access("/dev/urandom",R_OK))
      return -1;
    mbedtls_ssl_cache_init(&cache);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*) "gatling", strlen("gatling")))
      return -1;
  }

  memset(d,0,sizeof(*d));
  if (parse_cert(ssl_server_cert, &d->crt, &d->key))
    return -1;

  mbedtls_ssl_init(&d->ssl);
  mbedtls_net_init(&d->fd);
  d->fd.fd=sock;
  mbedtls_ssl_config_init(&d->conf);
  if (mbedtls_ssl_config_defaults(&d->conf,MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT))
    return -1;

  mbedtls_ssl_conf_authmode( &d->conf, MBEDTLS_SSL_VERIFY_NONE );
  mbedtls_ssl_conf_rng( &d->conf, mbedtls_ctr_drbg_random, &ctr_drbg );
  mbedtls_ssl_conf_dbg( &d->conf, my_debug, NULL);
  mbedtls_ssl_conf_session_cache( &d->conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
  mbedtls_ssl_conf_ca_chain( &d->conf, d->crt.next, NULL);
  mbedtls_ssl_conf_own_cert( &d->conf, &d->crt, &d->key );
  mbedtls_ssl_conf_sni( &d->conf, sni_callback, d );

//  ssl_set_ciphersuites( ssl, ciphersuites );
  mbedtls_ssl_set_bio( &d->ssl, &d->fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  if (mbedtls_dhm_parse_dhmfile(&d->dhm, ssl_dhparams) && mbedtls_dhm_parse_dhmfile(&d->dhm, ssl_server_cert))
    mbedtls_dhm_parse_dhm(&d->dhm, ssl_default_dhparams, sizeof(ssl_default_dhparams)-1);
  mbedtls_ssl_conf_dh_param_ctx(&d->conf, &d->dhm);
//  debug_set_threshold(65535);

  mbedtls_ssl_conf_min_version(&d->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);	/* demand at least TLS 1.0 */
//  ssl_set_dh_param( ssl, "CD95C1B9959B0A135B9D306D53A87518E8ED3EA8CBE6E3A338D9DD3167889FC809FE1AD59B38C98D1A8FCE47E46DF5FB56B8EA3B03B2132C249A99209F62A1AD63511BD08A60655B0463B6F1BB79BEC9D17C71BD269C6B50CF0EDDAAB83290B4C697A7F641FBD21EE0E7B57C698AFEED8DA3AB800525E6887215A61CA62DC437", "04" );

  if (mbedtls_ssl_setup(&d->ssl,&d->conf))
    return -1;

  mbedtls_ssl_session_reset( &d->ssl );
  return 0;
}

void free_tls_ctx(struct ssl_data* d) {
  mbedtls_ssl_free(&d->ssl);
  mbedtls_dhm_free(&d->dhm);
  mbedtls_x509_crt_free(&d->crt);
  mbedtls_ssl_config_free(&d->conf);
  mbedtls_pk_free(&d->key);
  if (d->snidata) {
    mbedtls_x509_crt_free(&d->snidata->crt);
    mbedtls_pk_free(&d->snidata->key);
    free(d->snidata);
  }
}

void free_tls_memory(void) {
  mbedtls_ssl_cache_free( &cache );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
}
