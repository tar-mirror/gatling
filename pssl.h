
  struct ssl_data {
    mbedtls_pk_context key;
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt crt;
    mbedtls_dhm_context dhm;
    mbedtls_net_context fd;
    struct {
      mbedtls_x509_crt crt;
      mbedtls_pk_context key;
    }* snidata;
  };

extern int init_serverside_tls(struct ssl_data* d,int sock);
extern void free_tls_ctx(struct ssl_data* d);
extern void free_tls_memory(void);
