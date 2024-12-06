#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <time.h>

static char *ngx_http_hmac_protection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_hmac_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_hmac_commands[] = {
    {
        ngx_string("hmac_protection"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_hmac_protection,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_hmac_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_hmac_module = {
    NGX_MODULE_V1,
    &ngx_http_hmac_module_ctx,     /* module context */
    ngx_http_hmac_commands,        /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_http_hmac_protection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hmac_handler;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_hmac_handler(ngx_http_request_t *r) {
    u_char *token, *exp_str, *acl, *ip;
    time_t current_time, exp;
    const char *secret = "your_secret_key";
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    // Get the HMAC token, expiration, ACL, and client IP from the request (e.g., from headers or query string)
    token = (u_char *)ngx_http_get_variable(r, (ngx_str_t *)"arg_hmac", NULL);
    exp_str = (u_char *)ngx_http_get_variable(r, (ngx_str_t *)"arg_exp", NULL);
    acl = (u_char *)ngx_http_get_variable(r, (ngx_str_t *)"arg_acl", NULL);
    ip = (u_char *)ngx_http_get_variable(r, (ngx_str_t *)"remote_addr", NULL);

    if (token == NULL || exp_str == NULL || acl == NULL) {
        return NGX_HTTP_FORBIDDEN;
    }

    // Convert expiration to time_t and check if expired
    exp = ngx_atoi(exp_str, ngx_strlen(exp_str));
    current_time = time(NULL);

    if (exp == NGX_ERROR || current_time > exp) {
        return NGX_HTTP_FORBIDDEN;
    }

    // Create HMAC using the ACL, expiration, and optional IP address
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, secret, ngx_strlen(secret), EVP_sha256(), NULL);
    HMAC_Update(hmac_ctx, acl, ngx_strlen(acl));
    HMAC_Update(hmac_ctx, exp_str, ngx_strlen(exp_str));
    if (ip != NULL) {
        HMAC_Update(hmac_ctx, ip, ngx_strlen(ip));
    }
    HMAC_Final(hmac_ctx, result, &result_len);
    HMAC_CTX_free(hmac_ctx);

    // Base64 encode the result and compare to the provided token
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, result, result_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    u_char *computed_token = ngx_pnalloc(r->pool, bptr->length);
    ngx_memcpy(computed_token, bptr->data, bptr->length);
    BIO_free_all(b64);

    if (ngx_strncmp(token, computed_token, ngx_strlen(token)) != 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED; // Allow the request to proceed
}
