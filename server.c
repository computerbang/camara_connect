// server_tls_persist.c
// TLS TCP 서버 (지속 연결):
//   [2B name_len][name][8B file_size][file_data] ... 반복
//   종료 신호: name_len == 0  (클라가 종료 요청)
// build: gcc -Wall -Wextra -O2 -o server_tls_persist server_tls_persist.c -lssl -lcrypto
// run  : ./server_tls_persist 7000 /var/cctv/records client01

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define DEFAULT_RECORD_DIR "/var/cctv/records"
#define DEFAULT_CLIENT_ID  "client01"
#define DEFAULT_UDP_PORT   5000

static SSL_CTX *g_ssl_ctx = NULL;
static int g_listen_fd = -1;
static int g_running = 1;
static pid_t g_ffplay_pid = -1;

static uint64_t ntohll_custom(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low  = (uint32_t)(val & 0xFFFFFFFFULL);
    return ((uint64_t)ntohl(low) << 32) | ntohl(high);
#else
    return val;
#endif
}

static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "[SERVER] Path exists but is not dir: %s\n", dir);
            return -1;
        }
        return 0;
    }
    if (mkdir(dir, 0755) < 0) {
        perror("[SERVER] mkdir record dir");
        return -1;
    }
    return 0;
}

static void tls_server_init(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        fprintf(stderr, "[TLS] SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(g_ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] load server.crt failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] load server.key failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        fprintf(stderr, "[TLS] private key mismatch\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    printf("[TLS] TLS context initialized.\n");
}

static void tls_server_cleanup(void) {
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
}

static int tls_read_all(SSL *ssl, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    while (total < len) {
        int n = SSL_read(ssl, p + total, (int)(len - total));
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;

        if (err == SSL_ERROR_ZERO_RETURN) return -2; // close_notify
        fprintf(stderr, "[TLS] SSL_read(header) failed: n=%d err=%d errno=%d\n", n, err, errno);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

static int start_ffplay(int udp_port) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        char url[64];
        snprintf(url, sizeof(url), "udp://@:%d", udp_port);
        execlp("ffplay", "ffplay",
               "-fflags", "nobuffer",
               "-flags", "low_delay",
               "-framedrop",
               url,
               (char *)NULL);
        _exit(1);
    }
    g_ffplay_pid = pid;
    return 0;
}

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_listen_fd >= 0) close(g_listen_fd);
    g_listen_fd = -1;

    if (g_ffplay_pid > 0) {
        kill(g_ffplay_pid, SIGTERM);
        waitpid(g_ffplay_pid, NULL, 0);
        g_ffplay_pid = -1;
    }
}

// 간단한 파일명 검증(경로 탈출 방지)
static int is_safe_filename(const char *name) {
    if (!name || !*name) return 0;
    if (strstr(name, "..")) return 0;
    if (strchr(name, '/')) return 0;
    if (strchr(name, '\\')) return 0;
    return 1;
}

// return:
//   1  : 파일 1개 수신 성공
//   0  : 정상 종료(클라가 name_len=0 보냄 or close_notify)
//  -1  : 에러
static int recv_one_file_or_close(SSL *ssl, const char *record_dir, const char *client_id) {
    uint16_t name_len_net = 0;
    uint64_t file_size_net = 0;

    int rc = tls_read_all(ssl, &name_len_net, sizeof(name_len_net));
    if (rc == -2) return 0;      // close_notify
    if (rc != 0) return -1;

    uint16_t name_len = ntohs(name_len_net);
    if (name_len == 0) {
        // 클라이언트가 “더 이상 파일 없음/종료” 신호
        return 0;
    }
    if (name_len > 1000) {
        fprintf(stderr, "[SERVER] invalid name_len=%u\n", name_len);
        return -1;
    }

    char filename[1024];
    memset(filename, 0, sizeof(filename));
    rc = tls_read_all(ssl, filename, name_len);
    if (rc == -2) return 0;
    if (rc != 0) return -1;
    filename[name_len] = '\0';

    if (!is_safe_filename(filename)) {
        fprintf(stderr, "[SERVER] unsafe filename: '%s'\n", filename);
        return -1;
    }

    rc = tls_read_all(ssl, &file_size_net, sizeof(file_size_net));
    if (rc == -2) return 0;
    if (rc != 0) return -1;

    uint64_t file_size = ntohll_custom(file_size_net);
    printf("[SERVER] Incoming file: name='%s', size=%llu\n",
           filename, (unsigned long long)file_size);

    char final_name[1400];
    snprintf(final_name, sizeof(final_name), "%s_%s", client_id, filename);

    char final_path[1800];
    snprintf(final_path, sizeof(final_path), "%s/%s", record_dir, final_name);

    char part_path[1900];
    snprintf(part_path, sizeof(part_path), "%s.part", final_path);

    int out_fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("[SERVER] open .part");
        return -1;
    }

    const size_t BUF_SIZE = 16 * 1024;
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) {
        close(out_fd);
        return -1;
    }

    uint64_t received = 0;
    while (received < file_size) {
        size_t need = (size_t)((file_size - received) > BUF_SIZE ? BUF_SIZE : (file_size - received));
        int n = SSL_read(ssl, buf, (int)need);

        if (n > 0) {
            ssize_t w = write(out_fd, buf, (size_t)n);
            if (w != n) {
                perror("[SERVER] write");
                free(buf);
                close(out_fd);
                unlink(part_path);
                return -1;
            }
            received += (uint64_t)n;
            continue;
        }

        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;

        if (err == SSL_ERROR_ZERO_RETURN) break; // close_notify

        fprintf(stderr, "[SERVER] SSL_read(data) failed: n=%d err=%d errno=%d\n", n, err, errno);
        ERR_print_errors_fp(stderr);
        free(buf);
        close(out_fd);
        unlink(part_path);
        return -1;
    }

    free(buf);
    close(out_fd);

    if (received != file_size) {
        fprintf(stderr, "[SERVER] size mismatch: expected=%llu received=%llu (delete .part)\n",
                (unsigned long long)file_size, (unsigned long long)received);
        unlink(part_path);
        return -1;
    }

    if (rename(part_path, final_path) < 0) {
        perror("[SERVER] rename");
        unlink(part_path);
        return -1;
    }

    printf("[SERVER] File saved: %s (%llu bytes)\n",
           final_path, (unsigned long long)received);
    return 1;
}

static void handle_persistent_client(int cfd, const char *record_dir, const char *client_id) {
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) { close(cfd); return; }
    SSL_set_fd(ssl, cfd);

    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "[TLS] SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    printf("[TLS] Handshake OK.\n");

    while (g_running) {
        int r = recv_one_file_or_close(ssl, record_dir, client_id);
        if (r == 1) continue;     // 다음 파일 계속
        if (r == 0) break;        // 정상 종료(종료 신호 or close_notify)
        // r == -1
        break;
    }

    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
    printf("[SERVER] Connection closed.\n");
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <TCP_PORT> [RECORD_DIR] [CLIENT_ID]\n", argv[0]);
        return 1;
    }

    uint16_t port = (uint16_t)atoi(argv[1]);
    const char *record_dir = (argc >= 3) ? argv[2] : DEFAULT_RECORD_DIR;
    const char *client_id  = (argc >= 4) ? argv[3] : DEFAULT_CLIENT_ID;

    if (ensure_dir(record_dir) != 0) return 1;
    tls_server_init();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    (void)start_ffplay(DEFAULT_UDP_PORT);

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(g_listen_fd, 16) < 0) {
        perror("listen");
        return 1;
    }

    printf("[SERVER] Listening on 0.0.0.0:%u (TLS persistent)\n", port);
    printf("[SERVER] Record dir: %s\n", record_dir);
    printf("[SERVER] Client prefix: %s\n", client_id);

    while (g_running) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        printf("[SERVER] New connection from %s:%u\n", ip, ntohs(cli.sin_port));

        handle_persistent_client(cfd, record_dir, client_id);
    }

    if (g_listen_fd >= 0) close(g_listen_fd);
    tls_server_cleanup();
    return 0;
}
