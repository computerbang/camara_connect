#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
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

/*
  ==========================
  목표(행님 조건) 구현 요약
  ==========================
  1) TLS 업로드 서버 (OpenSSL)
  2) 스레드풀 + 작업큐로 멀티 클라이언트 동시 처리
  3) source_id 기반 저장 경로 분리: <record_root>/<source_id>/
  4) UDP 모니터링: ffplay를 여러 개 띄울 수 있게 (3개 화면 가능)
  5) DJI RTMP: ffmpeg 프로세스를 띄워서 (저장 + UDP 재송출) 동시 수행
*/

#define DEFAULT_TCP_PORT     7000
#define DEFAULT_RECORD_ROOT  "/var/cctv/records"
#define DEFAULT_WORKERS      4
#define QUEUE_CAPACITY       64

// DJI RTMP 기본값(필요시 config/argv로 수정)
#define DEFAULT_DJI_SOURCE_ID "dji01"
#define DEFAULT_DJI_RTMP_IN   "rtmp://127.0.0.1/live/dji01"
#define DEFAULT_DJI_UDP_OUT_PORT 5002

// 모니터링 UDP 기본 예시(Edge1=5000, Edge2=5001, DJI=5002)
#define DEFAULT_UDP1 5000
#define DEFAULT_UDP2 5001
#define DEFAULT_UDP3 5002

static volatile sig_atomic_t g_running = 1;
static int g_listen_fd = -1;

static SSL_CTX *g_ssl_ctx = NULL;

/* ========= 유틸: 64-bit ntoh ========= */
static uint64_t ntohll_custom(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low  = (uint32_t)(val & 0xFFFFFFFFULL);
    return ((uint64_t)ntohl(low) << 32) | ntohl(high);
#else
    return val;
#endif
}

/* ========= 디렉터리 보장 ========= */
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
        perror("[SERVER] mkdir");
        return -1;
    }
    return 0;
}

/* record_root/source_id 까지 보장 */
static int ensure_source_dir(const char *record_root, const char *source_id) {
    if (ensure_dir(record_root) != 0) return -1;

    char p[2048];
    snprintf(p, sizeof(p), "%s/%s", record_root, source_id);
    return ensure_dir(p);
}

/* ========= 파일명 안전 검사(경로 탈출 방지) ========= */
static int is_safe_filename(const char *name) {
    if (!name || !*name) return 0;
    if (strstr(name, "..")) return 0;
    if (strchr(name, '/')) return 0;
    if (strchr(name, '\\')) return 0;
    return 1;
}

/* ========= TLS init/cleanup ========= */
static void tls_server_init_or_die(const char *crt, const char *key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) {
        fprintf(stderr, "[TLS] SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(g_ssl_ctx, crt, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] load cert failed: %s\n", crt);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[TLS] load key failed: %s\n", key);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(g_ssl_ctx)) {
        fprintf(stderr, "[TLS] private key mismatch\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("[TLS] TLS context ready (cert=%s key=%s)\n", crt, key);
}

static void tls_server_cleanup(void) {
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
}

/* ========= TLS read_all ========= */
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

        fprintf(stderr, "[TLS] SSL_read failed: n=%d err=%d errno=%d\n", n, err, errno);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

/* ========= 시그널 핸들러(실무식으로 최소만) ========= */
static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    // accept를 깨우기 위해 listen fd 닫기(완벽한 async-signal-safe는 아니지만 과제/프로젝트에서 흔히 씀)
    if (g_listen_fd >= 0) close(g_listen_fd);
    g_listen_fd = -1;
}

/* ========= 작업 큐(스레드풀용) ========= */
typedef struct {
    int cfd;
    struct sockaddr_in peer;
} task_t;

typedef struct {
    task_t items[QUEUE_CAPACITY];
    int head, tail, count;
    pthread_mutex_t mu;
    pthread_cond_t  cv_not_empty;
    pthread_cond_t  cv_not_full;
} task_queue_t;

static void tq_init(task_queue_t *q) {
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->cv_not_empty, NULL);
    pthread_cond_init(&q->cv_not_full, NULL);
}

static void tq_destroy(task_queue_t *q) {
    pthread_mutex_destroy(&q->mu);
    pthread_cond_destroy(&q->cv_not_empty);
    pthread_cond_destroy(&q->cv_not_full);
}

static int tq_push(task_queue_t *q, task_t t) {
    pthread_mutex_lock(&q->mu);
    while (q->count == QUEUE_CAPACITY && g_running) {
        pthread_cond_wait(&q->cv_not_full, &q->mu);
    }
    if (!g_running) {
        pthread_mutex_unlock(&q->mu);
        return -1;
    }
    q->items[q->tail] = t;
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->cv_not_empty);
    pthread_mutex_unlock(&q->mu);
    return 0;
}

static int tq_pop(task_queue_t *q, task_t *out) {
    pthread_mutex_lock(&q->mu);
    while (q->count == 0 && g_running) {
        pthread_cond_wait(&q->cv_not_empty, &q->mu);
    }
    if (q->count == 0 && !g_running) {
        pthread_mutex_unlock(&q->mu);
        return -1;
    }
    *out = q->items[q->head];
    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count--;
    pthread_cond_signal(&q->cv_not_full);
    pthread_mutex_unlock(&q->mu);
    return 0;
}

/* ========= 멀티 모니터링: ffplay 프로세스 관리 ========= */
typedef struct {
    pid_t pid;
    int udp_port;
} ffplay_proc_t;

static int spawn_ffplay(int udp_port, const char *title_hint) {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        // 자식: ffplay 실행. 로그는 /dev/null로 버림.
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        char url[64];
        snprintf(url, sizeof(url), "udp://@:%d", udp_port);

        // title_hint는 환경 따라 무시될 수 있어서 단순히 인자로만 둠(필요하면 -window_title 활용)
        (void)title_hint;

        execlp("ffplay", "ffplay",
               "-fflags", "nobuffer",
               "-flags", "low_delay",
               "-framedrop",
               url,
               (char *)NULL);
        _exit(1);
    }

    printf("[MON] ffplay PID=%d listening udp://@:%d\n", pid, udp_port);
    return (int)pid;
}

/* ========= DJI RTMP: ffmpeg 프로세스(저장 + UDP 재송출) ========= */
static pid_t spawn_dji_ffmpeg(const char *rtmp_in, const char *record_root, const char *source_id, int udp_out_port) {
    // 저장 디렉터리 확보
    if (ensure_source_dir(record_root, source_id) != 0) {
        fprintf(stderr, "[DJI] ensure_source_dir failed\n");
        return -1;
    }

    char out_dir[2048];
    snprintf(out_dir, sizeof(out_dir), "%s/%s", record_root, source_id);

    // ffmpeg tee 출력:
    // 1) udp mpegts -> ffplay
    // 2) segment mp4 저장(10분)
    char tee_arg[4096];
    snprintf(tee_arg, sizeof(tee_arg),
             "[f=mpegts]udp://127.0.0.1:%d|"
             "[f=segment:segment_time=600:reset_timestamps=1:strftime=1]%s/%s_%%Y%%m%%d_%%H%%M%%S.mp4",
             udp_out_port, out_dir, source_id);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        // 기본은 -c copy (재인코딩 없이 컨테이너만)
        // 만약 DJI 스트림이 copy로 문제 나면 -c:v libx264 같은 재인코딩으로 바꿔야 함.
        execlp("ffmpeg", "ffmpeg",
               "-i", rtmp_in,
               "-c", "copy",
               "-f", "tee",
               tee_arg,
               (char *)NULL);
        _exit(1);
    }

    printf("[DJI] ffmpeg PID=%d (in=%s, udp_out=%d, dir=%s/%s)\n",
           pid, rtmp_in, udp_out_port, record_root, source_id);
    return pid;
}

/*
  ========= 업로드 프로토콜(TLS) =========

  [1] source_id_len : uint16 (network order)
  [2] source_id     : source_id_len bytes (예: "client01")
  그 다음부터는 "파일 반복" 구조:
  [3] name_len      : uint16 (network order)  (0이면 종료)
  [4] filename      : name_len bytes
  [5] file_size     : uint64 (network order)
  [6] file_data     : file_size bytes
  ... (다음 파일 반복)

  => 서버는 record_root/source_id/ 로 저장한다.
*/

static int recv_one_file_or_close(SSL *ssl, const char *record_root, const char *source_id) {
    uint16_t name_len_net = 0;
    uint64_t file_size_net = 0;

    int rc = tls_read_all(ssl, &name_len_net, sizeof(name_len_net));
    if (rc == -2) return 0; // close_notify
    if (rc != 0) return -1;

    uint16_t name_len = ntohs(name_len_net);
    if (name_len == 0) return 0; // 종료 시그널
    if (name_len > 1000) {
        fprintf(stderr, "[UPLOAD] invalid name_len=%u\n", name_len);
        return -1;
    }

    char filename[1024];
    memset(filename, 0, sizeof(filename));
    rc = tls_read_all(ssl, filename, name_len);
    if (rc == -2) return 0;
    if (rc != 0) return -1;
    filename[name_len] = '\0';

    if (!is_safe_filename(filename)) {
        fprintf(stderr, "[UPLOAD] unsafe filename: '%s'\n", filename);
        return -1;
    }

    rc = tls_read_all(ssl, &file_size_net, sizeof(file_size_net));
    if (rc == -2) return 0;
    if (rc != 0) return -1;
    uint64_t file_size = ntohll_custom(file_size_net);

    // source dir 확보
    if (ensure_source_dir(record_root, source_id) != 0) {
        fprintf(stderr, "[UPLOAD] ensure_source_dir failed for %s\n", source_id);
        return -1;
    }

    char dir[2048];
    snprintf(dir, sizeof(dir), "%s/%s", record_root, source_id);

    // 최종 파일명은 "원본 filename" 유지(원하면 여기서 timestamp/nonce 붙이는 식으로 확장 가능)
    char final_path[4096];
    snprintf(final_path, sizeof(final_path), "%s/%s", dir, filename);

    // .part로 안전 저장
    char part_path[4096];
    snprintf(part_path, sizeof(part_path), "%s.part", final_path);

    int out_fd = open(part_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("[UPLOAD] open .part");
        return -1;
    }

    const size_t BUF_SIZE = 64 * 1024; // 64KB 권장(성능)
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) {
        close(out_fd);
        unlink(part_path);
        return -1;
    }

    uint64_t received = 0;
    while (received < file_size) {
        size_t need = (size_t)((file_size - received) > BUF_SIZE ? BUF_SIZE : (file_size - received));
        int n = SSL_read(ssl, buf, (int)need);

        if (n > 0) {
            ssize_t w = write(out_fd, buf, (size_t)n);
            if (w != n) {
                perror("[UPLOAD] write");
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

        fprintf(stderr, "[UPLOAD] SSL_read(data) failed: n=%d err=%d errno=%d\n", n, err, errno);
        ERR_print_errors_fp(stderr);
        free(buf);
        close(out_fd);
        unlink(part_path);
        return -1;
    }

    free(buf);
    close(out_fd);

    if (received != file_size) {
        fprintf(stderr, "[UPLOAD] size mismatch: expected=%llu received=%llu (delete .part)\n",
                (unsigned long long)file_size, (unsigned long long)received);
        unlink(part_path);
        return -1;
    }

    if (rename(part_path, final_path) < 0) {
        perror("[UPLOAD] rename");
        unlink(part_path);
        return -1;
    }

    printf("[UPLOAD] saved: %s (%llu bytes)\n",
           final_path, (unsigned long long)received);
    return 1;
}

static int recv_source_id(SSL *ssl, char *out_source, size_t out_cap) {
    uint16_t sid_len_net = 0;
    int rc = tls_read_all(ssl, &sid_len_net, sizeof(sid_len_net));
    if (rc == -2) return 0;
    if (rc != 0) return -1;

    uint16_t sid_len = ntohs(sid_len_net);
    if (sid_len == 0 || sid_len >= out_cap) {
        fprintf(stderr, "[UPLOAD] invalid source_id_len=%u\n", sid_len);
        return -1;
    }

    rc = tls_read_all(ssl, out_source, sid_len);
    if (rc == -2) return 0;
    if (rc != 0) return -1;
    out_source[sid_len] = '\0';

    // source_id도 안전하게(경로용이므로 / .. 같은 거 금지)
    if (!is_safe_filename(out_source)) {
        fprintf(stderr, "[UPLOAD] unsafe source_id: '%s'\n", out_source);
        return -1;
    }
    return 1;
}

/* ========= worker: TLS handshake + persistent 업로드 처리 ========= */
typedef struct {
    task_queue_t *q;
    const char *record_root;
} worker_arg_t;

static void handle_one_client_tls(int cfd, const char *record_root) {
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        close(cfd);
        return;
    }
    SSL_set_fd(ssl, cfd);

    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "[TLS] SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(cfd);
        return;
    }

    // 첫 메시지: source_id 수신
    char source_id[128];
    int s = recv_source_id(ssl, source_id, sizeof(source_id));
    if (s <= 0) {
        fprintf(stderr, "[TLS] failed to recv source_id\n");
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    printf("[TLS] Handshake OK. source_id=%s\n", source_id);

    // 파일 반복 수신
    while (g_running) {
        int r = recv_one_file_or_close(ssl, record_root, source_id);
        if (r == 1) continue; // 다음 파일
        break;                // 0(정상 종료) or -1(에러)
    }

    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
}

static void *worker_main(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    task_t t;

    while (g_running) {
        if (tq_pop(wa->q, &t) != 0) break;

        // peer 로그
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &t.peer.sin_addr, ip, sizeof(ip));
        printf("[SERVER] worker handling %s:%u (fd=%d)\n", ip, ntohs(t.peer.sin_port), t.cfd);

        handle_one_client_tls(t.cfd, wa->record_root);
        printf("[SERVER] worker done (fd closed)\n");
    }
    return NULL;
}

/* ========= main ========= */
int main(int argc, char *argv[]) {
    // SIGPIPE 무시: 상대가 끊겼을 때 프로세스 전체가 죽는 걸 방지
    signal(SIGPIPE, SIG_IGN);

    // 기본 설정(필요하면 argv로 바꿔도 됨)
    uint16_t tcp_port = DEFAULT_TCP_PORT;
    const char *record_root = DEFAULT_RECORD_ROOT;
    int workers = DEFAULT_WORKERS;

    const char *cert = "server.crt";
    const char *key  = "server.key";

    // 매우 간단한 인자 처리:
    // Usage: ./server [tcp_port] [record_root] [workers]
    if (argc >= 2) tcp_port = (uint16_t)atoi(argv[1]);
    if (argc >= 3) record_root = argv[2];
    if (argc >= 4) workers = atoi(argv[3]);
    if (workers <= 0) workers = DEFAULT_WORKERS;

    // record_root 보장 + TLS 초기화
    if (ensure_dir(record_root) != 0) return 1;
    tls_server_init_or_die(cert, key);

    // 시그널 등록
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // ======= (A) DJI RTMP 파이프라인 시작 (ffmpeg) =======
    // 실제 DJI가 푸시하는 RTMP 주소로 바꾸면 됨.
    pid_t dji_ffmpeg_pid = spawn_dji_ffmpeg(DEFAULT_DJI_RTMP_IN, record_root, DEFAULT_DJI_SOURCE_ID, DEFAULT_DJI_UDP_OUT_PORT);

    // ======= (B) 모니터링 화면 3개(ffplay 3개) =======
    int ff1 = spawn_ffplay(DEFAULT_UDP1, "edge1");
    int ff2 = spawn_ffplay(DEFAULT_UDP2, "edge2");
    int ff3 = spawn_ffplay(DEFAULT_UDP3, "dji");

    (void)ff1; (void)ff2; (void)ff3;

    // ======= (C) 업로드 서버: 스레드풀 + 큐 =======
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(tcp_port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_listen_fd);
        return 1;
    }
    if (listen(g_listen_fd, 64) < 0) {
        perror("listen");
        close(g_listen_fd);
        return 1;
    }

    printf("[SERVER] TLS upload server listening on 0.0.0.0:%u\n", tcp_port);
    printf("[SERVER] record_root=%s, workers=%d\n", record_root, workers);
    printf("[SERVER] protocol: [sid_len][sid][name_len][name][size][data] ... name_len=0 종료\n");

    task_queue_t q;
    tq_init(&q);

    pthread_t *ths = (pthread_t *)calloc((size_t)workers, sizeof(pthread_t));
    worker_arg_t wa;
    wa.q = &q;
    wa.record_root = record_root;

    for (int i = 0; i < workers; i++) {
        if (pthread_create(&ths[i], NULL, worker_main, &wa) != 0) {
            fprintf(stderr, "[SERVER] pthread_create failed\n");
            g_running = 0;
            break;
        }
    }

    // accept loop: "연결을 받기만 하고" 작업큐에 넣는다.
    while (g_running) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int cfd = accept(g_listen_fd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (!g_running) break;
            perror("accept");
            break;
        }

        task_t t;
        t.cfd = cfd;
        t.peer = cli;

        // 큐가 꽉 찼으면(혹은 종료 중) 연결을 닫는다.
        if (tq_push(&q, t) != 0) {
            close(cfd);
            break;
        }
    }

    // 종료 처리: worker 깨우기
    g_running = 0;
    pthread_mutex_lock(&q.mu);
    pthread_cond_broadcast(&q.cv_not_empty);
    pthread_cond_broadcast(&q.cv_not_full);
    pthread_mutex_unlock(&q.mu);

    for (int i = 0; i < workers; i++) {
        if (ths[i]) pthread_join(ths[i], NULL);
    }

    free(ths);
    tq_destroy(&q);

    if (g_listen_fd >= 0) close(g_listen_fd);
    g_listen_fd = -1;

    // ffplay 종료(간단히 PID를 저장해 kill하는 방식은 필요하면 확장 가능)
    // 여기서는 사용자가 Ctrl+C 누르면 터미널 프로세스 그룹에 같이 죽는 경우가 많지만,
    // 더 깔끔하게 하려면 spawn_ffplay에서 PID 저장 배열로 관리해서 kill/wait 하면 됨.

    // DJI ffmpeg 종료
    if (dji_ffmpeg_pid > 0) {
        kill(dji_ffmpeg_pid, SIGTERM);
        waitpid(dji_ffmpeg_pid, NULL, 0);
    }

    tls_server_cleanup();
    printf("[SERVER] Server exiting.\n");
    return 0;
}
