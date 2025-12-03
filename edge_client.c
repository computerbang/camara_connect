// edge_client.c
// USB 웹캠 기반 실시간 스트리밍 + 10초 세그먼트 자동 업로드 클라이언트
// 빌드 예시: gcc -Wall -Wextra -O2 -o edge_client edge_client.c
//
// 사용 예시:
//   ./edge_client 192.168.0.128 7000
//
// - UDP 스트리밍: udp://서버IP:5000  (서버에서 ffplay udp://@:5000 으로 시청)
// - 세그먼트 디렉터리: /home/ubuntu/segments
// - 업로드 프로토콜: [2B name_len][name][8B file_size][file_data]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/inotify.h>
#include <sys/wait.h>    // waitpid
#include <limits.h>

// ---- 설정 상수들 ----

// 카메라 디바이스
#define CAMERA_DEVICE   "/dev/video0"

// UDP 스트리밍 포트 (서버 ffplay: udp://@:5000)
#define DEFAULT_UDP_PORT 5000

// 세그먼트 저장 디렉터리
#define SEGMENT_DIR     "/home/ubuntu/segments"

// inotify 버퍼 크기
#define INOTIFY_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

// ffmpeg 경로
#define FFMPEG_CMD      "ffmpeg"

static pid_t g_ffmpeg_pid = -1;
static int g_running = 1;

// ---------- 시그널 핸들러 ----------

void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
    if (g_ffmpeg_pid > 0) {
        kill(g_ffmpeg_pid, SIGTERM);
    }
}

// ---------- send_all ----------

int send_all(int sockfd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t total = 0;

    while (total < len) {
        ssize_t n = send(sockfd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "send_all: peer closed\n");
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

// ---------- htonll ----------

static uint64_t htonll_custom(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low  = (uint32_t)(val & 0xFFFFFFFFULL);
    uint64_t res  = ((uint64_t)htonl(low) << 32) | htonl(high);
    return res;
#else
    return val;
#endif
}

// ---------- 파일 업로드 ----------

int upload_file_to_server(const char *server_ip,
                          uint16_t tcp_port,
                          const char *dir_path,
                          const char *filename)
{
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, filename);

    struct stat st;
    if (stat(filepath, &st) < 0) {
        perror("stat");
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[UPLOAD] Not a regular file: %s\n", filepath);
        return -1;
    }
    uint64_t file_size = (uint64_t)st.st_size;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        close(fd);
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons(tcp_port);

    if (inet_pton(AF_INET, server_ip, &servaddr.sin_addr) <= 0) {
        perror("inet_pton");
        close(fd);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(fd);
        close(sock);
        return -1;
    }

    printf("[UPLOAD] Connected to %s:%u\n", server_ip, tcp_port);

    size_t name_len_full = strlen(filename);
    if (name_len_full == 0) {
        fprintf(stderr, "[UPLOAD] filename length is 0\n");
        close(fd);
        close(sock);
        return -1;
    }
    if (name_len_full > UINT16_MAX) {
        fprintf(stderr, "[UPLOAD] filename too long: %zu\n", name_len_full);
        close(fd);
        close(sock);
        return -1;
    }

    uint16_t name_len = (uint16_t)name_len_full;
    uint16_t name_len_net = htons(name_len);
    uint64_t file_size_net = htonll_custom(file_size);

    // 1) 파일명 길이
    if (send_all(sock, &name_len_net, sizeof(name_len_net)) < 0) {
        fprintf(stderr, "[UPLOAD] failed to send name_len\n");
        close(fd);
        close(sock);
        return -1;
    }

    // 2) 파일명
    if (send_all(sock, filename, name_len) < 0) {
        fprintf(stderr, "[UPLOAD] failed to send filename\n");
        close(fd);
        close(sock);
        return -1;
    }

    // 3) 파일 크기
    if (send_all(sock, &file_size_net, sizeof(file_size_net)) < 0) {
        fprintf(stderr, "[UPLOAD] failed to send file_size\n");
        close(fd);
        close(sock);
        return -1;
    }

    // 4) 파일 데이터
    printf("[UPLOAD] Sending file '%s' (%llu bytes)\n",
           filename, (unsigned long long)file_size);

    const size_t BUF_SIZE = 1024 * 64;
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "[UPLOAD] malloc failed\n");
        close(fd);
        close(sock);
        return -1;
    }

    uint64_t sent_total = 0;
    while (sent_total < file_size) {
        ssize_t r = read(fd, buf, BUF_SIZE);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("read");
            free(buf);
            close(fd);
            close(sock);
            return -1;
        }
        if (r == 0) break;

        if (send_all(sock, buf, (size_t)r) < 0) {
            fprintf(stderr, "[UPLOAD] send_all failed\n");
            free(buf);
            close(fd);
            close(sock);
            return -1;
        }
        sent_total += (uint64_t)r;
    }

    free(buf);
    close(fd);
    close(sock);

    printf("[UPLOAD] Done. Sent %llu / %llu bytes for %s\n",
           (unsigned long long)sent_total,
           (unsigned long long)file_size,
           filename);

    return 0;
}

// ---------- ffmpeg 실행 (tee 제거, 두 개 출력) ----------

int start_ffmpeg(const char *server_ip, int udp_port) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // 자식: ffmpeg 실행
        char cmd[2048];

        //  - v4l2에서 10~15fps 정도로 영상 뽑고
        //  - libx264 저지연 인코딩
        //  - 1번 출력: mpegts over UDP -> 실시간 모니터링
        //  - 2번 출력: 10초 세그먼트 mp4 파일 생성
        snprintf(cmd, sizeof(cmd),
                 FFMPEG_CMD
                 " -f v4l2 -framerate 10 -i %s "
                 "-c:v libx264 -preset veryfast -tune zerolatency -pix_fmt yuv420p "
                 "-f mpegts udp://%s:%d "
                 "-f segment -segment_time 10 -reset_timestamps 1 -strftime 1 "
                 "%s/cam01_%%Y%%m%%d_%%H%%M%%S.mp4",
                 CAMERA_DEVICE,
                 server_ip,
                 udp_port,
                 SEGMENT_DIR);

        printf("[FFMPEG] exec: %s\n", cmd);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        perror("execl");
        _exit(1);
    }

    g_ffmpeg_pid = pid;
    printf("[FFMPEG] started with PID %d\n", g_ffmpeg_pid);
    return 0;
}

// ---------- 세그먼트 디렉토리 확인 ----------

int ensure_segment_dir(void) {
    struct stat st;
    if (stat(SEGMENT_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "SEGMENT_DIR exists but is not a directory: %s\n", SEGMENT_DIR);
            return -1;
        }
        return 0;
    }

    if (mkdir(SEGMENT_DIR, 0755) < 0) {
        perror("mkdir SEGMENT_DIR");
        return -1;
    }
    printf("[INIT] Created segment directory: %s\n", SEGMENT_DIR);
    return 0;
}

// ---------- inotify로 디렉토리 감시 ----------

void monitor_and_upload(const char *server_ip, uint16_t tcp_port) {
    int in_fd = inotify_init1(IN_NONBLOCK);
    if (in_fd < 0) {
        perror("inotify_init1");
        return;
    }

    int wd = inotify_add_watch(in_fd, SEGMENT_DIR,
                               IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(in_fd);
        return;
    }

    printf("[MONITOR] Watching directory: %s\n", SEGMENT_DIR);
    printf("[MONITOR] Waiting for new segment files...\n");

    char buf[INOTIFY_BUF_LEN];

    while (g_running) {
        ssize_t len = read(in_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100 * 1000);
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
            perror("read(inotify)");
            break;
        }

        ssize_t i = 0;
        while (i < len) {
            struct inotify_event *event = (struct inotify_event *)&buf[i];

            if (event->len > 0) {
                if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) {
                    if (!(event->mask & IN_ISDIR)) {
                        const char *fname = event->name;
                        printf("[MONITOR] Detected new file: %s\n", fname);

                        const char *ext = strrchr(fname, '.');
                        if (ext && strcmp(ext, ".mp4") == 0) {
                            if (upload_file_to_server(server_ip, tcp_port,
                                                      SEGMENT_DIR, fname) != 0) {
                                fprintf(stderr, "[MONITOR] Upload failed for %s\n", fname);
                            } else {
                                printf("[MONITOR] Upload success: %s\n", fname);
                            }
                        } else {
                            printf("[MONITOR] Ignored (not mp4): %s\n", fname);
                        }
                    }
                }
            }

            i += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(in_fd, wd);
    close(in_fd);
}

// ---------- main ----------

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <SERVER_IP> <TCP_PORT> [UDP_PORT]\n"
                "  SERVER_IP : 파일 업로드 및 UDP 스트림 수신 서버 IP\n"
                "  TCP_PORT  : 세그먼트 업로드용 TCP 포트 (예: 7000)\n"
                "  UDP_PORT  : (옵션) 스트리밍 UDP 포트, 생략 시 %d\n",
                argv[0], DEFAULT_UDP_PORT);
        return 1;
    }

    const char *server_ip = argv[1];
    uint16_t tcp_port = (uint16_t)atoi(argv[2]);
    int udp_port = DEFAULT_UDP_PORT;
    if (argc >= 4) {
        udp_port = atoi(argv[3]);
    }

    printf("[MAIN] Edge client starting...\n");
    printf("[MAIN] Server (TCP upload): %s:%u\n", server_ip, tcp_port);
    printf("[MAIN] UDP streaming to: udp://%s:%d\n", server_ip, udp_port);
    printf("[MAIN] Segment dir: %s\n", SEGMENT_DIR);

    if (ensure_segment_dir() != 0) {
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (start_ffmpeg(server_ip, udp_port) != 0) {
        fprintf(stderr, "Failed to start ffmpeg\n");
        return 1;
    }

    monitor_and_upload(server_ip, tcp_port);

    if (g_ffmpeg_pid > 0) {
        printf("[MAIN] Stopping ffmpeg (PID=%d)...\n", g_ffmpeg_pid);
        kill(g_ffmpeg_pid, SIGTERM);
        waitpid(g_ffmpeg_pid, NULL, 0);
    }

    printf("[MAIN] Edge client exiting.\n");
    return 0;
}
