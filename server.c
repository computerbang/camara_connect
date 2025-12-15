
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#define DEFAULT_RECORD_DIR "/var/cctv/records" // 녹화 저장 디렉터리
#define DEFAULT_CLIENT_ID  "client01" // 클라이언트 ID
#define DEFAULT_UDP_PORT   5000   // ffplay 수신 포트

static pid_t g_ffplay_pid = -1;
static int   g_listen_fd  = -1;
static int   g_running    = 1;

// 6.
static uint64_t ntohll_custom(uint64_t val) {
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t high = (uint32_t)(val >> 32);
    uint32_t low  = (uint32_t)(val & 0xFFFFFFFFULL);
    uint64_t res  = ((uint64_t)ntohl(low) << 32) | ntohl(high);
    return res;
#else
    return val;
#endif
}

// 5.
// len 바이트를 정확히 다 읽을 때까지 반복
// EOF나 에러가 나면 -1, 정상적으로 다 읽었으면 0
// handle_client_connection 함수에서 사용
static int read_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;

    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "[SERVER] read_all: peer closed (need %zu more bytes)\n",
                    len - total);
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

// 1.
// 녹화 디렉터리가 없으면 생성 
static int ensure_record_dir(const char *dir) {
    struct stat st;
    /**
     * @brief stat 함수
     * stat()은 그 경로가 실제로 존재하는지 + 어떤 타입인지(파일/폴더/권한 등) 정보를 st에 채움
     * 반환값이 0이면: 존재한다!
     */
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "[SERVER] Path exists but is not directory: %s\n", dir);
            return -1;
        }
        return 0;
    }
    // stat.h에서 mkdir라는 함수를 사용해서 디렉토리 생성
    // 755 보안 괜찮음? 
    if (mkdir(dir, 0755) < 0) {
        perror("mkdir record dir");
        return -1;
    }
    printf("[SERVER] Created record directory: %s\n", dir);
    return 0;
}

// 3.
// ffplay 자동 실행
static int start_ffplay(int udp_port) {
    pid_t pid = fork(); // ffplay가 외부 프로그램이므로 fork+exec 사용 
    if (pid < 0) {
        perror("[SERVER] fork ffplay");
        return -1;
    }

    if (pid == 0) {
        // 자식 프로세스: ffplay 실행
        char url[64];
        snprintf(url, sizeof(url), "udp://@:%d", udp_port);

        // execlp 자식 프로세스의 프로그램 이미지를 ffplay로 교체
        // ffplay -fflags nobuffer(버퍼 덜 쌓기) -flags low_delay(저지연) -framedrop(프레임 빌려서 현재 시점 따라감) udp://@:<port>
        execlp("ffplay",
               "ffplay",
               "-fflags", "nobuffer",
               "-flags", "low_delay",
               "-framedrop",
               url,
               (char *)NULL);

        perror("[SERVER] execlp ffplay");
        _exit(1);
    }

    g_ffplay_pid = pid;
    printf("[SERVER] ffplay started with PID %d (udp://@:%d)\n", g_ffplay_pid, udp_port);
    return 0;
}

// 2.
/** 
 * @bug
    * @
 * 
 */
// 시그널 핸들러: 서버/ffplay 정리
static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;

    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }

    if (g_ffplay_pid > 0) {
        printf("[SERVER] Stopping ffplay (PID=%d)...\n", g_ffplay_pid);
        kill(g_ffplay_pid, SIGTERM); 
        waitpid(g_ffplay_pid, NULL, 0); // 좀비 프로세스 방지
        g_ffplay_pid = -1;
    }
}

// 4.
// 한 클라이언트 소켓에서 파일 하나 수신 처리
static int handle_client_connection(int client_fd,
                                    const char *record_dir,
                                    const char *client_id)
{
    uint16_t name_len_net;
    uint16_t name_len;
    uint64_t file_size_net;
    uint64_t file_size;

    // 1) 파일명 길이(2바이트)
    if (read_all(client_fd, &name_len_net, sizeof(name_len_net)) < 0) {
        fprintf(stderr, "[SERVER] Failed to read filename length\n");
        return -1;
    }
    name_len = ntohs(name_len_net);

    if (name_len == 0 || name_len > 1000) {
        fprintf(stderr, "[SERVER] Invalid filename length: %u\n", name_len);
        return -1;
    }

    /** 
     * @bug 
        * @brief 파일명 읽기에서 경로 조각 문제 발생 가능
     */
    // 2) 파일명
    char filename[1024];
    memset(filename, 0, sizeof(filename));
    if (read_all(client_fd, filename, name_len) < 0) {
        fprintf(stderr, "[SERVER] Failed to read filename\n");
        return -1;
    }
    filename[name_len] = '\0';


    // 3) 파일 크기(8바이트)
    if (read_all(client_fd, &file_size_net, sizeof(file_size_net)) < 0) {
        fprintf(stderr, "[SERVER] Failed to read file size\n");
        return -1;
    }
    // ntohll_custom 32bit 시스템에서 64bit 정수 바이트 순서 변환
    file_size = ntohll_custom(file_size_net);

    printf("[SERVER] Incoming file: name='%s', size=%llu bytes\n",
           filename, (unsigned long long)file_size);

    // 최종 저장 파일명: CLIENT_ID_원본파일명
    char final_name[1200];
    snprintf(final_name, sizeof(final_name), "%s_%s", client_id, filename);

    char path[1600];
    /** 
     * @bug
     * @brief 디렉터리 경로 '/' 누락 시 문제 발생 가능 대부분 os는 가능 
     */
    snprintf(path, sizeof(path), "%s/%s", record_dir, final_name);

    // 파일 열기
    int out_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("[SERVER] open output file");
        return -1;
    }

    // 4) 파일 데이터 수신
    const size_t BUF_SIZE = 1024 * 64;
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "[SERVER] malloc failed\n");
        close(out_fd);
        return -1;
    }

    uint64_t received = 0;
    while (received < file_size) {
        size_t to_read = file_size - received;
        if (to_read > BUF_SIZE) to_read = BUF_SIZE;
        
        ssize_t n = read(client_fd, buf, to_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("[SERVER] read file data");
            free(buf);
            close(out_fd);
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "[SERVER] Connection closed while receiving file data\n");
            break;
        }

        ssize_t w = write(out_fd, buf, n);
        if (w < 0) {
            perror("[SERVER] write to output file");
            free(buf);
            close(out_fd);
            return -1;
        }
        if (w != n) {
            fprintf(stderr, "[SERVER] partial write: %zd / %zd\n", w, n);
            free(buf);
            close(out_fd);
            return -1;
        }

        received += (uint64_t)n;
    }

    free(buf);
    close(out_fd);

    if (received == file_size) {
        printf("[SERVER] File saved: %s (%llu bytes)\n",
               path, (unsigned long long)received);
        return 0;
    } else {
        fprintf(stderr,
                "[SERVER] WARNING: size mismatch. expected=%llu, received=%llu\n",
                (unsigned long long)file_size,
                (unsigned long long)received);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <TCP_PORT> [RECORD_DIR] [CLIENT_ID]\n"
                "  TCP_PORT   : listen port (예: 7000)\n"
                "  RECORD_DIR : (optional) 저장 경로, 기본: %s\n"
                "  CLIENT_ID  : (optional) 파일명 prefix, 기본: %s\n",
                argv[0], DEFAULT_RECORD_DIR, DEFAULT_CLIENT_ID);
        return 1;
    }

    uint16_t port = (uint16_t)atoi(argv[1]); // uint16_t로 오버플로우 방지, atoi는 int 반환("12abc" 같은 경우 12 반환), 실패는 0 반환

    const char *record_dir = DEFAULT_RECORD_DIR;
    const char *client_id  = DEFAULT_CLIENT_ID;

    if (argc >= 3) record_dir = argv[2];
    if (argc >= 4) client_id  = argv[3];

    printf("[SERVER] Starting TCP server on port %u\n", port);
    printf("[SERVER] Record dir: %s\n", record_dir);
    printf("[SERVER] Client ID prefix: %s\n", client_id);

    if (ensure_record_dir(record_dir) != 0) {
        return 1;
    }

    // 시그널 핸들러 등록
    struct sigaction sa; // 시그널이 오면 handle_signal 함수 호출
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal; 
    sigaction(SIGINT,  &sa, NULL); // Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // 종료 시그널

    // ffplay 실행
    if (start_ffplay(DEFAULT_UDP_PORT) != 0) {
        fprintf(stderr, "[SERVER] Failed to start ffplay (계속 진행은 함)\n");
    }

    // listen 소켓 생성, g_listen_fd static 전역변수
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(g_listen_fd);
        return 1;
    }

    //
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY는 모든 IP 주소를 허용
    addr.sin_port        = htons(port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_listen_fd);
        return 1;
    }

    if (listen(g_listen_fd, 5) < 0) {
        perror("listen");
        close(g_listen_fd);
        return 1;
    }

    printf("[SERVER] Listening...\n");

    while (g_running) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(g_listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) {
            if (!g_running && (errno == EBADF)) {
                // 시그널로 listen_fd 닫힌 경우
                break;
            }
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip_str, sizeof(ip_str));
        printf("[SERVER] New connection from %s:%u\n",
               ip_str, ntohs(cli_addr.sin_port));

        handle_client_connection(client_fd, record_dir, client_id);

        close(client_fd);
        printf("[SERVER] Connection closed.\n");
    }

    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }

    if (g_ffplay_pid > 0) {
        printf("[SERVER] Stopping ffplay (PID=%d)...\n", g_ffplay_pid);
        kill(g_ffplay_pid, SIGTERM);
        waitpid(g_ffplay_pid, NULL, 0);
        g_ffplay_pid = -1;
    }

    printf("[SERVER] Server exiting.\n");
    return 0;
}
