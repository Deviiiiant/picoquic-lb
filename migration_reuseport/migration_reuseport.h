
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include "picoquic_internal.h"
#include <picosocks.h>
#include <picoquic_utils.h>
#include <autoqlog.h>
#include "picosocks.h"
#include <sys/socket.h>
#include "picoquic_packet_loop.h"
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#define CORE_NUMBER 4
#define LB_MODE 1
#define ROUND_LB 1
#define HASH_LB 2
#define FILE_LB 3

#define PICOQUIC_SAMPLE_ALPN "picoquic_sample"
#define PICOQUIC_SAMPLE_SNI "test.example.com"

#define PICOQUIC_SAMPLE_NO_ERROR 0
#define PICOQUIC_SAMPLE_INTERNAL_ERROR 0x101
#define PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR 0x102
#define PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR 0x103
#define PICOQUIC_SAMPLE_FILE_READ_ERROR 0x104
#define PICOQUIC_SAMPLE_FILE_CANCEL_ERROR 0x105

#define PICOQUIC_SAMPLE_CLIENT_TICKET_STORE "sample_ticket_store.bin";
#define PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE "sample_token_store.bin";
#define PICOQUIC_SAMPLE_CLIENT_QLOG_DIR ".";
#define PICOQUIC_SAMPLE_SERVER_QLOG_DIR ".";

// common stream context 

typedef struct st_stream_ctx_t {
    struct st_stream_ctx_t* next_stream;
    struct st_stream_ctx_t* previous_stream;
    uint64_t stream_id;
    FILE* F;
    uint8_t file_name[256];
    size_t name_length;
    size_t file_length;
    size_t file_sent;
    unsigned int is_name_read : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} stream_ctx_t;

// app context 

typedef struct st_app_ctx_t {
    char const* default_dir;
    size_t default_dir_len;
    // picoquic_quic_t* server_back;
    stream_ctx_t* first_stream;
    stream_ctx_t* last_stream;
    int migration_flag; 
    uint8_t file_name[256];
} app_ctx_t;

// shared context
typedef struct st_shared_context {
    int cntmap_fd; 
    int sockmap_fd; 
    int prog_fd; 
    int worker_num; 
    picoquic_quic_t** worker_quic; 
    int** timer_flags; 
} shared_context_t; 

// thread parameters
typedef struct st_worker_thread_para {
    int id; 
    int* sock_fd; 
    picoquic_quic_t* quic; 
    int server_port; 
    shared_context_t* shared_context; 
} worker_thread_para_t; 

typedef struct st_timer_thread_attr {
    int** timer_flag; 
    int thread_num; 
    int sleep_time; 
} timer_thread_attr_t; 

// main function 
void worker(void* thread_paras); 

// stream callback function declartion
int stream_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx); 

