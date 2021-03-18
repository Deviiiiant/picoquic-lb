
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
#include "hashmap.h"
#include <pthread.h>

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
    picoquic_quic_t* server_back;
    stream_ctx_t* first_stream;
    stream_ctx_t* last_stream;
    uint8_t file_name[256];
} app_ctx_t;

// thread parameters
typedef struct st_worker_thread_para {
    int id; 
    picoquic_quic_t* quic; 
    int server_port; 
    shared_context_t* shared_context; 
} worker_thread_para; 

// shared context
typedef struct st_shared_context {
    struct hashmap_s* quic_table; 
    struct hashmap_s* cnc_table; 
} shared_context_t; 

// main function 
int worker((void* ) thread_paras); 

