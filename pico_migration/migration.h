
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

#define CORE_NUMBER 1
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

typedef struct st_sample_server_stream_ctx_t {
    struct st_sample_server_stream_ctx_t* next_stream;
    struct st_sample_server_stream_ctx_t* previous_stream;
    uint64_t stream_id;
    FILE* F;
    uint8_t file_name[256];
    size_t name_length;
    size_t file_length;
    size_t file_sent;
    unsigned int is_name_read : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_server_stream_ctx_t;

// master staff 

typedef struct trans_data_master
{
    int** trans_bytes;
    uint8_t** trans_buffer;
    uint8_t** trans_send_buffer;
    int** trans_if_index_to;
    int** trans_socket_rank;
    uint64_t** trans_current_time;
    unsigned char** trans_received_ecn;
    struct sockaddr_storage** trans_addr_to;
    struct sockaddr_storage** trans_addr_from;
    struct sockaddr_storage** trans_peer_addr;
    struct sockaddr_storage** trans_local_addr;
    pthread_mutex_t* socket_mutex;
    int** trans_s_socket;
    int** trans_sock_af;
    int** trans_nb_sockets;
}trans_data_master_t;

typedef struct master_thread_para
{
    picoquic_quic_t* quic;
    picoquic_quic_t** quic_back;
    struct hashmap_s* cnx_id_table;
    int** trans_flag;
    trans_data_master_t shared_data;
    pthread_cond_t* nonEmpty;
    pthread_mutex_t* buffer_mutex;
    int server_port;
    pthread_mutex_t* socket_mutex;
}master_thread_para_t;

typedef struct st_sample_server_migration_ctx_t {
    char const* default_dir;
    size_t default_dir_len;
    picoquic_quic_t* server_back;
    sample_server_stream_ctx_t* first_stream;
    sample_server_stream_ctx_t* last_stream;
    int migration_flag;
    int server_flag;
    uint8_t file_name[256];
} sample_server_migration_ctx_t;

void master(void* thread_para); 


// slave staff 
typedef struct trans_data
{
    int* trans_bytes;
    uint8_t* trans_buffer;
    uint8_t* trans_send_buffer;
    int* trans_if_index_to;
    int* trans_socket_rank;
    uint64_t* trans_current_time;
    unsigned char* trans_received_ecn;
    struct sockaddr_storage* trans_addr_to;
    struct sockaddr_storage* trans_addr_from;
    struct sockaddr_storage* trans_peer_addr;
    struct sockaddr_storage* trans_local_addr;
    pthread_mutex_t* socket_mutex;

    int* trans_s_socket;
    int* trans_sock_af;
    int* trans_nb_sockets;

}trans_data_t;

typedef struct slave_thread_para
{
    int id;
    picoquic_quic_t* quic;
    struct hashmap_s* cnx_id_table;
    int* trans_flag;
    trans_data_t shared_data;
    pthread_cond_t* nonEmpty;
    pthread_mutex_t* buffer_mutex;
    pthread_mutex_t* socket_mutex;
    int server_port;
}slave_thread_para_t;

typedef struct st_sample_server_ctx_t {
    char const* default_dir;
    size_t default_dir_len;
    sample_server_stream_ctx_t* first_stream;
    sample_server_stream_ctx_t* last_stream;
} sample_server_ctx_t;

int sample_server_migration_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx); 

void slave (void* slave_para); 



