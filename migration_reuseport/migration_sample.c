#include "migration_reuseport.h"

int test_migration(int server_port, const char* server_cert, const char* server_key, const char* default_dir) { 
    int ret = 0; 
    picoquic_quic_t* worker_quic[CORE_NUMBER] = {NULL}; 
    char const* qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;

    worker_thread_para* worker_thread_paras[CORE_NUMBER] = {NULL}; 

    struct hashmap_S hashmap; 
    hashmap_create(32, &hashmap); 
    struct hashmap_s* cnx_table = &hashmap; 
    current_time = picoquic_current_time(); 

    for (size_t i = 0; i < CORE_NUMBER; i ++) { 
        app_ctx_t* app_ctx = malloc(sizeof(app_ctx_t)); 
        app_ctx->default_dir = default_dir; 
        app_ctx->default_dir_len = strlen(default_dir); 
        worker_quic[i] = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        stream_callback, default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);
        work
    }


}