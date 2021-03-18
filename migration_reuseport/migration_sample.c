#include "migration_reuseport.h"

int test_migration(int server_port, const char* server_cert, const char* server_key, const char* default_dir) { 

    int ret = 0; 
    picoquic_quic_t* worker_quic[CORE_NUMBER] = {NULL}; 
    char const* qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;

    //create thread paras and thraed obj 
    worker_thread_para_t* worker_thread_paras[CORE_NUMBER] = {NULL}; 
    shared_context_t* shared_context = malloc(sizeof(shared_context_t)); 
    pthread_t thread[CORE_NUMBER]; 

    // initiate shared context 
    struct hashmap_s cnx_hashmap; 
    hashmap_create(32, &cnx_hashmap); 
    struct hashmap_s* cnx_table = &cnx_hashmap; 
    current_time = picoquic_current_time(); 
    
    shared_context->cnx_table = cnx_table; 
    shared_context->worker_quic = worker_quic; 

    // create worker thread 

    for (size_t i = 0; i < CORE_NUMBER; i ++) { 
        // create app context 
        app_ctx_t* app_ctx = malloc(sizeof(app_ctx_t)); 
        app_ctx->default_dir = default_dir; 
        app_ctx->default_dir_len = strlen(default_dir); 
        worker_quic[i] = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        stream_callback, app_ctx, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);
        printf("create worker %ld quic success\n", i); 
        
        // create thread para
        worker_thread_paras[i] = malloc(sizeof(worker_thread_para_t)); 
        worker_thread_paras[i]->id = i; 
        worker_thread_paras[i]->quic = worker_quic[i]; 
        worker_thread_paras[i]->server_port = server_port; 
        worker_thread_paras[i]->shared_context = shared_context; 

        // set quic attribute 
        picoquic_set_cookie_mode(worker_quic[i], 2);
        picoquic_set_default_congestion_algorithm(worker_quic[i], picoquic_bbr_algorithm);
        picoquic_set_qlog(worker_quic[i], qlog_dir);
        picoquic_set_log_level(worker_quic[i], 1);
        picoquic_set_key_log_file_from_env(worker_quic[i]);

        // initialize thread 
        pthread_create(&thread[i], NULL, (void* ) worker, worker_thread_paras[i]); 
        printf("create worker %ld thread success\n", i); 
    }

    for (int i = 0; i < CORE_NUMBER; i++) {
        pthread_join(thread[i], NULL); 
    }

    printf("server exit\n"); 
    return ret; 
}

static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s client server_name port folder *queried_file\n", sample_name);
    fprintf(stderr, "or :\n");
    fprintf(stderr, "    %s server port cert_file private_key_file folder\n", sample_name);
    exit(1);
}

int get_port(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}
int main(int argc, char** argv)
{
    int exit_code = 0;

    if (argc < 2) {
        usage(argv[0]);
    }
    else if (strcmp(argv[1], "server") == 0) {
        if (argc < 5) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[2]);
            exit_code = test_migration(server_port, argv[3], argv[4], argv[5]);
        }
    }
    else
    {
        usage(argv[0]);
    }

    exit(exit_code);
}