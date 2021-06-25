#include "migration_reuseport.h"

void timer(void* timer_attr) {
    timer_thread_attr_t* timer_thread_attr = (timer_thread_attr_t*) timer_attr; 
    sleep(timer_thread_attr->sleep_time); 
    printf("time to migrate!\n"); 
    for (int i = 0; i < timer_thread_attr->thread_num; i ++) {
        *(timer_thread_attr->timer_flag[i]) = 1; 
    }
}


int test_migration(int server_port, const char* server_cert, const char* server_key, int core_number, const char* default_dir) { 

    printf("something here"); 
    int thread_number = core_number; 
    int ret = 0; 
    picoquic_quic_t* worker_quic[thread_number]; 
    memset(worker_quic, 0, thread_number*sizeof(picoquic_quic_t*));
    uint64_t current_time = 0;

    //create thread paras and thraed obj 
    // worker_thread_para_t* worker_thread_paras[core_number] = {NULL}; 
    worker_thread_para_t* worker_thread_paras[thread_number]; 
    memset(worker_thread_paras, 0, thread_number*sizeof(worker_thread_para_t*));
    shared_context_t* shared_context = malloc(sizeof(shared_context_t)); 
    pthread_t thread[thread_number]; 
    pthread_t timer_thread; 

    // initiate shared context 
    /*todo:
    1. load bpf prog 
    2. find sockmap fd 
    3. find cntmap fd 
    4. pass fds to shared context  
    */ 
    // load bpf prog     
    struct bpf_prog_load_attr prog_load_attr= {0};
    prog_load_attr.prog_type = BPF_PROG_TYPE_SK_REUSEPORT;
    prog_load_attr.file = "bpf.o";
    // int err; 
    struct bpf_object* obj;

    //This will be a number to reference the program
    int prog_fd;
    struct bpf_program *prog;
    const char *prog_name = "sec/mybpf";
    bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd); 
    prog = bpf_object__find_program_by_title(obj, prog_name);
    assert(prog != 0);
    prog_fd = bpf_program__fd(prog);
    assert(prog_fd >= 0);

    // find sockmap 
    int sockmap_fd; 
    struct bpf_map *sockmap;
    sockmap = bpf_object__find_map_by_name(obj, "sockmap");
    sockmap_fd = bpf_map__fd(sockmap); 
    assert(sockmap_fd > -1); 

    // find cnt map 
    int cntmap_fd; 
    struct bpf_map *cntmap;
    cntmap = bpf_object__find_map_by_name(obj, "cntmap");
    cntmap_fd = bpf_map__fd(cntmap); 
    assert(cntmap_fd > -1); 

    // find core number map 
    int core_number_map_fd; 
    struct bpf_map *core_number_map;
    core_number_map = bpf_object__find_map_by_name(obj, "core_number_map");
    core_number_map_fd = bpf_map__fd(core_number_map); 
    assert(core_number_map_fd > -1); 
    // pass core number to bpf prog 
    int one = 1; 
    ret = bpf_map_update_elem(core_number_map_fd, &one, &thread_number, BPF_NOEXIST); 
    if (ret < 0) printf("update core number map errno is %s\n", strerror(errno)); 

    int rb_counter_map_fd; 
    struct bpf_map *rb_counter_map;
    rb_counter_map = bpf_object__find_map_by_name(obj, "rb_counter_map");
    rb_counter_map_fd = bpf_map__fd(rb_counter_map); 
    assert(rb_counter_map_fd > -1); 
    // pass core number to bpf prog 
    int zero = 0; 
    ret = bpf_map_update_elem(rb_counter_map_fd, &one, &zero, BPF_NOEXIST); 
    if (ret < 0) printf("update core number map errno is %s\n", strerror(errno)); 

    // init timer flag 
    int* timer_flags[thread_number]; 
    memset(timer_flags, 0, thread_number*sizeof(int*)); 
    for(int i = 0; i < thread_number; i ++) {
        timer_flags[i] = malloc(sizeof(int)); 
    }

    current_time = picoquic_current_time(); 

    shared_context->cntmap_fd = cntmap_fd; 
    shared_context->sockmap_fd = sockmap_fd; 
    shared_context->prog_fd = prog_fd; 
    shared_context->worker_quic = worker_quic; 
    shared_context->worker_num = core_number; 
    shared_context->timer_flags = timer_flags; 

    // create worker thread 
    cpu_set_t cpuset; 
    CPU_ZERO(&cpuset); 
    for (int i = 0; i < thread_number; i ++) { 
        // create app context 
        app_ctx_t* app_ctx = malloc(sizeof(app_ctx_t)); 
        app_ctx->default_dir = default_dir; 
        app_ctx->default_dir_len = strlen(default_dir); 
        app_ctx->first_stream = NULL; 
        app_ctx->last_stream = NULL; 
        app_ctx->migration_flag = -1; 
        worker_quic[i] = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        stream_callback, app_ctx, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);
        printf("create worker %d quic success\n", i); 
        
        // create thread para
        worker_thread_paras[i] = malloc(sizeof(worker_thread_para_t)); 
        worker_thread_paras[i]->id = i; 
        worker_thread_paras[i]->quic = worker_quic[i]; 
        worker_thread_paras[i]->server_port = server_port; 
        worker_thread_paras[i]->shared_context = shared_context; 

        // set quic attribute 
        picoquic_set_cookie_mode(worker_quic[i], 2);
        picoquic_set_default_congestion_algorithm(worker_quic[i], picoquic_bbr_algorithm);
        // picoquic_set_qlog(worker_quic[i], qlog_dir);
        // picoquic_set_log_level(worker_quic[i], 1);
        // picoquic_set_key_log_file_from_env(worker_quic[i]);

        // initialize thread 
        pthread_create(&thread[i], NULL, (void* ) worker, worker_thread_paras[i]); 
        printf("create worker %d thread success\n", i); 

        //set cpu affinity 
        CPU_SET(i + 8, &cpuset); 
        pthread_setaffinity_np(thread[i], sizeof(cpuset), &cpuset); 
    }

    // init timer thread attr 
    timer_thread_attr_t* timer_attr = malloc(sizeof(timer_thread_attr_t)); 
    timer_attr-> thread_num = thread_number; 
    timer_attr->timer_flag = timer_flags; 
    timer_attr->sleep_time = 5; 

    pthread_create(&timer_thread, NULL, (void* ) timer, timer_attr); 

    for (int i = 0; i < thread_number; i++) {
        printf("create thread %d\n", i); 
        pthread_join(thread[i], NULL); 
    }
    
    pthread_join(timer_thread, NULL);
    printf("timer thread create success\n");  

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
            int core_number = atoi(argv[5]); 
            exit_code = test_migration(server_port, argv[3], argv[4], core_number, argv[6]);
        }
    }
    else
    {
        usage(argv[0]);
    }

    exit(exit_code);
}