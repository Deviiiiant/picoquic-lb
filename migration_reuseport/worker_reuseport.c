#include "migration_reuseport.h"

int consume_context_pipe(context_pipe_t* cnx_pipe, picoquic_quic_t* quic){
    int migrate_counter = 0; 
    /* check if the pipe is empty */
    pthread_mutex_lock(&cnx_pipe->list_mutex); 
    if (is_pipe_empty(cnx_pipe)) {
        pthread_mutex_unlock(&(cnx_pipe->list_mutex)); 
        return 0; 
    }
    while (!is_pipe_empty(cnx_pipe)) {
        picoquic_cnx_t* cnx = dequeue_cnx(cnx_pipe); 
        if (cnx == NULL) {
            printf("a NUll CNX !!!\n"); 
        }
        // printf("got stuck here????\n"); 
        insert_cnx_to_list(cnx, quic); 
        migrate_counter ++; 
    }
    pthread_mutex_unlock(&(cnx_pipe->list_mutex)); 
    return migrate_counter; 
}

static void* picoquic_wake_list_node_value(picosplay_node_t* cnx_wake_node)
{
    return (cnx_wake_node == NULL)?NULL:(void*)((char*)cnx_wake_node - offsetof(struct st_picoquic_cnx_t, cnx_wake_node));
}


int migrate_connection(picoquic_cnx_t* connection_to_migrate, int server_b, shared_context_t* shared_context, int port){
    
    int ret = 0; 

    context_pipe_t* cnx_pipe = shared_context->context_pipes[server_b]; 
    pthread_mutex_lock(&cnx_pipe->list_mutex); 
    // /* delete context from wake list and current list */
    delete_cnx_from_list(connection_to_migrate); 
    connection_to_migrate->quic = shared_context->worker_quic[server_b]; 
    enqueue_cnx(cnx_pipe, connection_to_migrate); 
    pthread_mutex_unlock(&cnx_pipe->list_mutex); 
    // pthread_mutex_lock(&shared_context->cnt_map_mutex); 
    int cntmap_fd = shared_context->cntmap_fd; 
    ret = bpf_map_update_elem(cntmap_fd, &port, &server_b, BPF_ANY); 
    if (ret == -1) {
        printf("errno is %s\n", strerror(errno)); 
    }
    // pthread_mutex_unlock(&shared_context->cnt_map_mutex); 
    return ret; 
}

int open_sockets(int local_port, int local_af, SOCKET_TYPE * s_socket, int * sock_af, int nb_sockets_max)
{
    int nb_sockets = (local_af == AF_UNSPEC) ? 2 : 1;

    /* Compute how many sockets are necessary */
    if (nb_sockets > nb_sockets_max) {
        DBG_PRINTF("Cannot open %d sockets, max set to %d\n", nb_sockets, nb_sockets_max);
        nb_sockets = 0;
    } else if (local_af == AF_UNSPEC) {
        sock_af[0] = AF_INET;
        sock_af[1] = AF_INET6;
    }
    else if (local_af == AF_INET || local_af == AF_INET6) {
        sock_af[0] = local_af;
    }
    else {
        DBG_PRINTF("Cannot open socket(AF=%d), unsupported AF\n", local_af);
        nb_sockets = 0;
    }

    for (int i = 0; i < nb_sockets; i++) {
        int recv_set = 0;
        int send_set = 0;
        int optval = 1; 

        if ((s_socket[i] = socket(sock_af[i], SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET ||
            picoquic_socket_set_ecn_options(s_socket[i], sock_af[i], &recv_set, &send_set) != 0 ||
            picoquic_socket_set_pkt_info(s_socket[i], sock_af[i]) != 0 || setsockopt(s_socket[i], SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) != 0 || 
            (local_port != 0 && picoquic_bind_to_port(s_socket[i], sock_af[i], local_port) != 0)) {
            DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", sock_af[i], local_port);
            for (int j = 0; j < i; j++) {
                if (s_socket[i] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[i]);
                    s_socket[i] = INVALID_SOCKET;
                }
            }
            nb_sockets = 0;
            break;
        }
    }

    return nb_sockets;
}

int packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    shared_context_t* shared_context, 
    int id, 
    worker_thread_para_t* worker_thread_para, 
    int mig_cnc_num
    ) 
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    picoquic_cnx_t* last_cnx = NULL;
    int number_to_migrate = mig_cnc_num; 
    int migration_counter = 0; 
    int migration_recved = 0; 
    int migrate_threshold = 1; 

    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    worker_thread_para->sock_fd = s_socket; 

    // attach socket to ebpf prog 
    if (id == 0) {
        ret = setsockopt(s_socket[0] ,SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &(shared_context->prog_fd), sizeof(shared_context->prog_fd)); 
        // if (ret == 0) printf("bind socket to ebpf prog success\n"); 
    }

    // add sock fd to 
    ret = bpf_map_update_elem(shared_context->sockmap_fd, &id, &s_socket[0], BPF_NOEXIST);
    // printf("update sockmap ret is %d\n", ret); 
    if (ret == -1) printf("errno is %s\n", strerror(errno)); 

    while (ret == 0) {
        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &socket_rank, &current_time);

        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;

            loop_count_time = current_time;
            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;
            uint16_t current_recv_port = socket_port;

            if (bytes_recv > 0) {
                /* track the local port value if not known yet */
                if (socket_port == 0 && nb_sockets == 1) {
                    struct sockaddr_storage local_address;
                    if (picoquic_get_local_address(s_socket[0], &local_address) != 0) {
                        memset(&local_address, 0, sizeof(struct sockaddr_storage));
                        fprintf(stderr, "Could not read local address.\n");
                    }
                    else if (addr_to.ss_family == AF_INET6) {
                        socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                    }
                    else if (addr_to.ss_family == AF_INET) {
                        socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                    }
                    current_recv_port = socket_port;
                }
                /* Document incoming port */
                if (addr_to.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
                }
                else if (addr_to.ss_family == AF_INET) {
                    ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
                }


                if (migration_recved > 0) {
                    // printf("recved %d new connections!!!!!\n", migration_recved); 
                    
                    migration_counter += migration_recved; 
                    // printf("total migrated connections %d!!!!!!!\n", migration_counter); 
                    migration_recved = 0; 
                }

                /* Submit the packet to the server */
                (void)picoquic_incoming_packet(quic, buffer,
                    (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                    (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                    current_time); 

                if (number_to_migrate != 0 && id == 0) {
                    for (int i = 0; i < migrate_threshold; i++) {
                        picoquic_cnx_t* connection_to_migrate = (picoquic_cnx_t *)picoquic_wake_list_node_value(quic->cnx_wake_tree.root);
                        if (connection_to_migrate != NULL) {
                            struct sockaddr_in *src_addr = (struct sockaddr_in*) & addr_from;
                            int port = ntohs(src_addr->sin_port); 
                            if (connection_to_migrate->callback_ctx!=NULL) {
                                if ((((app_ctx_t *) (connection_to_migrate->callback_ctx))->migration_flag) == 1) {
                                    int next_server = (id + 1) % (shared_context->worker_num);   
                                    connection_to_migrate->has_been_migrated = 1; 
                                    migrate_connection(connection_to_migrate, next_server, shared_context, port); 
                                    // set migration flag to 0, since we only migrate once 
                                    // ((app_ctx_t *) (connection_to_migrate->callback_ctx))->migration_flag = 1; 
                                    number_to_migrate --; 
                                    migration_counter ++;  
                                    // printf("%d connections have been migrated on %d\n", migration_counter, id); 
                                }
                            }
                        }
                    }
                }   
                migration_recved = consume_context_pipe(shared_context->context_pipes[id], quic); 
            }

            while (ret == 0) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;


                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                if (ret == 0 && send_length > 0) {
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = s_socket[i];
                            break;
                        }
                    }

                    sock_ret = picoquic_send_through_socket(send_socket,
                        (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                        (const char*)send_buffer, (int)send_length, &sock_err);

                    // printf("worker %d is sending \n", id); 
                    if (sock_ret < 0) {
                        if (last_cnx == NULL) {
                            printf("last cnx is NULL\n"); 
                        }
                    }


                    
                }
                else {
                    break;
                }
            }

        }

    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(s_socket[i]);
            s_socket[i] = INVALID_SOCKET;
        }
    }

    return ret;
} 

stream_ctx_t * sample_server_create_stream_context(app_ctx_t* server_ctx, uint64_t stream_id)
{
    stream_ctx_t* stream_ctx = (stream_ctx_t*)malloc(sizeof(stream_ctx_t));
    // printf("stream ctx size is %ld\n", sizeof(stream_ctx_t)); 

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(stream_ctx_t));

        if (server_ctx->last_stream == NULL) {
            // printf("insert a new ctx to empty list\n"); 
            server_ctx->last_stream = stream_ctx;
            server_ctx->first_stream = stream_ctx;
        }
        else {
            // printf("list is not empty, attach ctx to tail\n"); 
            stream_ctx->previous_stream = server_ctx->last_stream;
            server_ctx->last_stream->next_stream = stream_ctx;
            server_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

int sample_server_open_stream(app_ctx_t* server_ctx, stream_ctx_t* stream_ctx)
{
    int ret = 0;
    char file_path[1024];

    /* Keep track that the full file name was acquired. */
    stream_ctx->is_name_read = 1;

    /* Verify the name, then try to open the file */
    if (server_ctx->default_dir_len + stream_ctx->name_length + 1 > sizeof(file_path)) {
        ret = PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR;
    }
    else {
        /* Verify that the default path is empty of terminates with "/" or "\" depending on OS,
         * and format the file path */
        size_t dir_len = server_ctx->default_dir_len;
        if (dir_len > 0) {
            memcpy(file_path, server_ctx->default_dir, dir_len);
            if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0]) {
                file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                dir_len++;
            }
        }
        memcpy(file_path + dir_len, stream_ctx->file_name, stream_ctx->name_length);
        file_path[dir_len + stream_ctx->name_length] = 0;

        /* Use the picoquic_file_open API for portability to Windows and Linux */
        stream_ctx->F = picoquic_file_open(file_path, "rb");

        if (stream_ctx->F == NULL) {
            ret = PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR;
        }
        else {
            /* Assess the file size, as this is useful for data planning */
            long sz;
            fseek(stream_ctx->F, 0, SEEK_END);
            sz = ftell(stream_ctx->F);

            if (sz <= 0) {
                stream_ctx->F = picoquic_file_close(stream_ctx->F);
                ret = PICOQUIC_SAMPLE_FILE_READ_ERROR;
            }
            else {
                stream_ctx->file_length = (size_t)sz;
                fseek(stream_ctx->F, 0, SEEK_SET);
                ret = 0;
            }
        }
    }

    return ret;
}

void sample_server_delete_stream_context(app_ctx_t* server_ctx, stream_ctx_t* stream_ctx)
{
    // printf("delete stream ctx\n"); 
    /* Close the file if it was open */
    if (stream_ctx->F != NULL) {
        stream_ctx->F = picoquic_file_close(stream_ctx->F);
    }

    /* Remove the context from the server's list */
    if (stream_ctx->previous_stream == NULL) {
        server_ctx->first_stream = stream_ctx->next_stream;
    }
    else {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }

    if (stream_ctx->next_stream == NULL) {
        server_ctx->last_stream = stream_ctx->previous_stream;
    }
    else {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }

    /* release the memory */
    free(stream_ctx);
}

void sample_server_delete_context(app_ctx_t* server_ctx)
{
    /* Delete any remaining stream context */
    while (server_ctx->first_stream != NULL) {
        sample_server_delete_stream_context(server_ctx, server_ctx->first_stream);
    }

    /* release the memory */
    free(server_ctx);
}

int stream_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    app_ctx_t* server_ctx = (app_ctx_t*)callback_ctx;
    stream_ctx_t* stream_ctx = (stream_ctx_t*)v_stream_ctx;

        // fprintf(stderr, "CALLBACK %d\n",fin_or_event);
    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (app_ctx_t *)malloc(sizeof(app_ctx_t));
        if (server_ctx == NULL) {
            /* cannot handle the connection */
            fprintf(stderr, "Could not allocate memory\n");
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            app_ctx_t* d_ctx = (app_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
            if (d_ctx != NULL) {
                memcpy(server_ctx, d_ctx, sizeof(app_ctx_t));
            }
            else {
                /* This really is an error case: the default connection context should never be NULL */
                memset(server_ctx, 0, sizeof(app_ctx_t));
                server_ctx->default_dir = "";
            }
            picoquic_set_callback(cnx, stream_callback, server_ctx);
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Create and initialize stream context */
                stream_ctx = sample_server_create_stream_context(server_ctx, stream_id);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_INTERNAL_ERROR);
                return(-1);
            }
            else if (stream_ctx->is_name_read) {
                /* Write after fin? */
                return(-1);
            }
            else {
                /* Accumulate data */
                size_t available = sizeof(stream_ctx->file_name) - stream_ctx->name_length - 1;

                if (length > available) {
                    /* Name too long: reset stream! */
                    sample_server_delete_stream_context(server_ctx, stream_ctx);

                    fprintf(stderr, "Name too long!\n");
                    (void) picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR);
                }
                else {
                    if (length > 0) {
                        memcpy(stream_ctx->file_name + stream_ctx->name_length, bytes, length);
                        stream_ctx->name_length += length;
                    }
                    if (fin_or_event == picoquic_callback_stream_fin) {
                        int stream_ret;

                        /* If fin, mark read, check the file, open it. Or reset if there is no such file */
                        stream_ctx->file_name[stream_ctx->name_length + 1] = 0;
                        stream_ctx->is_name_read = 1;
                        stream_ret = sample_server_open_stream(server_ctx, stream_ctx);

                        if (stream_ret == 0) {
                            /* If data needs to be sent, set the context as active */
                            ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                        }
                        else {
                            /* If the file could not be read, reset the stream */
                            fprintf(stderr, "Unknown file\n");
                            sample_server_delete_stream_context(server_ctx, stream_ctx);
                            (void) picoquic_reset_stream(cnx, stream_id, stream_ret);
                        }
                    }
                    memcpy(server_ctx->file_name, stream_ctx->file_name, 256*sizeof(uint8_t));
                    if (server_ctx->migration_flag != 2)  server_ctx->migration_flag = 1;
                   
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
            }
            else if (stream_ctx->F == NULL) {
                /* Error, asking for data after end of file */
            }
            else {
                /* Implement the zero copy callback */
                size_t available = stream_ctx->file_length - stream_ctx->file_sent;
                int is_fin = 1;
                uint8_t* buffer;

                if (available > length) {
                    available = length;
                    is_fin = 0;
                }
                
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL) {
                    size_t nb_read = fread(buffer, 1, available, stream_ctx->F);

                    if (nb_read != available) {
                        /* Error while reading the file */
                        sample_server_delete_stream_context(server_ctx, stream_ctx);
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_READ_ERROR);
                    }
                    else {
                        stream_ctx->file_sent += available;
                    }
                }
                else {
                /* Should never happen according to callback spec. */
                    ret = -1;
                }
            }
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            if (stream_ctx != NULL) {
                /* Mark stream as abandoned, close the file, etc. */
                fprintf(stderr, "Client reset\n");
                sample_server_delete_stream_context(server_ctx, stream_ctx);
                picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_CANCEL_ERROR);
            }
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            // fprintf(stderr, "App close\n");
            sample_server_delete_context(server_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

void worker(void* worker_thread_attr) {
    worker_thread_para_t* worker_thread_para = (worker_thread_para_t*) worker_thread_attr;
    picoquic_quic_t* quic = worker_thread_para->quic;
    shared_context_t* shared_context = worker_thread_para->shared_context; 
    int server_port = worker_thread_para->server_port;
    int id = worker_thread_para->id; 
    int mig_cnc_num = worker_thread_para->mig_cnc_num; 

    packet_loop(quic, server_port, 0, 0, shared_context, id, worker_thread_para, mig_cnc_num); 
}