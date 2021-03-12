#include "migration.h"

int worker_packet_loop(picoquic_quic_t* quic,
    int id,
    struct hashmap_s* cnx_id_table,
    int* trans_flag,
    trans_data_t shared_data,
    pthread_cond_t* nonEmpty,
    pthread_mutex_t* buffer_mutex,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx, 
    int thread_id) 
{
    int* trans_bytes = shared_data.trans_bytes;
    uint8_t* trans_buffer = shared_data.trans_buffer;
    unsigned char* trans_received_ecn = shared_data.trans_received_ecn;
    struct sockaddr_storage* trans_addr_to = shared_data.trans_addr_to;
    struct sockaddr_storage* trans_addr_from = shared_data.trans_addr_from;
    int* trans_if_index_to = shared_data.trans_if_index_to;
    int* trans_socket_rank = shared_data.trans_socket_rank;

    SOCKET_TYPE* trans_s_socket = shared_data.trans_s_socket;
    int* trans_sock_af = shared_data.trans_sock_af;
    int* trans_nb_sockets = shared_data.trans_nb_sockets;
    pthread_mutex_t* socket_mutex = shared_data.socket_mutex;
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv = 0;
    unsigned char received_ecn;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;

    picoquic_connection_id_t log_cid;

    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;

    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;

    memset(sock_af, 0, sizeof(sock_af));

    while (ret == 0) {
        int socket_rank = -1;
        uint64_t current_time = picoquic_get_quic_time(quic);
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        int64_t next_wake_time = current_time + delta_t;
        struct timespec tv;
        if (delta_t <= 0) {
            tv.tv_sec = 0;
            tv.tv_nsec  = 0;
        } else {
            if (delta_t > 10000000) {
                tv.tv_sec = (long)10;
                tv.tv_nsec  = 0;
            } else {
                tv.tv_sec = (long)(next_wake_time / 1000000);
                tv.tv_nsec  = (long)((next_wake_time % 1000000) * 1000);
            }
        }
        pthread_mutex_lock(buffer_mutex);
        int check = pthread_cond_timedwait(nonEmpty, buffer_mutex, &tv);
        if (check == 0) {
            received_ecn = *trans_received_ecn;
            bytes_recv = *trans_bytes;
            if_index_to = *trans_if_index_to;
            socket_rank = *trans_socket_rank;
            current_time = picoquic_get_quic_time(quic);
            memcpy(&addr_to, trans_addr_to, sizeof(struct sockaddr_storage));
            memcpy(&addr_from, trans_addr_from, sizeof(struct sockaddr_storage));
            memcpy(buffer, trans_buffer, sizeof(buffer));
            memcpy(sock_af, trans_sock_af, sizeof(sock_af));
            memcpy(s_socket, trans_s_socket, sizeof(s_socket));
            nb_sockets = *trans_nb_sockets;
            pthread_mutex_unlock(buffer_mutex);
        } else {
            pthread_mutex_unlock(buffer_mutex);
        }

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
        uint64_t loop_time = current_time;
        uint16_t current_recv_port = socket_port;

        if (bytes_recv > 0 && check == 0) {
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
            if (testing_migration) {
                if (socket_rank == 0) {
                    current_recv_port = socket_port;
                }
                else {
                    current_recv_port = next_port;
                }
            }
            /* Document incoming port */
            if (addr_to.ss_family == AF_INET6) {
                ((struct sockaddr_in6*) & addr_to)->sin6_port = current_recv_port;
            }
            else if (addr_to.ss_family == AF_INET) {
                ((struct sockaddr_in*) & addr_to)->sin_port = current_recv_port;
            }
            ret = picoquic_incoming_packet(quic, buffer,
            (size_t)bytes_recv, (struct sockaddr*) & addr_from,
            (struct sockaddr*) & addr_to, if_index_to, received_ecn,
            current_time);
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
                if (send_socket == INVALID_SOCKET) {
                    sock_ret = -1;
                    sock_err = -1;
                }
                else {
                    if (testing_migration) {
                        /* This code path is only used in the migration tests */
                        uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                            ((struct sockaddr_in*) & local_addr)->sin_port :
                            ((struct sockaddr_in6*) & local_addr)->sin6_port;

                        if (send_port == next_port) {
                            send_socket = s_socket[nb_sockets - 1];
                        }
                    }
                    pthread_mutex_lock(socket_mutex);
                    sock_ret = picoquic_send_through_socket(send_socket,
                        (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                        (const char*)send_buffer, (int)send_length, &sock_err);
                    printf("worker id %d is sending %d bytes\n", id, sock_ret); 
                    pthread_mutex_unlock(socket_mutex);
                }

                if (sock_ret <= 0) {
                    if (last_cnx == NULL) {
                        picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                            peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                    }
                    else {
                        picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                            peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                    }
                }
            } else {
                break; 
            }
        }

        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            SOCKET_TYPE s_mig = INVALID_SOCKET;
            int s_mig_af;
            int sock_ret;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            
            next_port = (testing_nat) ? 0 : socket_port + 1;
            sock_ret = picoquic_packet_loop_open_sockets(next_port, sock_af[0], &s_mig, &s_mig_af, 1);
            if (sock_ret != 1 || s_mig == INVALID_SOCKET) {
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d, err=%d",
                        next_port, sock_af[0], sock_ret);
                }
            }
            else if (testing_nat) {
                if (s_socket[0] != INVALID_SOCKET) {
                    SOCKET_CLOSE(s_socket[0]);
                }
                s_socket[0] = s_mig;
                ret = 0;
            } else {
                /* Testing organized migration */
                if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                    struct sockaddr_storage local_address;
                    picoquic_store_addr(&local_address, (struct sockaddr*)& last_cnx->path[0]->local_addr);
                    if (local_address.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                    }
                    else if (local_address.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                    }
                    s_socket[nb_sockets] = s_mig;
                    nb_sockets++;
                    testing_migration = 1;
                    ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*)&last_cnx->path[0]->peer_addr,
                        (struct sockaddr*) &local_address, current_time);
                }
                else {
                    SOCKET_CLOSE(s_mig);
                }
            }
        }
    }
    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
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



void sample_server_delete_stream_context_for_migration(app_ctx_t* server_ctx, stream_ctx_t* stream_ctx)
{
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

void sample_server_delete_context_for_migration(app_ctx_t* server_ctx)
{
    /* Delete any remaining stream context */
    while (server_ctx->first_stream != NULL) {
        sample_server_delete_stream_context_for_migration(server_ctx, server_ctx->first_stream);
    }

    /* release the memory */
    free(server_ctx);
}

int sample_server_open_stream_for_migration(app_ctx_t* server_ctx, stream_ctx_t* stream_ctx)
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


stream_ctx_t * sample_server_create_stream_context_for_migration(app_ctx_t* server_ctx, uint64_t stream_id)
{
    stream_ctx_t* stream_ctx = (stream_ctx_t*)malloc(sizeof(stream_ctx_t));

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(stream_ctx_t));

        if (server_ctx->last_stream == NULL) {
            server_ctx->last_stream = stream_ctx;
            server_ctx->first_stream = stream_ctx;
        }
        else {
            stream_ctx->previous_stream = server_ctx->last_stream;
            server_ctx->last_stream->next_stream = stream_ctx;
            server_ctx->last_stream = stream_ctx;
        }
        stream_ctx->stream_id = stream_id;
    }

    return stream_ctx;
}

int stream_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    app_ctx_t* server_ctx= (app_ctx_t*)callback_ctx;
    stream_ctx_t* stream_ctx = (stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (app_ctx_t *)malloc(sizeof(app_ctx_t));
        if (server_ctx == NULL) {
            /* cannot handle the connection */
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
                stream_ctx = sample_server_create_stream_context_for_migration(server_ctx, stream_id);
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
                    sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
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
                        stream_ret = sample_server_open_stream_for_migration(server_ctx, stream_ctx);

                        if (stream_ret == 0) {
                            /* If data needs to be sent, set the context as active */
                            ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
                        }
                        else {
                            /* If the file could not be read, reset the stream */
                            sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                            (void) picoquic_reset_stream(cnx, stream_id, stream_ret);
                        }
                    }

                    if (server_ctx->server_flag) {
                        memcpy(server_ctx->file_name, stream_ctx->file_name, 256*sizeof(uint8_t));
                        server_ctx->migration_flag = 1;
                    }
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
                        sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                        (void)picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_READ_ERROR);
                        printf("reading file error\n"); 
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
                sample_server_delete_stream_context_for_migration(server_ctx, stream_ctx);
                picoquic_reset_stream(cnx, stream_id, PICOQUIC_SAMPLE_FILE_CANCEL_ERROR);
            }
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            sample_server_delete_context_for_migration(server_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
            break;
            // time to migrate
            
        case picoquic_callback_ready:
            break;
        default:
            /* unexpected */
            break;
        }
    }
    return ret;
}

void worker(void* worker_thread_attr) {
    worker_thread_attr_t* worker_attr = (worker_thread_attr_t*) worker_thread_attr;
    picoquic_quic_t* quic = worker_attr->quic;
    struct hashmap_s* cnx_id_table = worker_attr->cnx_id_table;
    int* trans_flag = worker_attr->trans_flag;
    trans_data_t trans_data = worker_attr->shared_data;
    pthread_cond_t* nonEmpty = worker_attr->nonEmpty;
    pthread_mutex_t* buffer_mutex = worker_attr->buffer_mutex;
    int server_port = worker_attr->server_port;

    worker_packet_loop(quic, worker_attr->id,cnx_id_table, trans_flag, trans_data,nonEmpty ,buffer_mutex ,server_port, 0, 0, NULL, NULL, worker_attr->id);
}



