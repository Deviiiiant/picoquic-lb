
#include "migration.h"


int dispatcher_packet_loop(picoquic_quic_t* quic,
    picoquic_quic_t** worker_quic,
    struct hashmap_s* cnx_id_table,
    int** trans_flag,
    trans_data_dispatcher_t shared_data,
    pthread_cond_t* nonEmpty,
    pthread_mutex_t* buffer_mutex,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{

    int** trans_bytes= shared_data.trans_bytes;
    uint8_t** trans_buffer = shared_data.trans_buffer;
    unsigned char** trans_received_ecn = shared_data.trans_received_ecn;
    struct sockaddr_storage** trans_addr_to = shared_data.trans_addr_to;
    struct sockaddr_storage** trans_addr_from = shared_data.trans_addr_from;
    int** trans_if_index_to = shared_data.trans_if_index_to;
    int** trans_socket_rank= shared_data.trans_socket_rank;
    uint64_t** trans_current_time = shared_data.trans_current_time;
    SOCKET_TYPE** trans_s_socket = shared_data.trans_s_socket;

    int** trans_sock_af = shared_data.trans_sock_af;
    int** trans_nb_sockets = shared_data.trans_nb_sockets;
    pthread_mutex_t* socket_mutex = shared_data.socket_mutex;

    int server_number = 0;
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
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }
    // printf("ret is %d\n", ret);
    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
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


                // before the incoming packet function we need to check the packet.
                // if the src port is in the hashmap we need to just continue

                picoquic_cnx_t * connection_to_migrate = quic->cnx_list;
                if (connection_to_migrate != NULL && connection_to_migrate->callback_ctx!=NULL) {
                    char* key_string = malloc(128 * sizeof(char));
                    memset(key_string, '0', 128);
                    // printf("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n");
                    if (((app_ctx_t *) (connection_to_migrate->callback_ctx))->migration_flag){
                        ((app_ctx_t *) (connection_to_migrate->callback_ctx))->migration_flag = 0;
                        int * target_server = malloc(sizeof(int));
                        switch (LB_MODE)
                        {
                        case ROUND_LB:
                        {
                            server_number = (server_number + 1) % CORE_NUMBER;
                            *target_server = server_number;
                            /* code */
                            break;
                        }   
                        case FILE_LB:
                        {
                            uint8_t* file_name = ((app_ctx_t *)(connection_to_migrate->callback_ctx))->file_name;
                            // printf("File name is %s\n", (char *)file_name);
                            // printf("Name length is %ld\n", strlen((char *)file_name));
                            *target_server = atoi((char *)file_name);
                            break;
                        }
                        default:
                            *target_server = 0;
                            break;
                        }
                        printf("first migrated to the back-up server %d!!\n", *target_server);
                        picoquic_shallow_migrate(quic, worker_quic[*target_server]);
                        picoquic_addr_text((struct sockaddr *)&connection_to_migrate->path[0]->peer_addr, key_string, 128);
                        if (cnx_id_table != NULL) {
                            hashmap_put(cnx_id_table, key_string, 128, (void *)target_server);
                        } else {
                        }
                        *trans_flag[server_number] =1;
                    }
                }

                /*trigger connection migration across slaves when receiving any incoming packet
                1. modify the hashmap 
                2. migrate connection state and callback context 
                */
                char* key = malloc(128 * sizeof(char));
                memset(key, '0', 128);
                picoquic_addr_text((struct sockaddr *)&addr_from, key, 128);
                if (hashmap_get(cnx_id_table, key, 128) != NULL) {
                    // locate the target server and direct to the next server 
                    void* const element = hashmap_get(cnx_id_table, key, 128);
                    int target_server_number = *((int *) element);
                    int next_target_server_number = (target_server_number + 1) % CORE_NUMBER; 
                    hashmap_put(cnx_id_table, key, 128, (void*) &next_target_server_number); 
                    // migrate connection context 
                    picoquic_shallow_migrate(worker_quic[target_server_number], worker_quic[next_target_server_number]); 
                    
                }


                // check whether it belongs to this server
                if (hashmap_get(cnx_id_table, key, 128) != NULL) {
                    void* const element = hashmap_get(cnx_id_table, key, 128);
                    int target_server_number = *((int *) element);
                    free(key);
                    pthread_mutex_lock(&buffer_mutex[target_server_number]);
                    *trans_bytes[target_server_number] = bytes_recv;
                    *trans_received_ecn[target_server_number] = received_ecn;
                    *trans_current_time[target_server_number] = current_time;
                    *trans_socket_rank[target_server_number] = socket_rank;
                    *trans_if_index_to[target_server_number] = if_index_to;
                    memcpy(trans_addr_to[target_server_number], &addr_to, sizeof(struct sockaddr_storage));
                    memcpy(trans_addr_from[target_server_number], &addr_from, sizeof(struct sockaddr_storage)); 
                    memcpy(trans_sock_af[target_server_number], sock_af, sizeof(sock_af));
                    memcpy(trans_s_socket[target_server_number], s_socket, sizeof(s_socket));
                    *trans_nb_sockets[target_server_number] = nb_sockets;
                    memcpy(trans_buffer[target_server_number], buffer, sizeof(buffer));
                    // then trigger the backup thread and return.
                    pthread_cond_signal(&nonEmpty[target_server_number]);
                    pthread_mutex_unlock(&buffer_mutex[target_server_number]);
                    continue;
                }
                /* Submit the packet to the server */
                ret = picoquic_incoming_packet(quic, buffer,
                (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                current_time);
                
                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
            
                
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;
                // once the migration is done call quic = worker_quic
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
                        pthread_mutex_unlock(socket_mutex);
                        printf("dispatcher is sending %d bytes\n", sock_ret); 
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
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

void dispatcher(void* dispatcher_thread_attr) {
    dispatcher_thread_attr_t* dispatcher_attr = (dispatcher_thread_attr_t*) dispatcher_thread_attr;

    picoquic_quic_t* quic = dispatcher_attr->quic;
    picoquic_quic_t** worker_quic = dispatcher_attr->worker_quic;
    struct hashmap_s* cnx_id_table = dispatcher_attr->cnx_id_table;
    int** trans_flag = dispatcher_attr->trans_flag;
    trans_data_dispatcher_t trans_data = dispatcher_attr->shared_data;
    pthread_cond_t* nonEmpty = dispatcher_attr->nonEmpty;
    pthread_mutex_t* buffer_mutex = dispatcher_attr->buffer_mutex;
    int server_port = dispatcher_attr->server_port;


    dispatcher_packet_loop(quic, worker_quic, cnx_id_table, trans_flag, trans_data ,nonEmpty ,buffer_mutex,server_port, 0, 0, NULL, NULL); 


}

