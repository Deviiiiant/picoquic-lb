
#include "migration.h"


int picoquic_shallow_migrate(picoquic_quic_t* old_server, picoquic_quic_t* new_server) {
    int ret = 0;
    // printf("time to migrate!\n");
    //pick a connection to migrate
    picoquic_cnx_t* connection_to_migrate = NULL;
    //need to be changed in the future, for now just get one connection!
    connection_to_migrate = old_server->cnx_list;
    if(connection_to_migrate == NULL) {
        printf("OMMMMMMMMMMMMMMMMG\n");
    }
    picoquic_remove_cnx_from_list(connection_to_migrate);
    picoquic_remove_cnx_from_wake_list(connection_to_migrate);
    //copy the data from the connection!
    connection_to_migrate->quic = new_server;
    picoquic_insert_cnx_in_list(new_server, connection_to_migrate);
    // update the wake time
    connection_to_migrate->next_wake_time = picoquic_get_quic_time(new_server);
    picoquic_insert_cnx_by_wake_time(new_server, connection_to_migrate);
    picoquic_local_cnxid_t* l_cid = connection_to_migrate->local_cnxid_first;

    picoquic_register_cnx_id(new_server, connection_to_migrate, l_cid);

/* Register or update default address and reset secret */
    // picoquic_register_net_secret(cnx);
    picoquic_register_net_icid(connection_to_migrate);
    // printf("shallow copy finished here\n");
    return ret;
}

void master_packet_loop (picoquic_quic_t* quic,
    picoquic_quic_t** quic_back,
    struct hashmap_s* cnx_id_table,
    int** trans_flag,
    trans_data_master_t shared_data,
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

    int server_number = 0;
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    int bytes_recv;
    int nb_loops = 0;
    SOCKET_TYPE s_socket[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */

    memset(sock_af, 0, sizeof(sock_af));

    // open sockets 
    if ((nb_sockets = picoquic_packet_loop_open_sockets(local_port, local_af, s_socket, sock_af, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }

    while (ret == 0) { 

        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        // select sockets 
        bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &socket_rank, &current_time);

        nb_loops++;
        if (nb_loops >= 100) {

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
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

                picoquic_cnx_t * connection_to_migrate = quic->cnx_list;

                if (connection_to_migrate != NULL && connection_to_migrate->callback_ctx!=NULL) {
                    char* key_string = malloc(128 * sizeof(char));
                    memset(key_string, '0', 128);
                    if (((sample_server_migration_ctx_t *) (connection_to_migrate->callback_ctx))->migration_flag){
                        ((sample_server_migration_ctx_t *) (connection_to_migrate->callback_ctx))->migration_flag = 0;
                        int * target_server = malloc(sizeof(int));
                        switch (LB_MODE)
                        {
                        case ROUND_LB:
                        {
                            server_number = (server_number + 1) % CORE_NUMBER;
                            *target_server = server_number;
                            break;
                        }   
                        case FILE_LB:
                        {
                            uint8_t* file_name = ((sample_server_migration_ctx_t *)(connection_to_migrate->callback_ctx))->file_name;
                            *target_server = atoi((char *)file_name);
                            break;
                        }
                        default:
                            *target_server = 0;
                            break;
                        }
                        picoquic_shallow_migrate(quic, quic_back[*target_server]);
                        picoquic_addr_text((struct sockaddr *)&connection_to_migrate->path[0]->peer_addr, key_string, 128);
                        if (cnx_id_table != NULL) {
                            hashmap_put(cnx_id_table, key_string, 128, (void *)target_server);
                        } 
                        *trans_flag[server_number] =1;
                    }
                }

                char* key = malloc(128 * sizeof(char));
                memset(key, '0', 128);
                picoquic_addr_text((struct sockaddr *)&addr_from, key, 128);
                if (hashmap_get(cnx_id_table, key, 128) != NULL) {
                    void* const element = hashmap_get(cnx_id_table, key, 128);
                    int target_server_number = *((int *) element);
                    free(key);
                    // master share data structure with slave 
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
                    pthread_cond_signal(&nonEmpty[target_server_number]);
                    pthread_mutex_unlock(&buffer_mutex[target_server_number]);
                }
                ret = picoquic_incoming_packet(quic, buffer,
                (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                current_time);
            }
        }
    }
}

void master(void* thread_para) {
    master_thread_para_t* thread_context = (master_thread_para_t*) thread_para;

    picoquic_quic_t* quic = thread_context->quic;
    picoquic_quic_t** quic_back = thread_context->quic_back;
    struct hashmap_s* cnx_id_table = thread_context->cnx_id_table;
    int** trans_flag = thread_context->trans_flag;
    trans_data_master_t trans_data = thread_context->shared_data;
    pthread_cond_t* nonEmpty = thread_context->nonEmpty;
    pthread_mutex_t* buffer_mutex = thread_context->buffer_mutex;
    int server_port = thread_context->server_port;

    printf("master is here!!!!!!!!!!!"); 

    master_packet_loop(quic, quic_back, cnx_id_table, trans_flag, trans_data,nonEmpty ,buffer_mutex,server_port, 0, 0, NULL, NULL); 

    printf("master quits!!!!!!!!!!!!!"); 

}

