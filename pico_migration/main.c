/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* The "sample" project builds a simple file transfer program that can be 
 * instantiated in client or server mode. The programe can be instantiated
 * as either:
 *    picoquic_sample client server_name port folder *queried_file
 * or:
 *    picoquic_sample server port cert_file private_key_file folder
 *
 * The client opens a quic connection to the server, and then fetches 
 * the listed files. The client opens one bidir client stream for each
 * file, writes the requested file name in the stream data, and then
 * marks the stream as finished. The server reads the file name, and
 * if the named file is present in the server's folder, sends the file
 * content on the same stream, marking the fin of the stream when all
 * bytes are sent. If the file is not available, the server resets the
 * stream. If the client receives the file, it writes its content in the
 * client's folder.
 *
 * Server or client close the connection if it remains inactive for
 * more than 10 seconds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "migration.h"
#include <pthread.h>
#include "hashmap.h"
#include <picoquic.h>

int picoquic_sample_server_test_migration(int server_port, const char* server_cert, const char* server_key, const char* default_dir) {
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_quic_t* quic_back_server[CORE_NUMBER] = {NULL};
    char const* qlog_dir = PICOQUIC_SAMPLE_SERVER_QLOG_DIR;
    uint64_t current_time = 0;

    pthread_mutex_t buffer_mutex_global[CORE_NUMBER] = {PTHREAD_MUTEX_INITIALIZER};
    pthread_mutex_t socket_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t nonEmpty_global[CORE_NUMBER] = {PTHREAD_COND_INITIALIZER};
    int* trans_flag[CORE_NUMBER] = {NULL};
    int* trans_bytes[CORE_NUMBER] = {NULL};
    uint8_t* trans_buffer[CORE_NUMBER] = {NULL};
    uint8_t* trans_send_buffer[CORE_NUMBER] = {NULL};
    struct sockaddr_storage* trans_addr_to[CORE_NUMBER] = {NULL};
    struct sockaddr_storage* trans_addr_from[CORE_NUMBER] = {NULL};
    struct sockaddr_storage* trans_peer_addr[CORE_NUMBER] = {NULL};
    struct sockaddr_storage* trans_local_addr[CORE_NUMBER] = {NULL};
    int* trans_s_socket[CORE_NUMBER] = {NULL};
    int* trans_sock_af[CORE_NUMBER] = {NULL};
    int* trans_nb_sockets[CORE_NUMBER] = {NULL};
    int* trans_if_index_to[CORE_NUMBER] = {NULL};
    int* trans_socket_rank[CORE_NUMBER] = {NULL};
    uint64_t* trans_current_time[CORE_NUMBER] = {NULL};
    unsigned char* trans_received_ecn[CORE_NUMBER] = {NULL};
    slave_thread_para_t* slave_para[CORE_NUMBER] = {NULL};

    struct hashmap_s hashmap;
    if (0 != hashmap_create(32, &hashmap)) {
        printf("create hashmap wrong!\n");
    }
    struct hashmap_s * cnx_id_table = &hashmap;

    current_time = picoquic_current_time();
    for (size_t i = 0; i < CORE_NUMBER; i++){
        // buffer_mutex_global[i] = PTHREAD_MUTEX_INITIALIZER;
        // nonEmpty_global[i]  = PTHREAD_COND_INITIALIZER;
        trans_flag[i] = malloc(sizeof(int));
        trans_bytes[i] = malloc(sizeof(int));
        trans_buffer[i] = malloc(1536 * sizeof(uint8_t));
        trans_send_buffer[i] = malloc(1536 * sizeof(uint8_t));
        trans_addr_to[i] = malloc(sizeof(struct sockaddr_storage));
        trans_addr_from[i] = malloc(sizeof(struct sockaddr_storage));
        trans_peer_addr[i] = malloc(sizeof(struct sockaddr_storage));
        trans_local_addr[i] = malloc(sizeof(struct sockaddr_storage));
        trans_s_socket[i] = malloc(2 * sizeof(int));
        trans_sock_af[i] = malloc(2 * sizeof(int));
        trans_nb_sockets[i] = malloc(sizeof(int));
        trans_if_index_to[i] = malloc(sizeof(int));
        trans_socket_rank[i] = malloc(sizeof(int));
        trans_current_time[i] = malloc(sizeof(uint64_t));
        trans_received_ecn[i] = malloc(sizeof(unsigned char));

        sample_server_migration_ctx_t* default_context = malloc(sizeof(sample_server_migration_ctx_t));
        default_context->default_dir = default_dir;
        default_context->default_dir_len = strlen(default_dir);
        default_context->migration_flag = 0;
        default_context->server_flag = 0;
        quic_back_server[i] = picoquic_create_id(i+1,8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_migration_callback, default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

        slave_para[i] = malloc(sizeof(slave_thread_para_t));
        slave_para[i]->id = i;
        slave_para[i]->quic = quic_back_server[i];
        slave_para[i]->cnx_id_table = cnx_id_table;
        slave_para[i]->trans_flag = trans_flag[i];
        slave_para[i]->shared_data.trans_buffer = trans_buffer[i];
        slave_para[i]->shared_data.trans_send_buffer = trans_send_buffer[i];
        slave_para[i]->shared_data.trans_bytes = trans_bytes[i];
        slave_para[i]->shared_data.trans_received_ecn = trans_received_ecn[i];
        slave_para[i]->shared_data.trans_addr_to = trans_addr_to[i];
        slave_para[i]->shared_data.trans_addr_from = trans_addr_from[i];
        slave_para[i]->shared_data.trans_peer_addr = trans_peer_addr[i];
        slave_para[i]->shared_data.trans_local_addr = trans_local_addr[i];
        slave_para[i]->shared_data.trans_if_index_to = trans_if_index_to[i];
        slave_para[i]->shared_data.trans_current_time = trans_current_time[i];
        slave_para[i]->shared_data.trans_socket_rank = trans_socket_rank[i];
        slave_para[i]->shared_data.trans_s_socket = trans_s_socket[i];
        slave_para[i]->shared_data.trans_sock_af = trans_sock_af[i];
        slave_para[i]->shared_data.trans_nb_sockets = trans_nb_sockets[i];
        slave_para[i]->nonEmpty = &nonEmpty_global[i];
        slave_para[i]->buffer_mutex = &buffer_mutex_global[i];
        slave_para[i]->server_port = server_port;
        slave_para[i]->shared_data.socket_mutex = &socket_mutex;


        if (quic_back_server[i] == NULL) {
            fprintf(stderr, "Could not create server context\n");
            ret = -1;
        }
        else {
            picoquic_set_cookie_mode(quic_back_server[i], 2);

            picoquic_set_default_congestion_algorithm(quic_back_server[i], picoquic_bbr_algorithm);

            picoquic_set_qlog(quic_back_server[i], qlog_dir);

            picoquic_set_log_level(quic_back_server[i], 1);

            picoquic_set_key_log_file_from_env(quic_back_server[i]);
            
            printf("Build server 2 OK\n");
        }
        /* code */
    }

    sample_server_migration_ctx_t default_migration_context = { 0 };
    default_migration_context.default_dir = default_dir;
    default_migration_context.default_dir_len = strlen(default_dir);
    default_migration_context.server_back = quic;
    default_migration_context.migration_flag = 0;
    default_migration_context.server_flag = 1;

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        sample_server_migration_callback, &default_migration_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        ret = -1;
    }
    else {
        picoquic_set_cookie_mode(quic, 2);

        picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

        // picoquic_set_qlog(quic, qlog_dir);

        picoquic_set_log_level(quic, 1);

        picoquic_set_key_log_file_from_env(quic);

        printf("Build server 1 OK\n");
    }

    if (ret == 0) {
        
        // picohash_table* cnx_id_table = picohash_create((size_t)8 * 4, picoquic_cnx_id_hash, picoquic_cnx_id_compare);
        // free(cnx_id_table);
        // ret = picoquic_packet_loop(quic, server_port, 0, 0, NULL, NULL);
        // ret = picoquic_packet_loop_with_migration_master(quic, quic_back, cnx_id_table, trans_flag, trans_buffer ,nonEmpty ,server_port, 0, 0, NULL, NULL);
        // if migration finished we should use picoquic_packet_loop(q_back......)
        pthread_t thread[CORE_NUMBER+1];

        // strcpy(source,"hello world!");
        // buflen = strlen(source);
        /* create 2 threads*/
        /*
        pthread_create(&thread[2], NULL, (void *)watch, &thread_id[2]);
        */
        /* create one consumer and one producer */
        master_thread_para_t* master_para = malloc(sizeof(master_thread_para_t));
        master_para->quic = quic;
        master_para->quic_back = quic_back_server;
        master_para->cnx_id_table = cnx_id_table;
        master_para->trans_flag = trans_flag;
        master_para->shared_data.trans_buffer = trans_buffer;
        master_para->shared_data.trans_send_buffer = trans_send_buffer;
        master_para->shared_data.trans_bytes = trans_bytes;
        master_para->shared_data.trans_received_ecn = trans_received_ecn;
        master_para->shared_data.trans_addr_to = trans_addr_to;
        master_para->shared_data.trans_addr_from = trans_addr_from;
        master_para->shared_data.trans_peer_addr = trans_peer_addr;
        master_para->shared_data.trans_local_addr = trans_local_addr;
        master_para->shared_data.trans_if_index_to = trans_if_index_to;
        master_para->shared_data.trans_current_time = trans_current_time;
        master_para->shared_data.trans_socket_rank = trans_socket_rank;
        master_para->shared_data.trans_s_socket = trans_s_socket;
        master_para->shared_data.trans_sock_af = trans_sock_af;
        master_para->shared_data.trans_nb_sockets = trans_nb_sockets;
        master_para->nonEmpty = nonEmpty_global;
        master_para->buffer_mutex = buffer_mutex_global;
        master_para->shared_data.socket_mutex = &socket_mutex;
        master_para->server_port = server_port;
        
        for (size_t i = 0; i < CORE_NUMBER; i++)
        {
            /* code */
            pthread_create(&thread[i], NULL, (void *)slave, slave_para[i]);
        }
        
        pthread_create(&thread[CORE_NUMBER], NULL, (void *)master, master_para);

        for(int i = 0; i<CORE_NUMBER+1 ; i++)
        {
            pthread_join(thread[i], NULL);
        }
    }
    printf("Server exit, ret = %d\n", ret);

    if (quic != NULL) {
        picoquic_free(quic);
    }

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
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc < 2) {
        usage(argv[0]);
    }
    else if (strcmp(argv[1], "client") == 0) {
        if (argc < 6) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[3]);
            char const** file_names = (char const **)(argv + 5);
            int nb_files = argc - 5;

            //exit_code = picoquic_sample_client(argv[2], server_port, argv[4], nb_files, file_names);
        }
    }
    else if (strcmp(argv[1], "server") == 0) {
        if (argc < 5) {
            usage(argv[0]);
        }
        else {
            int server_port = get_port(argv[0], argv[2]);
            exit_code = picoquic_sample_server_test_migration(server_port, argv[3], argv[4], argv[5]);
        }
    }
    else
    {
        usage(argv[0]);
    }

    exit(exit_code);
}

