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
#include "picoquic.h"

int test_migration(int server_port, const char* server_cert, const char* server_key, const char* default_dir) {
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_quic_t* worker_quic[CORE_NUMBER] = {NULL};
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
    worker_thread_attr_t* worker_attrs[CORE_NUMBER] = {NULL}; 

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

        app_ctx_t* default_context = malloc(sizeof(app_ctx_t));
        default_context->default_dir = default_dir;
        default_context->default_dir_len = strlen(default_dir);
        default_context->migration_flag = 0;
        default_context->server_flag = 0;
        worker_quic[i] = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        stream_callback, default_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

        worker_attrs[i] = malloc(sizeof(worker_thread_attr_t));
        worker_attrs[i]->id = i;
        worker_attrs[i]->quic = worker_quic[i];
        worker_attrs[i]->cnx_id_table = cnx_id_table;
        worker_attrs[i]->trans_flag = trans_flag[i];
        worker_attrs[i]->shared_data.trans_buffer = trans_buffer[i];
        worker_attrs[i]->shared_data.trans_send_buffer = trans_send_buffer[i];
        worker_attrs[i]->shared_data.trans_bytes = trans_bytes[i];
        worker_attrs[i]->shared_data.trans_received_ecn = trans_received_ecn[i];
        worker_attrs[i]->shared_data.trans_addr_to = trans_addr_to[i];
        worker_attrs[i]->shared_data.trans_addr_from = trans_addr_from[i];
        worker_attrs[i]->shared_data.trans_peer_addr = trans_peer_addr[i];
        worker_attrs[i]->shared_data.trans_local_addr = trans_local_addr[i];
        worker_attrs[i]->shared_data.trans_if_index_to = trans_if_index_to[i];
        worker_attrs[i]->shared_data.trans_current_time = trans_current_time[i];
        worker_attrs[i]->shared_data.trans_socket_rank = trans_socket_rank[i];
        worker_attrs[i]->shared_data.trans_s_socket = trans_s_socket[i];
        worker_attrs[i]->shared_data.trans_sock_af = trans_sock_af[i];
        worker_attrs[i]->shared_data.trans_nb_sockets = trans_nb_sockets[i];
        worker_attrs[i]->nonEmpty = &nonEmpty_global[i];
        worker_attrs[i]->buffer_mutex = &buffer_mutex_global[i];
        worker_attrs[i]->server_port = server_port;
        worker_attrs[i]->shared_data.socket_mutex = &socket_mutex;


        if (worker_quic[i] == NULL) {
            fprintf(stderr, "Could not create server context\n");
            ret = -1;
        }
        else {
            picoquic_set_cookie_mode(worker_quic[i], 2);

            picoquic_set_default_congestion_algorithm(worker_quic[i], picoquic_bbr_algorithm);

            picoquic_set_qlog(worker_quic[i], qlog_dir);

            picoquic_set_log_level(worker_quic[i], 1);

            picoquic_set_key_log_file_from_env(worker_quic[i]);
            
            printf("Build slave 1 OK\n");
        }
        /* code */
    }

    app_ctx_t default_migration_context = { 0 };
    default_migration_context.default_dir = default_dir;
    default_migration_context.default_dir_len = strlen(default_dir);
    default_migration_context.server_back = quic;
    default_migration_context.migration_flag = 0;
    default_migration_context.server_flag = 1;

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create(8, server_cert, server_key, NULL, PICOQUIC_SAMPLE_ALPN,
        stream_callback, &default_migration_context, NULL, NULL, NULL, current_time, NULL, NULL, NULL, 0);

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

        printf("Build dispatcher OK\n");
    }

        
        pthread_t thread[CORE_NUMBER+1];
        /* create one consumer and one producer */
        dispatcher_thread_attr_t* dispatcher_attr = malloc(sizeof(dispatcher_thread_attr_t));
        dispatcher_attr->quic = quic;
        dispatcher_attr->quic_back = worker_quic;
        dispatcher_attr->cnx_id_table = cnx_id_table;
        dispatcher_attr->trans_flag = trans_flag;
        dispatcher_attr->shared_data.trans_buffer = trans_buffer;
        dispatcher_attr->shared_data.trans_send_buffer = trans_send_buffer;
        dispatcher_attr->shared_data.trans_bytes = trans_bytes;
        dispatcher_attr->shared_data.trans_received_ecn = trans_received_ecn;
        dispatcher_attr->shared_data.trans_addr_to = trans_addr_to;
        dispatcher_attr->shared_data.trans_addr_from = trans_addr_from;
        dispatcher_attr->shared_data.trans_peer_addr = trans_peer_addr;
        dispatcher_attr->shared_data.trans_local_addr = trans_local_addr;
        dispatcher_attr->shared_data.trans_if_index_to = trans_if_index_to;
        dispatcher_attr->shared_data.trans_current_time = trans_current_time;
        dispatcher_attr->shared_data.trans_socket_rank = trans_socket_rank;
        dispatcher_attr->shared_data.trans_s_socket = trans_s_socket;
        dispatcher_attr->shared_data.trans_sock_af = trans_sock_af;
        dispatcher_attr->shared_data.trans_nb_sockets = trans_nb_sockets;
        dispatcher_attr->nonEmpty = nonEmpty_global;
        dispatcher_attr->buffer_mutex = buffer_mutex_global;
        dispatcher_attr->shared_data.socket_mutex = &socket_mutex;
        dispatcher_attr->server_port = server_port;
        
        printf("configured thread paras\n");
        for (size_t i = 0; i < CORE_NUMBER; i++)
        {
            printf("creating worker thread\n"); 
            pthread_create(&thread[i], NULL, (void *)worker, worker_attrs[i]);
        }
        printf("creating dispatcher thread\n");
        pthread_create(&thread[CORE_NUMBER], NULL, (void *)dispatcher, dispatcher_attr);

        for(int i = 0; i < CORE_NUMBER+1 ; i++)
        {
            printf("threads join\n"); 
            pthread_join(thread[i], NULL);
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

