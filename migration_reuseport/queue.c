#include "migration_reuseport.h" 


context_pipe_t* create_cnx_pipe() {
    context_pipe_t* p = (context_pipe_t*) malloc(sizeof(context_pipe_t)); 
    p->first_cnx = NULL; 
    p->last_cnx = NULL; 
    return p; 
}

cnx_node_t* create_cnx_node(picoquic_cnx_t* cnx) {
    cnx_node_t* n = (cnx_node_t*) malloc(sizeof(cnx_node_t)); 
    n->cnx = cnx; 
    n->next = NULL; 
    return n; 
}

int is_pipe_empty(context_pipe_t* p) {
    return (p->first_cnx == NULL); 
}

void enqueue_cnx(context_pipe_t* p, picoquic_cnx_t* cnx) {
    cnx_node_t* node = create_cnx_node(cnx); 
    if (p->last_cnx == NULL) {
        p->first_cnx = p->last_cnx = node; 
        return; 
    }
    p->last_cnx->next = node; 
    p->last_cnx = node; 
}

picoquic_cnx_t* dequeue_cnx(context_pipe_t* p) {
    if (is_pipe_empty(p)) {
        return; 
    }
    cnx_node_t* first_node = p->first_cnx; 
    p->first_cnx = first_node->next; 

    if (p->first_cnx == NULL) {
        p->last_cnx = NULL; 
    }

    picoquic_cnx_t* cnx = first_node->cnx;  
    free(first_node); 
    return cnx; 
}

