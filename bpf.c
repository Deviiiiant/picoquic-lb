#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>  

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 64);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} sockmap SEC(".maps");

struct bpf_map_def SEC("maps") cntmap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),	        // packet identifier 
	.value_size = sizeof(int),			// socket index 
	.max_entries = 2048,
};

struct bpf_map_def SEC("maps") core_number_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(int),	        // packet identifier 
	.value_size = sizeof(int),			// socket index 
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") rb_counter_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),	        // packet identifier 
	.value_size = sizeof(int),			// socket index 
	.max_entries = 1,
};



int rb_counter = 0; 

SEC("sec/mybpf")
int mybpf(struct sk_reuseport_md *reuse_md)
{
    __be16 port;  
    void *data, *data_end;
	data = reuse_md->data;
	data_end = reuse_md->data_end;

    unsigned int one = 1; 
    int* core_number = bpf_map_lookup_elem(&core_number_map, &one); 

    if (core_number == NULL) {
        return 0; 
    }
    unsigned int mod = *core_number; 

    // round-robin block 
    int* rb_counter_p = bpf_map_lookup_elem(&rb_counter_map, &one); 
    if (rb_counter_p == NULL) {
        return 0; 
    }
    int rb_counter = *rb_counter_p; 

    // read src port 
    struct udphdr *uh = data;
    if (data_end < (void*) uh + sizeof(struct udphdr)) {
        bpf_printk("offset error\n"); 
    }
    else {


        port = uh->source;
        int res =  (int) __be16_to_cpu(port); 
        int* sock_index = bpf_map_lookup_elem(&cntmap, &res); 
        if (sock_index == NULL){

            // 1. hashing 
            // int target = port % mod; 
            // bpf_map_update_elem(&cntmap, &res, &target, BPF_ANY); 
            // sock_index = &target; 

            //2. round-robin 
            sock_index = &rb_counter; 
            rb_counter ++; 
            if (rb_counter == mod) rb_counter = 0; 
            bpf_map_update_elem(&cntmap, &res, &rb_counter, BPF_ANY); 
            bpf_map_update_elem(&rb_counter_map, &one, &rb_counter, BPF_ANY); 
            bpf_printk("rb counter is %d, mod is %d\n", rb_counter, mod); 


            // 3. cpu affinity 
            // int cpu_id = bpf_get_smp_processor_id(); 
            // // server threads start from 8 
            // int server_index = cpu_id - 8; 
            // if (server_index < 0) {
            //     bpf_printk("something is wrong\n"); 
            // }
            // sock_index = &server_index; 
            // bpf_map_update_elem(&cntmap, &res, &cpu_id, BPF_ANY); 
        }

        bpf_sk_select_reuseport(reuse_md, &sockmap, sock_index, 0);
    }

    return 0 ? SK_DROP : SK_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
