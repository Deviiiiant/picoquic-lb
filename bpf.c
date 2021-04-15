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
	.key_size = sizeof(__u32),	        // packet identifier 
	.value_size = sizeof(__u32),			// socket index 
	.max_entries = 2048,
};

SEC("sec/mybpf")
int mybpf(struct sk_reuseport_md *reuse_md)
{
    // bpf_printk("hello\n");
    int port;  
    // load reuse_md 
    void *data, *data_end;

	data = reuse_md->data;
	data_end = reuse_md->data_end;

    // read src port 
    struct udphdr *uh = data;
    if (data_end < (void*) uh + sizeof(struct udphdr)) {
        bpf_printk("offset error\n"); 
    }
    else {
        // bpf_printk("source port is %d\n", uh->source);
        port = uh->source;
        // bpf_printk("source port is %d\n", data_check.skb_ports[0]);

        // bpf_printk("source port is %d\n", port);
        int* sock_index = bpf_map_lookup_elem(&cntmap, &port); 
        if (sock_index == NULL){
            int target = port % 4; 
            bpf_map_update_elem(&cntmap, &port, &target, BPF_ANY); 
            bpf_printk("port %d mod is %d\n", port, target); 
            sock_index = &target; 
        }
        else {
            bpf_printk("found index is %d\n", *sock_index); 
        }
        // test select 
        bpf_sk_select_reuseport(reuse_md, &sockmap, sock_index, 0);
    }
    return 0 ? SK_DROP : SK_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
