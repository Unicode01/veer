#include "../../../plugins/include/veer_plugin_helpers.h"
extern __u32 veer_kfuncs_wan_v1(void) __attribute__((section(".ksyms")));
SEC("tc") int veer_kfuncs_probe(struct __sk_buff *skb) {
 return veer_kfuncs_wan_v1();
}
char SEC("license") LICENSE[] = "GPL";
