#include "../../../plugins/include/veer_plugin_helpers.h"
#include "../../../plugins/include/veer_kfuncs.h"
SEC("tc") int veer_kfuncs_probe(struct __sk_buff *skb) {
 struct veer_handoff_v1 config = {};
 if (veer_skb_handoff_v1(skb, &config) != -22) return 0;
 return veer_kfuncs_abi_v1();
}
char SEC("license") LICENSE[] = "GPL";
