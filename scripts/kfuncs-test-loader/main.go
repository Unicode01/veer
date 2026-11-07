//go:build linux

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type settings struct {
	Object, Program, Map string
	Interfaces           []string
	EgressInterfaces     []string
	Entries              []struct{ Key, Value string }
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: kfuncs-test-loader CONFIG.json")
	}
	var c settings
	f, e := os.ReadFile(os.Args[1])
	if e != nil {
		return e
	}
	if e = json.Unmarshal(f, &c); e != nil {
		return e
	}
	_ = rlimit.RemoveMemlock()
	s, e := ebpf.LoadCollectionSpec(c.Object)
	if e != nil {
		return e
	}
	coll, e := ebpf.NewCollection(s)
	if e != nil {
		return e
	}
	defer coll.Close()
	if coll.Programs[c.Program] == nil || coll.Maps[c.Map] == nil {
		return fmt.Errorf("program or map missing from object")
	}
	for _, v := range c.Entries {
		k, e := hex.DecodeString(v.Key)
		if e != nil {
			return e
		}
		val, e := hex.DecodeString(v.Value)
		if e != nil {
			return e
		}
		if e = coll.Maps[c.Map].Put(k, val); e != nil {
			return e
		}
	}
	for _, name := range append(append([]string{}, c.Interfaces...), c.EgressInterfaces...) {
		link, e := netlink.LinkByName(name)
		if e != nil {
			return e
		}
		a := netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}
		q := &netlink.GenericQdisc{QdiscAttrs: a, QdiscType: "clsact"}
		if e = netlink.QdiscReplace(q); e != nil {
			return e
		}
		parent := uint32(netlink.HANDLE_MIN_INGRESS)
		for _, egress := range c.EgressInterfaces {
			if name == egress {
				parent = netlink.HANDLE_MIN_EGRESS
			}
		}
		filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: parent, Priority: 10, Protocol: unix.ETH_P_ALL}, Fd: coll.Programs[c.Program].FD(), Name: "veer-kfunc-test", DirectAction: true}
		if e = netlink.FilterReplace(filter); e != nil {
			return e
		}
		defer netlink.FilterDel(filter)
	}
	fmt.Println("READY")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
	return nil
}
