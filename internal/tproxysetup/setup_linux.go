//go:build linux

package tproxysetup

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

const (
	tproxyTable = "198"
	tproxyMark  = "0x1/0x1"
)

var (
	transparentSetupDone bool
	transparentSetupMu   sync.Mutex
)

func EnsureRouting() {
	transparentSetupMu.Lock()
	defer transparentSetupMu.Unlock()
	if transparentSetupDone {
		return
	}

	if !ipRuleExists() {
		if err := runCmd("ip", "rule", "add", "fwmark", tproxyMark, "lookup", tproxyTable); err != nil {
			log.Printf("transparent: ip rule add: %v", err)
		} else {
			log.Printf("transparent: added ip rule fwmark -> table %s", tproxyTable)
		}
	}

	if err := runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyTable); err != nil {
		log.Printf("transparent: ip route replace: %v", err)
	} else {
		log.Printf("transparent: local route in table %s ready", tproxyTable)
	}

	ensureIptablesRule("tcp")
	ensureIptablesRule("udp")

	transparentSetupDone = true
	log.Println("transparent: routing setup complete")
}

func CleanupRouting() {
	transparentSetupMu.Lock()
	defer transparentSetupMu.Unlock()
	if !transparentSetupDone {
		return
	}

	removeIptablesRule("tcp")
	removeIptablesRule("udp")

	_ = runCmd("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyTable)
	_ = runCmd("ip", "rule", "del", "fwmark", tproxyMark, "lookup", tproxyTable)

	transparentSetupDone = false
	log.Println("transparent: routing cleanup complete")
}

func ipRuleExists() bool {
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "fwmark") && strings.Contains(line, tproxyMark) && strings.Contains(line, "lookup "+tproxyTable) {
			return true
		}
	}
	return false
}

func ensureIptablesRule(proto string) {
	err := exec.Command("iptables", "-t", "mangle", "-C", "PREROUTING",
		"-p", proto, "-m", "socket", "--transparent",
		"-j", "MARK", "--set-mark", tproxyMark).Run()
	if err == nil {
		return
	}
	if err := runCmd("iptables", "-t", "mangle", "-A", "PREROUTING",
		"-p", proto, "-m", "socket", "--transparent",
		"-j", "MARK", "--set-mark", tproxyMark); err != nil {
		log.Printf("transparent: iptables %s rule: %v", proto, err)
	} else {
		log.Printf("transparent: added iptables mangle PREROUTING %s rule", proto)
	}
}

func removeIptablesRule(proto string) {
	_ = exec.Command("iptables", "-t", "mangle", "-D", "PREROUTING",
		"-p", proto, "-m", "socket", "--transparent",
		"-j", "MARK", "--set-mark", tproxyMark).Run()
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
