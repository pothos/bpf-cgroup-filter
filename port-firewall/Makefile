# Always recompile because the variable might have changed
BPFNAME ?= port-firewall
all: compile load cleanup

.PHONY: compile
compile:
ifeq ($(FILTER),)
	@printf "To configure which packets to forward invoke as:\n  FILTER=… make\nor\n  make FILTER=…\n"
	@printf "With FILTER being a valid C expression over the boolean variables [udp, tcp, icmp, ip, ipv6]\n"
	@printf "and the integers [dst_port, src_port], e.g.:\n"
	@printf "  FILTER='icmp || (udp && dst_port == 53) || (tcp && dst_port == 80)'\n"
	@printf "  FILTER='!udp || dst_port == 53'\n"
	@exit 1
endif
	clang -O2 -Wall -target bpf -c port-firewall.c -o '${BPFNAME}.o' -D "FILTER=${FILTER}"

.PHONY: load
load:
	@which bpftool || ( echo "Install bpftool as package or compile and copy it to your PATH: cd linux-source-x.xx/tools/bpf/bpftool ; make bpftool ; cp bpftool ~/.local/bin/"; exit 1 )
	sudo sh -c "rm '/sys/fs/bpf/${BPFNAME}' || true"
	sudo `which bpftool` prog load '${BPFNAME}.o' '/sys/fs/bpf/${BPFNAME}' type cgroup/skb
	@echo "Success"
	@echo 'Now use it with Systemd v243 and the option IP(Ingress|Egress)FilterPath= or attach it manually to a cgroup with:'
	@echo "  sudo `which bpftool` cgroup attach /sys/fs/cgroup/unified/… ingress|egress pinned '/sys/fs/bpf/${BPFNAME}' multi"
	@echo 'You can make a new cgroup with "sudo systemd-run --scope -S" or "systemd-run --user --scope -S" (-S can be replaced with a command)'

.PHONY: cleanup
cleanup:
	rm '${BPFNAME}.o'

.PHONY: remove
remove:
	sudo rm '/sys/fs/bpf/${BPFNAME}'
