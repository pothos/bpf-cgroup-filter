cgroup-sock-drop.o: cgroup-sock-drop.c
	clang -O2 -S -Wall -target bpf -c cgroup-sock-drop.c -o cgroup-sock-drop.S
	llvm-mc -triple bpf -filetype=obj -o cgroup-sock-drop.o cgroup-sock-drop.S

load:
	@which bpftool || ( echo "Install bpftool as package or compile and copy it to your PATH: cd linux-source-x.xx/tools/bpf/bpftool ; cd make bpftool ; cp bpftool ~/.local/bin/"; exit 1 )
	sudo sh -c "rm /sys/fs/bpf/cgroup-sock-drop || true"
	sudo `which bpftool` prog load cgroup-sock-drop.o /sys/fs/bpf/cgroup-sock-drop type cgroup/skb
	@echo "Success"
