/*
 * Copyright 2019 Kai Lüke <kailueke@riseup.net>
 * SPDX-License-Identifier: GPL-2.0
 * Structure adapted from linux-source-4.19/samples/bpf/test_cgrp2_attach.c
 * authored by Daniel Mack, Sargun Dhillon, Joe Stringer, Alexei Starovoitov, and Jakub Kicinski
 *
 * Loads a BPF cgroup ingress/egress filter bytecode that filters based on the packet size.
 * It loads the BPF filter to a given location in /sys/fs/bpf/.
 * Through the +/- keys the MTU can be changed interactively (changes values in the BPF map).
 * Optionally the inital MTU value can be specified on startup.
 * The program can also attach the BPF filter to a cgroup by specifying the cgroup by its path.
 * The BPF filter stays loaded when the program exits and has to be deleted manually.
 *
 * The BPF filter is hardcoded below as BPF assembly instructions and does not use a BPF compiler.
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ncurses.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include "bpf_insn.h"

const int DEFAULT_MTU = 1500;

enum {
	MAP_KEY_PACKETS_DROPPED,
	MAP_KEY_PACKETS_FORWARDED,
	MAP_KEY_MTU,
};

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int prog_load(int map_fd)
{
	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1), /* r6 = skb */

		BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_MTU), /* (arg) r0 = mtu_key */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd), /* (arg r1) = fd */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(fp-4) = r0 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), /* r2 = fp */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* (arg) r2 -= 4 */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_MOV64_IMM(BPF_REG_7, 0), /* r7 = 0 (fallback mtu is 0) */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1), /* may be null, skip mtu read */
		BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 0), /* r7 = *r0 (i.e. mtu) */

		BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct __sk_buff, len)), /* r8 = *(r6+offset) (i.e. skb->len) */

		BPF_MOV64_IMM(BPF_REG_9, 1), /* r9 = 1 (forward decision) */
		BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_PACKETS_FORWARDED), /* r0 = forward_key */
		BPF_JMP_REG(BPF_JLE, BPF_REG_8, BPF_REG_7, 2), /* jmp to pc+2(update) if r8 <= r7 */
		BPF_MOV64_IMM(BPF_REG_9, 0), /* r9 = 0 (drop decision) */
		BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_PACKETS_DROPPED), /* r0 = drop_key */
		/* update: */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* (arg) r0 = forward/drop_key */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd), /* (arg r1) = fd */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(fp-4) = r0 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), /* r2 = fp */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* (arg) r2 -= 4 */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2), /* may be null, skip count write */
		BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
		BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */

		BPF_MOV64_REG(BPF_REG_0, BPF_REG_9), /* r0 = r9 (set forward/drop decision) */
		BPF_EXIT_INSN(),
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	return bpf_load_program(BPF_PROG_TYPE_CGROUP_SKB,
				prog, insns_cnt, "GPL", 0,
				bpf_log_buf, BPF_LOG_BUF_SIZE);
}

static int attach_filter(int cg_fd, int type, long long mtu, char* file)
{
	int prog_fd, map_fd, ret, key;
	long long pkt_cnt_dropped, pkt_cnt_forwarded;
	char input;
	struct timeval tv;
	fd_set fds;

	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY,
				sizeof(key), sizeof(pkt_cnt_dropped),
				256, 0);
	if (map_fd < 0) {
		printf("Failed to create map: '%s'\n", strerror(errno));
		return EXIT_FAILURE;
	}

	key = MAP_KEY_MTU;
	assert(bpf_map_update_elem(map_fd, &key, &mtu, BPF_EXIST) == 0);

	prog_fd = prog_load(map_fd);
	printf("Output from kernel verifier:\n%s\n-------\n", bpf_log_buf);

	if (prog_fd < 0) {
		printf("Failed to load prog: '%s'\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if (bpf_obj_pin(prog_fd, file)) {
		printf("Failed to pin prog to '%s': '%s'\n", file, strerror(errno));
		return EXIT_FAILURE;
	}

	if (cg_fd != -1) {
		/* allow multiple filters (invocation is ordered!) */
		ret = bpf_prog_attach(prog_fd, cg_fd, type, BPF_F_ALLOW_MULTI);
		if (ret < 0) {
			printf("Failed to attach prog to cgroup: '%s'\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}

	initscr();
	timeout(1000);
	noecho();

	while (1) {
		key = MAP_KEY_PACKETS_DROPPED;
		assert(bpf_map_lookup_elem(map_fd, &key, &pkt_cnt_dropped) == 0);

		key = MAP_KEY_PACKETS_FORWARDED;
		assert(bpf_map_lookup_elem(map_fd, &key, &pkt_cnt_forwarded) == 0);

		key = MAP_KEY_MTU;
		assert(bpf_map_lookup_elem(map_fd, &key, &mtu) == 0);

		clear();
		printw("cgroup dropped %lld packets, forwarded %lld packets, MTU is %lld bytes (Press +/- to change)\n",
		       pkt_cnt_dropped, pkt_cnt_forwarded, mtu);

		input = getch();
		switch (input) {
		case '+':
			mtu += 50;
			if (mtu < 0)
				mtu = 0;
			key = MAP_KEY_MTU;
			assert(bpf_map_update_elem(map_fd, &key, &mtu, BPF_EXIST) == 0);
			break;
		case '-':
			mtu -= 50;
			if (mtu < 0)
				mtu = 0;
			key = MAP_KEY_MTU;
			assert(bpf_map_update_elem(map_fd, &key, &mtu, BPF_EXIST) == 0);
			break;
		default:
			break;
		}
	}

	return EXIT_SUCCESS;
}

static int usage(char *argv0)
{
	printf("Usage: %s [-m MTU] [-c <cg-path>] [-t <egress|ingress>] </sys/fs/bpf/new-bpffs-name>\n", argv0);
	printf("        -c PATH Attach program to control group in PATH (usually /sys/fs/cgroup/…)\n");
	printf("        -m MTU  Set MTU value (default %d)\n", DEFAULT_MTU);
	printf("	-t type Attach program as egress/ingress filter (default ingress)\n");
	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	int mtu = DEFAULT_MTU;
	enum bpf_attach_type type = BPF_CGROUP_INET_INGRESS;
	int opt, cg_fd = -1;

	while ((opt = getopt(argc, argv, "c:m:t:")) != -1) {
		switch (opt) {
		case 'c':
			cg_fd = open(optarg, O_DIRECTORY | O_RDONLY);
			if (cg_fd < 0) {
				printf("Failed to open cgroup path: '%s'\n", strerror(errno));
				return EXIT_FAILURE;
			}
			break;
		case 'm':
			mtu = atoi(optarg);
			if (mtu < 0)
				mtu = 0;
			break;
		case 't':
			if (strcmp(optarg, "ingress") == 0)
				type = BPF_CGROUP_INET_INGRESS;
			else if (strcmp(optarg, "egress") == 0)
				type = BPF_CGROUP_INET_EGRESS;
			else
				return usage(argv[0]);
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (argc - optind < 1)
		return usage(argv[0]);

	return attach_filter(cg_fd, type, mtu, argv[optind]);
}
