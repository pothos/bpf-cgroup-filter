# Examples for cgroup socket ingress/egress BPF filters with systemd

These are examples for my [blogpost about custom BPF firewalls for systemd services](https://kailueke.gitlab.io/systemd-custom-bpf-firewall/)
that I implemented in [this commit](https://github.com/systemd/systemd/commit/fab347489fcfafbc8367c86afc637ce1b81ae59e).
You can find more explanations and examples on how to use it when reading the blog post.

## Update: Port-based BPF firewall compiled with clang

The [port-firewall folder](port-firewall/) contains a
small configurable packet filter that parses IP/IPv6 packets, ICMP, UDP ports,
and TCP ports.
The forward rule is a C expression passed as `FILTER` variable
to the compiler with `-D`.

The expression can use the boolean variables `udp`, `tcp`, `icmp`, `ip`, and `ipv6` denoting the packet type and the the integers `dst_port` and `src_port` for the UDP/TCP ports.
If the expression evaluates to 0 (false), the packet will be dropped.
Valid filters examples are `FILTER='icmp || (udp && dst_port == 53) || (tcp && dst_port == 80)'` or `FILTER='!udp || dst_port == 53'`.

The makefile requires to pass the filter to build the program: `make FILTER='…'`.
With `make load` the bytecode is loaded to `/sys/fs/bpf/port-firewall` as pinned BPF program in the special BPF filesystem.

From there you can use it with the systemd options `IP(Ingress|Egress)FilterPath=` or attach
it manually to a cgroup.

The [folder](port-firewall/) also includes a `bpf-make.service` systemd unit file to configure and load the firewall
and an example `my-filtered-ping.service` file that uses the loaded firewall.
It includes an workaround you can use to not require systemd v243.

The next section shows how to load and use a simple dropping filter as template for your own filters if you don't want to use this one.

## Simple dropping filter compiled with clang

In the [bpf-program-only folder](bpf-program-only/) is a
minimal BPF cgroup filter dropping all packets.
You can build it with `make` and then run
`make load` to `/sys/fs/bpf/cgroup-sock-drop`.
This will load it with `bpftool` to
`/sys/fs/bpf/cgroup-sock-drop`.

You can use this to specify an `IPIngressFilterPath` or `IPEgressFilterPath`
for systemd services (>= 243).
Here an example with ping running in a temporary systemd system scope (or service)
with an ingress filter but no egress filter. You can also use user scopes without `sudo` by passing `--user`.

```
$ sudo systemd-run -p IPIngressFilterPath=/sys/fs/bpf/cgroup-sock-drop --scope ping 127.0.0.1
Running scope as unit: run-re62ba1c….scope
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
^C # cancel since it will not get responses
--- 127.0.0.1 ping statistics ---
8 packets transmitted, 0 received, 100% packet loss, time 186ms
```

You can also find the example service `my-ping.service` configured with a filter
that is loaded from its dependency service `cgroup-sock-drop-filter.service` (please note
the `LimitMEMLOCK=infinity` entry in the unit that load the filter). When you want to use
it for your service to start at boot you need to add, e.g.,
`After=network.target` and an `[Install]` section with `WantedBy=multi-user.target`.

Until systemd 243 is released you can also try the interactive MTU filter program from the next section below which has an option to attach the filter to a cgroup.

### Workaround when systemd 243 is not available
Use `systemd-run` to spawn a shell in a new cgroup either as system scope or user scope (a temporary service). `-S` can be replaced with a concrete binary if you don't want to start a shell.

```
$ sudo systemd-run --scope -S
$ # or:
$ systemd-run --user --scope -S
Running scope as unit: run-r63de6b74621b4ae3877d4fa86b54be75.scope
```

This will print out the unit name which is also the name of the cgroup. The full cgroup path for the system service shell is `/sys/fs/cgroup/unified/system.slice/NAME`. For the user service shell the path is `/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/NAME` depening on your UID not being `1000`.

Then attach the BPF program to the cgroup:

```
$ sudo $(which bpftool) cgroup attach /sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/run-rfaa93ac79de2482d8ef1870fd6b508cd.scope egress pinned /sys/fs/bpf/cgroup-sock-drop multi
```

You can either choose `ingress` or `egress` to filter incoming or outgoing packets. You can load the same filter for both `ingress` and `egrees` and you can load multiple different filters per `ingress`/`egress` (which also true when used through the systemd v243 option above).
If you turn on `IPAccounting` in `systemd-run` you need to turn on `Delegate` as well to allow multiple BPF programs.

## Interactive MTU filter

In the [standalone folder](standalone/) is an interactive program
that loads a BPF filter and controls its behavior.

_From the source code comment:_
Loads a BPF cgroup ingress/egress filter bytecode that filters based on the packet size.
It loads the BPF filter to a given location in `/sys/fs/bpf/`.
Through the +/- keys the MTU can be changed interactively (changes values in the BPF map).
Optionally the initial MTU value can be specified on startup.
The program can also attach the BPF filter to a cgroup by specifying the cgroup by its path.
The BPF filter stays loaded when the program exits and has to be deleted manually.

It does not use a BPF compiler but uses hardcoded BPF assembly instructions
to include the BPF code in the final program. Not very accessible for hacking
but for me it was interesting to see how BPF instructions work
and what needs to be done to comply with the verifier.

### With systemd >= 243
In one terminal you can run the interactive filter:

```
$ sudo ./load_and_control_filter -m 100 -t ingress /sys/fs/bpf/ingressfilter
cgroup dropped 0 packets, forwarded 0 packets, MTU is 100 bytes (Press +/- to change)
… # keeps running
```

It loaded the BPF filter to `/sys/fs/bpf/ingressfilter` which you can use for a
systemd service.

In another terminal you can, for example, again run ping as root in a temporary
systemd scope and specify our filter as `IPIngressFilterPath`:

```
$ sudo systemd-run -p IPIngressFilterPath=/sys/fs/bpf/ingressfilter --scope ping 127.0.0.1
Running scope as unit: run-….scope
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.086 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.069 ms
…
```

When you switch back to the first terminal and press `-`, the new MTU is 50 bytes
and you can see the dropped packet count increase.
In the ping terminal you will see no new responses because they are all dropped.

### Workaround when systemd 243 is not available

The `load_and_control_filter` program can be told to attach the filter to a cgroup
of a systemd service.

Systemd uses a BPF filter for its IP accounting and firewalling based on IP addresses.
If such a filter is present but no others, the flag to allow multiple BPF filters for a cgroup is missing.
As workaround when, e.g., IP accounting is enabled, you can tell systemd that the cgroup management is done by externally.
This means that systemd will use the flag to allow multiple BPF filters instead of loading the
IP accounting BPF filter without this flag.

```
$ sudo systemd-run -p IPAccounting=yes -p Delegate=yes --scope ping 127.0.0.1
Running scope as unit: run-r9f31b3947f4c4a11a24babf5517fe025.scope
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.086 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.069 ms
…
```

You can see the scope name in the first output line.
This is also the last part of the cgroup path you have to use as argument
in order to attach the filter to the cgroup.

```
$ sudo ./load_and_control_filter -m 100 -c /sys/fs/cgroup/unified/system.slice/run-r9f31b3947f4c4a11a24babf5517fe025.scope -t ingress /sys/fs/bpf/myfilter
cgroup dropped 0 packets, forwarded 4 packets, MTU is 100 bytes (Press +/- to change)
… # keeps running and increases the forward count
```

Now hit `-` to reduce the MTU and observe the packet drop count increasing while no ping responses can be seen.
