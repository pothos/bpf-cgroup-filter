# Examples for cgroup socket ingress/egress BPF filters with systemd

These are examples for my [blogpost about custom BPF firewalls for systemd services](https://kailueke.gitlab.io/systemd-custom-bpf-firewall/)
that I implemented in [this commit](https://github.com/systemd/systemd/commit/fab347489fcfafbc8367c86afc637ce1b81ae59e).
You can find more explanations and examples on how to use it when reading the blog post.

## Simple dropping filter compiled with clang

In the [bpf-program-only folder](bpf-program-only/) is a
minimal BPF cgroup filter dropping all packets.
You can build it with `make` and then run
`make load` to `/sys/fs/bpf/cgroup-sock-drop`.
This will load it with `bpftool` to
`/sys/fs/bpf/cgroup-sock-drop`.

You can use this to specify an `IPIngressFilterPath` or `IPEgressFilterPath`
for systemd services (>= 243).
Here an example with ping running as root in a temporary systemd scope (or service)
with an ingress filter but no egress filter.

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

Until systemd 243 is released you can try the below program which has an option to attach the filter to a cgroup.

## Interactive MTU filter

In the [standalone folder](standalone/) is an interactive program
that loads a BPF filter and controls its behavior.

_From the source code comment:_
Loads a BPF cgroup ingress/egress filter bytecode that filters based on the packet size.
It loads the BPF filter to a given location in /sys/fs/bpf/.
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
