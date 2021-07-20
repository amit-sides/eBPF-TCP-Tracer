#!/usr/bin/python
#
# tcpv4tracer   Trace TCP connections.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-v] [-p PID] [-N NETNS]
#
# You should generally try to avoid writing long scripts that measure multiple
# functions and walk multiple kernel structures, as they will be a burden to
# maintain as the kernel changes.
# The following code should be replaced, and simplified, when static TCP probes
# exist.
#
# Copyright 2017-2020 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
import time
import collections
from bcc import BPF

import argparse as ap
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

# define BPF program
bpf_program = """
/*Necessary header files*/
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define BUFF_SIZE (100)

/*Define the value in BPF_HASH*/
struct message_data_t {
    u32 pid;
    size_t length;
    char buff[BUFF_SIZE];
};


BPF_HASH(messages, struct message_data_t);


/*Detect the tcp_sendmsg function in the kernel */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    /*Get the pid of the current process*/
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    /*Get the socket type of the network protocol*/
    u16 family = sk->__sk_common.skc_family;

    /* Determine whether it is IPv4*/
    if (family == AF_INET) {
        struct message_data_t message_data = {.pid = pid};
        struct iovec *iov = (struct iovec *)msg->msg_iter.iov;
        
        bpf_probe_read(&message_data.length, sizeof(message_data.length), &iov->iov_len);

        u8 * temp_ptr;
        bpf_probe_read(&temp_ptr, sizeof(temp_ptr), &iov->iov_base);
        bpf_probe_read(&message_data.buff, sizeof(message_data.buff), temp_ptr);

        messages.increment(message_data, pid);
    }
    return 0;
}
"""

# init bpf
b = BPF(text=bpf_program)
messages = b["messages"]

print("Tracing TCP established connections. Ctrl-C to end.")

# output
exiting = False
while not exiting:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        exiting = True

    # IPv4: build dict of all seen keys
    for message, pid in messages.items():
        print("TCP Message Sent: PID: {} \tsize: {} \tdata: {}".format(message.pid, message.length, message.buff[:message.length]))
    messages.clear()

