---
title: Developer Guide
---

<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

## Overview

This documentation explains how to develop this project.

## Prerequisites

You may need `clang`, `libelf` and `zlib` to build the project, package names may vary across distros.

On `Ubuntu/Debian`, you need:

```sh
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On `CentOS/Fedora`, you need:

```sh
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## How it works

First, the eBPF program use `uprobe`  to attach to `libluajit.so` get the `lua_State` pointer:

bpftools/profile_nginx_lua/profile.bpf.c
```c
static int probe_entry_lua(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct lua_stack_event event = {};

	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	event.pid = pid;
	event.L = (void *)PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&lua_events, &tid, &event, BPF_ANY);
	return 0;
}
```

To get stack frame of lua, it uses a loop to backtrace the lua vm stack and find all information of functions, see the `fix_lua_stack` function:

```c
	cTValue *frame, *nextframe, *bot = tvref(BPF_PROBE_READ_USER(L, stack)) + LJ_FR2;
	int i = 0;
	frame = nextframe = BPF_PROBE_READ_USER(L, base) - 1;
	/* Traverse frames backwards. */
	// for the ebpf verifier insns (limit 1000000), we need to limit the max loop times to 15
	for (; i < 15 && frame > bot; i++)
	{
		if (frame_gc(frame) == obj2gco(L))
		{
			level++; /* Skip dummy frames. See lj_err_optype_call(). */
		}
		if (level-- == 0)
		{
			level++;
			/* Level found. */
			if (lua_get_funcdata(ctx, frame, eventp, count) != 0)
			{
				continue;
			}
			count++;
		}
		nextframe = frame;
		if (frame_islua(frame))
		{
			frame = frame_prevl(frame);
		}
		else
		{
			if (frame_isvarg(frame))
				level++; /* Skip vararg pseudo-frame. */
			frame = frame_prevd(frame);
		}
	}
```

After that, it gets the function data and send the backtrace to user space:

```c
static inline int lua_get_funcdata(struct bpf_perf_event_data *ctx, cTValue *frame, struct lua_stack_event *eventp, int level)
{
	if (!frame)
		return -1;
	GCfunc *fn = frame_func(frame);
	if (!fn)
		return -1;
	if (isluafunc(fn))
	{
		eventp->type = FUNC_TYPE_LUA;
		GCproto *pt = funcproto(fn);
		if (!pt)
			return -1;
		eventp->ffid = BPF_PROBE_READ_USER(pt, firstline);
		GCstr *name = proto_chunkname(pt); /* GCstr *name */
		const char *src = strdata(name);
		if (!src)
			return -1;
		bpf_probe_read_user_str(eventp->name, sizeof(eventp->name), src);
		bpf_printk("level= %d, fn_name=%s\n", level, eventp->name);
	}
	else if (iscfunc(fn))
	{
		eventp->type = FUNC_TYPE_C;
		eventp->funcp = BPF_PROBE_READ_USER(fn, c.f);
	}
	else if (isffunc(fn))
	{
		eventp->type = FUNC_TYPE_F;
		eventp->ffid = BPF_PROBE_READ_USER(fn, c.ffid);
	}
	eventp->level = level;
	bpf_perf_event_output(ctx, &lua_event_output, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));
	return 0;
}
```

In user space, it will use the `user_stack_id` to mix the lua stack with the original user and kernel stack:

bpftools/profile_nginx_lua/profile.c: print_fold_user_stack_with_lua
```c
				const struct lua_stack_event* eventp = &(lua_bt->stack[count]);
				if (eventp->type == FUNC_TYPE_LUA)
				{
					if (eventp->ffid) {
						printf(";L:%s:%d", eventp->name, eventp->ffid);
					} else {
						printf(";L:%s", eventp->name);
					}
				}
				else if (eventp->type == FUNC_TYPE_C)
				{
					sym = syms__map_addr(syms, (unsigned long)eventp->funcp);
					if (sym)
					{
						printf(";C:%s", sym ? sym->name : "[unknown]");
					}
				}
				else if (eventp->type == FUNC_TYPE_F)
				{
					printf(";builtin#%d", eventp->ffid);
				}
```

If the lua stack output `user_stack_id` matches the original `user_stack_id`, this means the stack is a lua stack. Then, the program replace the `[unknown]` function whose uip insides the luajit vm function range with our lua stack. This may not be totally correct, but it works for now. After printing the stack, you may use the [FlameGraph](https://github.com/brendangregg/FlameGraph) tool to generate the flame graph for `APISIX`.

## Test

Run `make test` in the test directory.
