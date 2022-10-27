#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "profile.h"
#include "lua_stacks_map.h"
#include "profile.skel.h"
extern "C"
{
#include "trace_helpers.h"
#include "uprobe_helpers.h"
}

#define warn(...) fprintf(stderr, __VA_ARGS__)

extern struct profile_env env;
extern class lua_stack_map lua_bt_map;

/* This structure combines key_t and count which should be sorted together */
struct key_ext_t
{
    struct stack_key k;
    __u64 v;
};

static int stack_id_err(int stack_id)
{
    return (stack_id < 0) && (stack_id != -EFAULT);
}

static int cmp_counts(const void *dx, const void *dy)
{
    __u64 x = ((struct key_ext_t *)dx)->v;
    __u64 y = ((struct key_ext_t *)dy)->v;
    return x > y ? -1 : !(x == y);
}

static bool batch_map_ops = true; /* hope for the best */

static bool read_batch_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
    void *in = NULL, *out;
    __u32 i, n, n_read = 0;
    int err = 0;
    __u32 vals[*count];
    struct stack_key keys[*count];

    while (n_read < *count && !err)
    {
        n = *count - n_read;
        err = bpf_map_lookup_batch(fd, &in, &out, keys + n_read,
                                   vals + n_read, &n, NULL);
        if (err && errno != ENOENT)
        {
            /* we want to propagate EINVAL upper, so that
             * the batch_map_ops flag is set to false */
            if (errno != EINVAL)
                warn("bpf_map_lookup_batch: %s\n",
                     strerror(-err));
            return false;
        }
        n_read += n;
        in = out;
    }

    for (i = 0; i < n_read; i++)
    {
        items[i].k.pid = keys[i].pid;
        items[i].k.kernel_ip = keys[i].kernel_ip;
        items[i].k.user_stack_id = keys[i].user_stack_id;
        items[i].k.kern_stack_id = keys[i].kern_stack_id;
        strncpy(items[i].k.name, keys[i].name, TASK_COMM_LEN);
        items[i].v = vals[i];
    }

    *count = n_read;
    return true;
}

static bool read_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
    struct stack_key empty = {};
    struct stack_key *lookup_key = &empty;
    int i = 0;
    int err;

    if (batch_map_ops)
    {
        bool ok = read_batch_counts_map(fd, items, count);
        if (!ok && errno == EINVAL)
        {
            /* fall back to a racy variant */
            batch_map_ops = false;
        }
        else
        {
            return ok;
        }
    }

    if (!items || !count || !*count)
        return true;

    while (!bpf_map_get_next_key(fd, lookup_key, &items[i].k))
    {

        err = bpf_map_lookup_elem(fd, &items[i].k, &items[i].v);
        if (err < 0)
        {
            fprintf(stderr, "failed to lookup counts: %d\n", err);
            return false;
        }
        if (items[i].v == 0)
            continue;

        lookup_key = &items[i].k;
        i++;
    }

    *count = i;
    return true;
}

static void print_fold_lua_func(const struct syms *syms, const struct lua_stack_event *eventp)
{
    if (!eventp)
    {
        return;
    }
    if (eventp->type == FUNC_TYPE_LUA)
    {
        if (eventp->ffid)
        {
            printf(";L:%s:%d", eventp->name, eventp->ffid);
        }
        else
        {
            printf(";L:%s", eventp->name);
        }
    }
    else if (eventp->type == FUNC_TYPE_C)
    {
        const struct sym *sym = syms__map_addr(syms, (unsigned long)eventp->funcp);
        if (sym)
        {
            printf(";C:%s", sym ? sym->name : "[unknown]");
        }
    }
    else if (eventp->type == FUNC_TYPE_F)
    {
        printf(";builtin#%d", eventp->ffid);
    }
    else
    {
        printf(";[unknown]");
    }
}

static void print_fold_user_stack_with_lua(const lua_stack_backtrace *lua_bt, const struct syms *syms, unsigned long *uip, unsigned int nr_uip)
{
    const struct sym *sym = NULL;
    int lua_bt_count = lua_bt->size() - 1;
    for (int j = nr_uip - 1; j >= 0; j--)
    {
        sym = syms__map_addr(syms, uip[j]);
        if (sym)
        {
            if (!env.lua_user_stacks_only)
            {
                printf(";%s", sym->name);
            }
        }
        else
        {
            if (lua_bt_count >= 0)
            {
                print_fold_lua_func(syms, &((*lua_bt)[lua_bt_count]));
                lua_bt_count--;
            }
        }
    }
    while (lua_bt_count >= 0)
    {
        print_fold_lua_func(syms, &((*lua_bt)[lua_bt_count]));
        lua_bt_count--;
    }
}

void print_stack_trace(struct ksyms *ksyms, struct syms_cache *syms_cache,
                       struct profile_bpf *obj)
{
    const struct ksym *ksym;
    const struct syms *syms = NULL;
    const struct sym *sym;
    int cfd, sfd;
    lua_stack_backtrace lua_bt = {};
    __u32 nr_count;
    struct stack_key *k;
    __u64 v;
    unsigned long *kip;
    unsigned long *uip;
    bool has_collision = false;
    unsigned int missing_stacks = 0;
    struct key_ext_t counts[MAX_ENTRIES];
    unsigned int nr_kip;
    unsigned int nr_uip;
    int idx = 0;

    /* add 1 for kernel_ip */
    kip = (unsigned long *)calloc(env.perf_max_stack_depth + 1, sizeof(*kip));
    if (!kip)
    {
        fprintf(stderr, "failed to alloc kernel ip\n");
        return;
    }

    uip = (unsigned long *)calloc(env.perf_max_stack_depth, sizeof(*uip));
    if (!uip)
    {
        fprintf(stderr, "failed to alloc user ip\n");
        return;
    }

    cfd = bpf_map__fd(obj->maps.counts);
    sfd = bpf_map__fd(obj->maps.stackmap);

    nr_count = MAX_ENTRIES;
    if (!read_counts_map(cfd, counts, &nr_count))
    {
        goto cleanup;
    }

    qsort(counts, nr_count, sizeof(counts[0]), cmp_counts);

    for (std::size_t i = 0; i < nr_count; i++)
    {
        k = &counts[i].k;
        v = counts[i].v;
        nr_uip = 0;
        nr_kip = 0;
        idx = 0;

        if (!env.user_stacks_only && stack_id_err(k->kern_stack_id))
        {
            missing_stacks += 1;
            has_collision |= (k->kern_stack_id == -EEXIST);
        }
        if (!env.kernel_stacks_only && stack_id_err(k->user_stack_id))
        {
            missing_stacks += 1;
            has_collision |= (k->user_stack_id == -EEXIST);
        }

        if (!env.kernel_stacks_only && k->user_stack_id >= 0)
        {
            if (bpf_map_lookup_elem(sfd, &k->user_stack_id, uip) == 0)
            {
                /* count the number of ips */
                while (nr_uip < env.perf_max_stack_depth && uip[nr_uip])
                    nr_uip++;
                syms = syms_cache__get_syms(syms_cache, k->pid);
            }
            int stack_level = lua_bt_map.get_lua_stack_backtrace(k->user_stack_id, &lua_bt);
            if (env.lua_user_stacks_only && env.folded)
            {
                if (stack_level <= 0)
                {
                    // if show lua user stack only, then we do not count the stack if it is not lua stack
                    continue;
                }
            }
        }

        if (!env.user_stacks_only && k->kern_stack_id >= 0)
        {
            if (k->kernel_ip)
                kip[nr_kip++] = k->kernel_ip;
            if (bpf_map_lookup_elem(sfd, &k->kern_stack_id, kip + nr_kip) == 0)
            {
                /* count the number of ips */
                while (nr_kip < env.perf_max_stack_depth && kip[nr_kip])
                    nr_kip++;
            }
        }

        if (env.folded)
        {
            // print folded stack output
            printf("%s", k->name);

            if (!env.kernel_stacks_only)
            {
                if (stack_id_err(k->user_stack_id))
                    printf(";[Missed User Stack]");
                if (syms)
                {
                    if (!env.disable_lua_user_trace)
                    {
                        print_fold_user_stack_with_lua(&lua_bt, syms, uip, nr_uip);
                    }
                    else
                    {
                        const struct sym *sym = NULL;
                        for (int j = nr_uip - 1; j >= 0; j--)
                        {
                            sym = syms__map_addr(syms, uip[j]);
                            printf(";%s", sym ? sym->name : "[unknown]");
                        }
                    }
                }
            }
            if (!env.user_stacks_only)
            {
                if (env.delimiter && k->user_stack_id >= 0 &&
                    k->kern_stack_id >= 0)
                    printf(";-");

                if (stack_id_err(k->kern_stack_id))
                    printf(";[Missed Kernel Stack]");
                for (std::size_t j = nr_kip - 1; j >= 0; j--)
                {
                    ksym = ksyms__map_addr(ksyms, kip[j]);
                    printf(";%s", ksym ? ksym->name : "[unknown]");
                }
            }
            printf(" %lld\n", v);
        }
        else
        {
            // print default multi-line stack output
            if (!env.user_stacks_only)
            {
                if (stack_id_err(k->kern_stack_id))
                    printf("    [Missed Kernel Stack]\n");
                for (std::size_t j = 0; j < nr_kip; j++)
                {
                    ksym = ksyms__map_addr(ksyms, kip[j]);
                    if (ksym)
                        printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, kip[j], ksym->name, kip[j] - ksym->addr);
                    else
                        printf("    #%-2d 0x%lx [unknown]\n", idx++, kip[j]);
                }
            }

            if (!env.kernel_stacks_only)
            {
                if (env.delimiter && k->kern_stack_id >= 0 &&
                    k->user_stack_id >= 0)
                    printf("    --\n");

                if (stack_id_err(k->user_stack_id))
                    printf("    [Missed User Stack]\n");
                if (!syms)
                {
                    for (std::size_t j = 0; j < nr_uip; j++)
                        printf("    #%-2d 0x%016lx [unknown]\n", idx++, uip[j]);
                }
                else
                {
                    for (std::size_t j = 0; j < nr_uip; j++)
                    {
                        char *dso_name;
                        uint64_t dso_offset;
                        sym = syms__map_addr_dso(syms, uip[j], &dso_name, &dso_offset);

                        printf("    #%-2d 0x%016lx", idx++, uip[j]);
                        if (sym)
                            printf(" %s+0x%lx", sym->name, sym->offset);
                        if (dso_name)
                            printf(" (%s+0x%lx)", dso_name, dso_offset);
                        printf("\n");
                    }
                }
            }

            printf("    %-16s %s (%d)\n", "-", k->name, k->pid);
            printf("        %lld\n\n", v);
        }
    }

    if (missing_stacks > 0)
    {
        fprintf(stderr, "WARNING: %d stack traces could not be displayed.%s\n",
                missing_stacks, has_collision ? " Consider increasing --stack-storage-size." : "");
    }

cleanup:
    free(kip);
    free(uip);
}
