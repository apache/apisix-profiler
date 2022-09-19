#ifndef STACK_PRINTER_H
#define STACK_PRINTER_H

void print_stack_trace(struct ksyms *ksyms, struct syms_cache *syms_cache,
                       struct profile_bpf *obj);

#endif
