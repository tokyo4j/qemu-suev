#ifndef QEMU_SUEV_H
#define QEMU_SUEV_H

#include <stdint.h>

#define RMPE_SHARED 0
#define RMPE_PRIVATE 1
#define RMPE_MERGEABLE 2
#define RMPE_LEAF 3

// for pvalidate, asid must be zero
#define SUEV_ASID_END 256

/* For RMPE leaf, only gPA, VALIDATED and gen are effective */
union rmpe_attr {
  struct {
    uint64_t validated : 1;
    uint64_t fixed : 1;
    uint64_t type : 2;
    uint64_t asid : 8;
    uint64_t gpn : 44;
    uint64_t : 8;
  };
  uint64_t bits;
};

#define RMPE_VALIDATED_MASK 0x0000000000000001UL
#define RMPE_FIXED_MASK     0x0000000000000002UL
#define RMPE_TYPE_MASK      0x000000000000000cUL
#define RMPE_ASID_MASK      0x0000000000000ff0UL
#define RMPE_GPN_MASK       0x00fffffffffff000UL

struct rmpe {
  union rmpe_attr attr;
  uint64_t gen;
};

#ifdef NEED_CPU_H // when included from QEMU

#define RMP_COVERED_END(env) ((env)->hrmplen/sizeof(struct rmpe)*4096)
#define RMPE_ADDR(env, spa) ((env)->hrmpbase+(spa)/4096*sizeof(struct rmpe))

struct guest_ctx {
    uint64_t gen;
    enum {
        GUEST_STATE_INIT,
        GUEST_STATE_CREATED,
        GUEST_STATE_ACTIVATED,
    } state;
};

extern struct guest_ctx suev_vms[SUEV_ASID_END];
extern uint64_t suev_last_gen;

#endif

#endif