#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "suev.h"

#define SUEV_ASSERT(stmt) \
    do { \
        if (!(stmt)) { \
            riscv_raise_exception(env,RISCV_EXCP_ILLEGAL_INST,GETPC()); \
        } \
    } while(0)
#define SUEV_VM_ASSERT(stmt) \
    do { \
        if(!(stmt)) { \
            riscv_raise_exception(env,RISCV_EXCP_VIRT_INSTRUCTION_FAULT,GETPC()); \
        } \
    } while(0)

struct guest_ctx suev_vms[SUEV_ASID_END];
uint64_t suev_last_gen = 10;

static const char empty_page[4096];

void helper_rmpupdate(CPURISCVState *env, target_ulong spa, target_ulong rmpe_attr)
{
#ifndef CONFIG_USER_ONLY
    union rmpe_attr input_attr = {.bits = rmpe_attr};

    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                !(spa & 4095UL) &&
                spa < RMP_COVERED_END(env) &&
                !(input_attr.bits & ~(
                    /* These fields are only allowed as input */
                    RMPE_TYPE_MASK |
                    RMPE_ASID_MASK |
                    RMPE_GPN_MASK
                )));

    if (input_attr.type == RMPE_LEAF
            || input_attr.type == RMPE_SHARED) {
        SUEV_ASSERT(!(input_attr.bits & ~RMPE_TYPE_MASK));
    }

    struct rmpe rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, spa), &rmpe, sizeof(rmpe));

    if (suev_vms[input_attr.asid].gen != rmpe.gen
            || (rmpe.attr.type != RMPE_SHARED
                && input_attr.type == RMPE_SHARED)) {
        cpu_physical_memory_write(spa, empty_page, 4096);
    }

    bool set_gen;
    if (input_attr.type == RMPE_PRIVATE || input_attr.type == RMPE_MERGEABLE) {
        set_gen = true;
    } else {
        set_gen = false;
    }
    rmpe = (struct rmpe) {
        .attr = {
            .validated = 0,
            .fixed = 0,
            .type = input_attr.type,
            .asid = input_attr.asid,
            .gpn = input_attr.gpn,
        },
        .gen = set_gen ? suev_vms[input_attr.asid].gen : 0,
    };
    cpu_physical_memory_write(RMPE_ADDR(env, spa), &rmpe, sizeof(rmpe));

    tlb_flush(env_cpu(env));
#endif
}

void helper_vmcreate(CPURISCVState *env, target_ulong asid) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                asid < SUEV_ASID_END &&
                suev_vms[asid].state == GUEST_STATE_INIT);
    suev_vms[asid].gen = ++suev_last_gen;
    suev_vms[asid].state = GUEST_STATE_CREATED;
#endif
}

void helper_vmactivate(CPURISCVState *env, target_ulong asid) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                asid < SUEV_ASID_END &&
                suev_vms[asid].state == GUEST_STATE_CREATED);
    suev_vms[asid].state = GUEST_STATE_ACTIVATED;
#endif
}

void helper_vmdestroy(CPURISCVState *env, target_ulong asid) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                asid < SUEV_ASID_END &&
                suev_vms[asid].state == GUEST_STATE_ACTIVATED);
    suev_vms[asid].state = GUEST_STATE_INIT;
#endif
}

void helper_vmupdatedata(CPURISCVState *env, target_ulong dest_paddr,
                         target_ulong src_paddr, target_ulong len) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                !(dest_paddr & 4095UL) &&
                dest_paddr < RMP_COVERED_END(env) &&
                !(src_paddr & 4095UL) &&
                !(len & 4095UL));

    while (true) {
        struct rmpe dest_rmpe;
        cpu_physical_memory_read(RMPE_ADDR(env, dest_paddr), &dest_rmpe, sizeof(dest_rmpe));
        SUEV_ASSERT(suev_vms[dest_rmpe.attr.asid].state == GUEST_STATE_CREATED &&
                    suev_vms[dest_rmpe.attr.asid].gen == dest_rmpe.gen);

        char buf[4096];
        // TODO: handle invalid memory R/W
        cpu_physical_memory_read(src_paddr, buf, 4096);
        cpu_physical_memory_write(dest_paddr, buf, 4096);

        dest_rmpe.attr.validated = 1;
        cpu_physical_memory_write(RMPE_ADDR(env, dest_paddr), &dest_rmpe, sizeof(dest_rmpe));

        len -= 4096;
        if (len == 0) {
            break;
        }
        src_paddr += 4096;
        dest_paddr += 4096;
    }
#endif
}

void helper_pvalidate(CPURISCVState *env, target_ulong rmpe_attr) {
#ifndef CONFIG_USER_ONLY
    SUEV_VM_ASSERT(env->virt_enabled &&
                   env->hrmplen &&
                   !(rmpe_attr & ~(
                        /* These fields are only allowed as input */
                        RMPE_VALIDATED_MASK |
                        RMPE_TYPE_MASK |
                        RMPE_GPN_MASK /* guest _virtual_ page number */
                    )));
    uint64_t gpa, hpa;
    int ret;
    int prot;
    int mmu_idx = cpu_mmu_index(env, false);

    /* attr.gpn is guest _virtual_ page number here */
    union rmpe_attr input_attr = {.bits = rmpe_attr};

    uint64_t confidentiality;
    ret = get_physical_address(env, &gpa, &prot, input_attr.gpn << 12,
                                NULL, MMU_DATA_LOAD,
                                mmu_idx, true, true, false, &confidentiality);
    if (ret != TRANSLATE_SUCCESS) {
        SUEV_VM_ASSERT(false);
    }
    ret = get_physical_address(env, &hpa, &prot, gpa,
                                NULL, MMU_DATA_LOAD,
                                MMUIdx_U, false, true, false, NULL);
    if (ret != TRANSLATE_SUCCESS) {
        SUEV_VM_ASSERT(false);
    }
    uint64_t asid = get_field(env->hgatp, SATP64_ASID);
    struct rmpe rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, hpa), &rmpe, sizeof(rmpe));
    SUEV_VM_ASSERT(rmpe.attr.validated == input_attr.validated &&
                   !rmpe.attr.fixed &&
                   rmpe.attr.type == input_attr.type &&
                   (rmpe.attr.gpn << 12) == gpa &&
                   rmpe.gen == suev_vms[asid].gen);
    // TODO allow fixed
    rmpe.attr.validated = !rmpe.attr.validated;
    cpu_physical_memory_write(RMPE_ADDR(env, hpa), &rmpe, sizeof(rmpe));

    tlb_flush(env_cpu(env));
#endif
}

void helper_pfix(CPURISCVState *env, target_ulong hpa, target_ulong leaf_hpa) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                !(hpa & 4095UL) &&
                hpa < RMP_COVERED_END(env) &&
                !(leaf_hpa & 4095UL) &&
                leaf_hpa < RMP_COVERED_END(env));

    struct rmpe rmpe_for_leaf;
    cpu_physical_memory_read(RMPE_ADDR(env, leaf_hpa), &rmpe_for_leaf,
                             sizeof(rmpe_for_leaf));
    SUEV_ASSERT(rmpe_for_leaf.attr.type == RMPE_LEAF);

    struct rmpe rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, hpa), &rmpe, sizeof(rmpe));
    SUEV_ASSERT(rmpe.attr.type == RMPE_MERGEABLE &&
                !rmpe.attr.fixed &&
                rmpe.attr.validated);

    struct rmpe rmple = {
        .attr = {
            .validated = 1,
            .gpn = rmpe.attr.gpn,
        },
        .gen = rmpe.gen,
    };

    uint64_t rmple_addr = leaf_hpa + rmpe.attr.asid * sizeof(struct rmpe);

    rmpe = (struct rmpe) {
        .attr = {
            .validated = 1, /* unchanged */
            .fixed = 1,
            .type = RMPE_MERGEABLE, /* unchanged */
            .asid = 0,
            .gpn = leaf_hpa >> 12,
        },
        .gen = 0,
    };

    cpu_physical_memory_write(leaf_hpa, empty_page, 4096);
    cpu_physical_memory_write(rmple_addr, &rmple, sizeof(rmple));
    cpu_physical_memory_write(RMPE_ADDR(env, hpa), &rmpe, sizeof(rmpe));

    tlb_flush(env_cpu(env));
#endif
}

void helper_punfix(CPURISCVState *env, target_ulong hpa, target_ulong asid) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                !(hpa & 4095UL) &&
                hpa < RMP_COVERED_END(env) &&
                asid < SUEV_ASID_END);
    struct rmpe rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, hpa), &rmpe, sizeof(rmpe));
    SUEV_ASSERT(rmpe.attr.validated &&
                rmpe.attr.type == RMPE_MERGEABLE &&
                rmpe.attr.fixed);

    struct rmpe rmple;
    uint64_t rmple_addr = (rmpe.attr.gpn << 12) + asid * sizeof(struct rmpe);
    cpu_physical_memory_read(rmple_addr, &rmple, sizeof(rmple));
    SUEV_ASSERT(rmpe.attr.validated);

    rmpe = (struct rmpe) {
        .attr = {
            .validated = 1, /* unchanged */
            .fixed = 0,
            .type = RMPE_MERGEABLE, /* unchanged */
            .asid = asid,
            .gpn = rmple.attr.gpn,
        },
        .gen = rmple.gen,
    };

    cpu_physical_memory_write(RMPE_ADDR(env, hpa), &rmpe, sizeof(rmpe));

    tlb_flush(env_cpu(env));

    /* RMPE for RMP leaf is left unmodified */
#endif
}

void helper_pmerge(CPURISCVState *env, target_ulong dst_hpa,
                   target_ulong src_hpa) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                !(dst_hpa & 4095UL) &&
                dst_hpa < RMP_COVERED_END(env) &&
                !(src_hpa & 4095UL) &&
                src_hpa < RMP_COVERED_END(env));

    struct rmpe dst_rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, dst_hpa), &dst_rmpe,
                             sizeof(dst_rmpe));
    SUEV_ASSERT(dst_rmpe.attr.type == RMPE_MERGEABLE &&
                dst_rmpe.attr.fixed &&
                dst_rmpe.attr.validated);

    struct rmpe src_rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, src_hpa), &src_rmpe,
                             sizeof(src_rmpe));
    SUEV_ASSERT(src_rmpe.attr.type == RMPE_MERGEABLE &&
                !src_rmpe.attr.fixed &&
                src_rmpe.attr.validated);

    char dst_page[4096], src_page[4096];
    cpu_physical_memory_read(dst_hpa, dst_page, 4096);
    cpu_physical_memory_read(src_hpa, src_page, 4096);
    SUEV_ASSERT(!memcmp(dst_page, src_page, 4096));

    struct rmpe rmple = {
        .attr = {
            .gpn = src_rmpe.attr.gpn,
            /* Validated means Present here */
            .validated = 1,
        },
        .gen = src_rmpe.gen,
    };

    /* dst_rmpe.attr.gpn is pointer to RMP leaf */
    uint64_t rmple_addr = (dst_rmpe.attr.gpn << 12) +
                          src_rmpe.attr.asid * sizeof(struct rmpe);
    cpu_physical_memory_write(rmple_addr, &rmple, sizeof(rmple));
    src_rmpe = (struct rmpe){0};
    cpu_physical_memory_write(RMPE_ADDR(env, src_hpa), &src_rmpe,
                              sizeof(src_rmpe));
    cpu_physical_memory_write(src_hpa, empty_page, 4096);

    tlb_flush(env_cpu(env));
#endif
}

void helper_punmerge(CPURISCVState *env, target_ulong dst_hpa,
                     target_ulong src_hpa, target_ulong asid) {
#ifndef CONFIG_USER_ONLY
    SUEV_ASSERT(env->priv <= PRV_S &&
                !env->virt_enabled &&
                env->hrmplen &&
                !(dst_hpa & 4095UL) &&
                dst_hpa < RMP_COVERED_END(env) &&
                !(src_hpa & 4095UL) &&
                src_hpa < RMP_COVERED_END(env) &&
                asid < SUEV_ASID_END);

    /* No checks for destination RMPE */

    struct rmpe src_rmpe;
    cpu_physical_memory_read(RMPE_ADDR(env, src_hpa), &src_rmpe,
                             sizeof(src_rmpe));
    SUEV_ASSERT(src_rmpe.attr.validated &&
                src_rmpe.attr.fixed &&
                src_rmpe.attr.type == RMPE_MERGEABLE);

    struct rmpe rmple;
    uint64_t rmple_addr = (src_rmpe.attr.gpn << 12) +
                          asid * sizeof(struct rmpe);
    cpu_physical_memory_read(rmple_addr, &rmple, sizeof(rmple));
    SUEV_ASSERT(rmple.attr.validated);

    struct rmpe dst_rmpe = {
        .attr = {
            .validated = 1,
            .fixed = 0,
            .type = RMPE_MERGEABLE,
            .asid = asid,
            .gpn = rmple.attr.gpn,
        },
        .gen = rmple.gen,
    };
    rmple = (struct rmpe){0};

    cpu_physical_memory_write(rmple_addr, &rmple, sizeof(rmple));
    cpu_physical_memory_write(RMPE_ADDR(env, dst_hpa), &dst_rmpe,
                              sizeof(dst_rmpe));

    char buf[4096];
    cpu_physical_memory_read(src_hpa, buf, 4096);
    cpu_physical_memory_write(dst_hpa, buf, 4096);

    tlb_flush(env_cpu(env));
#endif
}
