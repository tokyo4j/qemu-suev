static bool trans_rmpupdate(DisasContext *ctx, arg_rmpupdate *a)
{
    decode_save_opc(ctx);
    TCGv hpa = get_gpr(ctx, 10, EXT_NONE); //a0
    TCGv rmpe_attrs = get_gpr(ctx, 11, EXT_NONE); //a1

    gen_helper_rmpupdate(cpu_env, hpa, rmpe_attrs);

    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_vmcreate(DisasContext *ctx, arg_vmcreate *a)
{
    decode_save_opc(ctx);
    TCGv asid = get_gpr(ctx, 10, EXT_NONE); //a0

    gen_helper_vmcreate(cpu_env, asid);

    return true;
}

static bool trans_vmactivate(DisasContext *ctx, arg_vmactivate *a)
{
    decode_save_opc(ctx);
    TCGv asid = get_gpr(ctx, 10, EXT_NONE); //a0

    gen_helper_vmactivate(cpu_env, asid);

    return true;
}

static bool trans_vmdestroy(DisasContext *ctx, arg_vmdestroy *a)
{
    decode_save_opc(ctx);
    TCGv asid = get_gpr(ctx, 10, EXT_NONE); //a0

    gen_helper_vmdestroy(cpu_env, asid);

    return true;
}

static bool trans_vmupdatedata(DisasContext *ctx, arg_vmupdatedata *a)
{
    decode_save_opc(ctx);
    TCGv dest_paddr = get_gpr(ctx, 10, EXT_NONE); //a0
    TCGv src_paddr = get_gpr(ctx, 11, EXT_NONE); //a1
    TCGv len = get_gpr(ctx, 12, EXT_NONE); //a2

    gen_helper_vmupdatedata(cpu_env, dest_paddr, src_paddr, len);

    return true;
}

static bool trans_pvalidate(DisasContext *ctx, arg_pvalidate *a)
{
    decode_save_opc(ctx);
    TCGv rmpe_attrs = get_gpr(ctx, 10, EXT_NONE); //a0

    gen_helper_pvalidate(cpu_env, rmpe_attrs);

    return true;
}

static bool trans_pfix(DisasContext *ctx, arg_pfix *a)
{
    decode_save_opc(ctx);
    TCGv hpa = get_gpr(ctx, 10, EXT_NONE); //a0
    TCGv leaf_hpa = get_gpr(ctx, 11, EXT_NONE); //a1

    gen_helper_pfix(cpu_env, hpa, leaf_hpa);

    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_punfix(DisasContext *ctx, arg_punfix *a)
{
    decode_save_opc(ctx);
    TCGv hpa = get_gpr(ctx, 10, EXT_NONE); //a0
    TCGv asid = get_gpr(ctx, 11, EXT_NONE); //a1

    gen_helper_punfix(cpu_env, hpa, asid);

    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_pmerge(DisasContext *ctx, arg_pmerge *a)
{
    decode_save_opc(ctx);
    TCGv dst_hpa = get_gpr(ctx, 10, EXT_NONE); //a0
    TCGv src_hpa = get_gpr(ctx, 11, EXT_NONE); //a1

    gen_helper_pmerge(cpu_env, dst_hpa, src_hpa);

    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_punmerge(DisasContext *ctx, arg_punmerge *a)
{
    decode_save_opc(ctx);
    TCGv dst_hpa = get_gpr(ctx, 10, EXT_NONE); //a0
    TCGv src_hpa = get_gpr(ctx, 11, EXT_NONE); //a1
    TCGv asid = get_gpr(ctx, 12, EXT_NONE); //a2

    gen_helper_punmerge(cpu_env, dst_hpa, src_hpa, asid);

    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}
