#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <fixup.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <offset.hpp>
#include "ops.inc"
#include "d.inc"

int get_rC(uint32 val, uint32 ops)
{
  int reg = val & 0x1f;
  // check for fp reg
  if ( ops & 2 )
    reg |= 32;
  return reg;
}

int get_rB(uint32 val, uint32 ops)
{
  int reg = (val >> 16) & 0x1f;
  // check for fp reg
  if ( 0xC == ((ops >> 8) & 0xff) )
    reg |= 32;
  return reg;
}

int get_rA(uint32 val, uint32 ops)
{
  int reg = (val >> 21) & 0x1f;
  // check for fp reg
  if ( 6 == ((ops >> 16) & 0xff) )
    reg |= 32;
  return reg;
}

int get_rpiindex(uint32 val)
{
  return val & 0xff;
}

int get_f3(uint32 val, uint32 ops)
{
  int reg = (val >> 5) & 0x1f;
  return reg | 32;
}

int is_fma(uint32 ops)
{
  ops >>= 16;
  return ops == 0x1223 || ops == 0x1423;
}

int is_fmal(uint32 ops)
{
  ops >>= 16;
  return ops == 0x1224;
}

ea_t get_b21(ea_t curr, uint32 val)
{
  // wipe out hi 6 bit for ops
  uint32 disp = val & 0x1FFFFF;
  if ( disp & 0x100000 )
    disp = (disp ^ 0x100000) - 0x100000;
  int tmp = (int)disp;
  if ( tmp < 0 )
    return curr + 4 * tmp;
  return curr + 4 * disp;
}

int get_imm8(uint32 val)
{
  return (val >> 13) & 0xff;
}

// 1 - ld, 2 - sw
int is_ld_sw(sw64_insn_type_t op)
{
  switch(op)
  {
    case sw64_flds:
    case sw64_fldd:
    case sw64_ldi:
    case sw64_ldih:
    case sw64_ldbu:
    case sw64_ldhu:
    case sw64_ldw:
    case sw64_ldl:
    case sw64_ldl_u:
    case sw64_lldw:
    case sw64_lldl:
    case sw64_ldw_inc:
    case sw64_ldl_inc:
    case sw64_ldw_dec:
    case sw64_ldl_dec:
    case sw64_ldw_set:
    case sw64_ldl_set:
    case sw64_ldw_nc:
    case sw64_ldl_nc:
    case sw64_ldd_nc:
    case sw64_vldd_nc:
    case sw64_ldwe:
    case sw64_ldse:
    case sw64_ldde:
    case sw64_vlds:
    case sw64_vldd:
     return 1;

    case sw64_stb:
    case sw64_sth:
    case sw64_stw:
    case sw64_stl:
    case sw64_stl_u:
    case sw64_fsts:
    case sw64_fstd:
    case sw64_stw_nc:
    case sw64_stl_nc:
    case sw64_std_nc:
    case sw64_vsts:
    case sw64_vstd:
    case sw64_vstd_u:
    case sw64_vsts_u:
    case sw64_vstw_ul:
    case sw64_vstw_uh:
    case sw64_vsts_ul:
    case sw64_vsts_uh:
    case sw64_vstd_ul:
    case sw64_vstd_uh:
    case sw64_vstd_nc:
      return 2;
  }
  return 0;
}

int ld_sw_size(sw64_insn_type_t op, op_dtype_t &t)
{
  switch(op)
  {
    case sw64_flds:
    case sw64_vlds:
    case sw64_fsts:
    case sw64_vsts:
    case sw64_ldse:
      t = dt_float;
      return 1;
    case sw64_fldd:
    case sw64_vldd:
    case sw64_fstd:
    case sw64_ldde:
    case sw64_vstd:
      t = dt_double;
      return 1;
    case sw64_ldbu:
    case sw64_stb:
      t = dt_byte;
      return 1;
    case sw64_ldw:
    case sw64_lldw:
    case sw64_stw:
      t = dt_dword;
      return 1;
    default:
      if ( is_ld_sw(op) )
      {
        t = dt_qword;
        return 1;
      }
  }
  return 0;
}

void set_rA_dtype(insn_t *insn)
{
  ld_sw_size((sw64_insn_type_t)insn->itype, insn->Op1.dtype);
}

const int SW64_BPF_REG_RA = 26;
const int SW64_BPF_REG_PV = 27;
const int SW64_BPF_REG_GP = 29;
const int SW64_BPF_REG_SP = 30;
const int SW64_BPF_REG_ZR = 31;

int is_sp_based(const insn_t *insn, const op_t *op)
{
  if ( op->type != o_reg )
    return 0;
  if ( !is_ld_sw((sw64_insn_type_t)insn->itype) )
    return 0;
  return op->reg == SW64_BPF_REG_SP;
}

int is_sp_based(const insn_t *insn)
{
  if ( !is_ld_sw((sw64_insn_type_t)insn->itype) )
    return 0;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op3.type == o_imm &&
    insn->Op2.reg == SW64_BPF_REG_SP
    );
}

bool is_sp_down(const insn_t *insn)
{
  if ( insn->itype != sw64_ldi )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op3.type == o_imm &&
    insn->Op1.reg == SW64_BPF_REG_SP &&
    insn->Op2.reg == SW64_BPF_REG_SP
    );
}

bool is_pv_gp(const insn_t *insn)
{
  if ( insn->itype != sw64_ldih )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op1.reg == SW64_BPF_REG_GP &&
    insn->Op2.reg == SW64_BPF_REG_PV
    );
}

bool is_ldih_gp_ra(const insn_t *insn)
{
  if ( insn->itype != sw64_ldih )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op1.reg == SW64_BPF_REG_GP &&
    insn->Op2.reg == SW64_BPF_REG_RA
    );
}

bool is_ldi_gp(const insn_t *insn)
{
  if ( insn->itype != sw64_ldi )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op1.reg == SW64_BPF_REG_GP &&
    insn->Op2.reg == SW64_BPF_REG_GP
    );
}

bool is_ldl_pv(const insn_t *insn)
{
  if ( insn->itype != sw64_ldl )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op1.reg == SW64_BPF_REG_PV &&
    insn->Op2.reg == SW64_BPF_REG_PV
    );
}

bool is_ldih_gp(const insn_t *insn, int reg)
{
  if ( insn->itype != sw64_ldih )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg &&
    insn->Op1.reg == reg &&
    insn->Op2.reg == SW64_BPF_REG_GP
    );
}

bool is_ldl(const insn_t *insn)
{
  if ( insn->itype != sw64_ldl && insn->itype != sw64_ldbu && insn->itype != sw64_ldi )
    return false;
  return (insn->Op1.type == o_reg &&
    insn->Op2.type == o_reg);
}

bool is_sw64_basic_block_end(const insn_t *insn, bool call_insn_stops_block)
{
  uint32 feature = insn->get_canon_feature(ph);
  if ( feature & CF_STOP )
    return true;
  return false;
}

bool is_reg_alive(const insn_t *insn, int ridx)
{
  uint32 feature = insn->get_canon_feature(ph);
  if ( feature & CF_CHG1 )
  {
    if ( insn->Op1.type == o_reg && insn->Op1.reg == ridx )
      return false;
  }
  if ( feature & CF_CHG2 )
  {
    if ( insn->Op2.type == o_reg && insn->Op2.reg == ridx )
      return false;
  }
  return true;
}

bool is_reg_alive_gp(const insn_t *insn, int ridx)
{
  uint32 feature = insn->get_canon_feature(ph);
  if ( feature & CF_CHG1 )
  {
    if ( insn->Op1.type == o_reg && insn->Op1.reg == ridx )
      return false;
    if ( insn->Op1.type == o_reg && insn->Op1.reg == SW64_BPF_REG_GP )
      return false;
  }
  return true;
}

void make_jmp(const insn_t *insn)
{
  if ( insn->Op1.type == o_far )
  {
    insn->add_cref(insn->Op1.addr, 0, fl_JF);
    return;
  }
  if ( insn->Op2.type == o_far )
  {
    insn->add_cref(insn->Op2.addr, 0, fl_JF);
    return;
  }
  if ( insn->Op3.type == o_far )
  {
    insn->add_cref(insn->Op3.addr, 0, fl_JF);
    return;
  }
}

int track_back_gp(ea_t curr, ea_t &res)
{
  func_item_iterator_t fii(get_func(curr), curr);
  insn_t prev;
  res = NULL;
  int state = 0;
  short off = 0;
  while ( fii.decode_prev_insn(&prev) )
  {
    if ( is_pv_gp(&prev) )
    {
      res = prev.ea + (prev.Op3.value << 0x10) + off;
      return 1;
    }
    if ( is_ldi_gp(&prev) )
    {
      auto val = get_dword(prev.ea);
      off = (short)(val & 0xffff);
      continue;
    }
  }
  return 0;
}

int track_back_reg(ea_t curr, int reg, ea_t &res)
{
  func_item_iterator_t fii(get_func(curr), curr);
  insn_t prev;
  res = NULL;
  int state = 0;
  int off16 = 0;
  int ra16 = 0;
  short off = 0;
  while ( fii.decode_prev_insn(&prev) )
  {
    if ( state && is_pv_gp(&prev) )
    {
      res = prev.ea + (prev.Op3.value << 0x10) + off;
      if ( off16 )
      {
        if ( off16 < 0 )
          res -= (-off16) << 0x10;
        else
          res += off16 << 0x10;
      }
      return 1;
    }
    if ( state && is_ldi_gp(&prev) )
    {
      auto val = get_dword(prev.ea);
      off = (short)(val & 0xffff);
      continue;
    }
    if ( is_ldih_gp(&prev, reg) )
    {
      off16 = prev.Op3.value;
      state = 1;
      continue;
    }
    if ( is_ldih_gp_ra(&prev) )
    {
      ra16 = prev.Op3.value;
      state = 2;
      continue;
    }
    if ( 2 == state && prev.itype == sw64_call )
    {
      ea_t ea = prev.ea + 4;
      if ( ra16 )
      {
        if ( ra16 < 0 )
          ea -= (-ra16) << 0x10;
        else
          ea += ra16 << 0x10;
      }
      res = ea + off;
      char comm[64];
      qsnprintf(comm, sizeof(comm), "%a", ea);
      set_cmt(prev.ea + 4, comm, false);
      if ( off16 )
      {
        if ( off16 < 0 )
          res -= (-off16) << 0x10;
        else
          res += off16 << 0x10;
      }
      return 1;
    }
    if ( !state )
    {
      if ( !is_reg_alive_gp(&prev, reg) )
        return 0;
    }
  }
  return 0;
}

void emu_insn(const insn_t *insn)
{
  segment_t *got = get_segm_by_name(".got");
  char comm[64];
  make_jmp(insn);
  int is_end = is_sw64_basic_block_end(insn, false);
  if ( !is_end )
    add_cref(insn->ea, insn->ea + insn->size, fl_F);
  fixup_data_t fd;
  if ( get_fixup(&fd, insn->ea) )
  {
    if ( insn->itype == sw64_call )
      insn->add_cref(fd.off, 2, fl_CN);
    else
      insn->add_dref(fd.off, 0, dr_O);
    qsnprintf(comm, sizeof(comm), "%a", fd.off);
    set_cmt(insn->ea, comm, false);    
    goto sp;
  }
  if ( is_pv_gp(insn) )
  {
    ea_t ea = insn->ea + (insn->Op3.value << 0x10);
    qsnprintf(comm, sizeof(comm), "%a", ea);
    set_cmt(insn->ea, comm, false);
    goto sp;
  }
  if ( is_ldl_pv(insn) )
  {
    auto val = get_dword(insn->ea);
    short off = (short)(val & 0xffff);
    ea_t gp = NULL;
    if ( track_back_gp(insn->ea, gp) )
    {
      ea_t ea = gp + off;
      qsnprintf(comm, sizeof(comm), "%a", ea);
      set_cmt(insn->ea, comm, false);    
      // add xref
      insn->add_dref(ea, 0, dr_O);
      goto sp;
    }
  }
  if ( is_ldi_gp(insn) )
  {
    auto val = get_dword(insn->ea);
    short off = (short)(val & 0xffff);
    func_item_iterator_t fii(get_func(insn->ea), insn->ea);
    insn_t prev;
    if ( fii.decode_prev_insn(&prev) && is_pv_gp(&prev) )
    {
      ea_t ea = prev.ea + (prev.Op3.value << 0x10) + off;
      qsnprintf(comm, sizeof(comm), "%a", ea);
      set_cmt(insn->ea, comm, false);
      goto sp;
    }
  } 
  if ( is_ldl(insn) && !is_sp_based(insn) && insn->Op2.reg != SW64_BPF_REG_ZR )
  {
    auto val = get_dword(insn->ea);
    short off = (short)(val & 0xffff);
    ea_t gp = NULL;
    if ( track_back_reg(insn->ea, insn->Op2.reg, gp) )
    {
      ea_t ea = gp + off;
      qsnprintf(comm, sizeof(comm), "%a", ea);
      set_cmt(insn->ea, comm, false);    
      // add xref
      insn->add_dref(ea, 0, dr_O);
      goto sp;
    }
  }
sp:
  int ssize = 0;
  if ( is_sp_down(insn) )
  {
    func_t *pfn = get_func(insn->ea);
#ifdef _DEBUG
    msg("%a stack pfn %p\n", insn->ea, pfn);
#endif /* _DEBUG */
    if ( pfn != NULL )
      add_auto_stkpnt(pfn, insn->ea+insn->size, insn->Op3.value);
    return;
  }
  if ( is_sp_based(insn) )
  {
    if ( insn_create_stkvar(*insn, insn->Op1, insn->Op3.value, 0) )
      op_stkvar(insn->ea, insn->Op1.n);
    return;
  }
}

int sw64disasm(uint32 value, insn_t *insn)
{
  sw64_insn_type_t op_idx;
  uint32 mask = 0, ops = 0;
  if ( !decode_sw64(value, op_idx, mask, ops) )
    return 0;
  insn->itype = op_idx;
  mask = ~mask;
  if ( !mask )
    return 4;
  // check rc, rb, ra, disp
  int za = (ops >> 16) & 0xff;
  int zb = (ops >> 8) & 0xff;
  int zc = (ops & 0xff);
  int has_disp = (ops & 0xf00) == 0xb00; 
  int has_disp17 = (ops & 0x1f00) == 0x1700;
  if ( ops == 0x82601 )
  {
    // pri_rcsr/pri_wcsr
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    set_rA_dtype(insn);
    insn->Op2.type = o_imm;
    insn->Op2.value = get_rpiindex(value);
    insn->Op3.type = o_reg;
    insn->Op3.reg = get_rB(value, ops);
    return 4;
  }
  if ( is_fma(ops) )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    set_rA_dtype(insn);
    insn->Op2.type = o_reg;
    insn->Op2.reg = get_rB(value, ops);
    insn->Op3.type = o_reg;
    insn->Op3.reg = get_f3(value, ops);
    insn->Op4.type = o_reg;
    insn->Op4.reg = get_rC(value, ops);
    return 4;
  }
  if ( za == 0xf )
  {
    int op = value >> 26;
    if ( op == 0x10 ) // OPCODE_ALU_REG
    { // from sw64_bpf_gen_format_simple_alu_reg
      insn->Op1.type = o_reg;
      insn->Op1.reg = get_rA(value, ops);
      set_rA_dtype(insn);
      insn->Op2.type = o_reg;
      insn->Op2.reg = get_rB(value, ops);
      insn->Op3.type = o_reg;
      insn->Op3.reg = get_rC(value, ops);
      return 4;
    } else if ( op == 0x12 ) // OPCODE_ALU_IMM
    { // from sw64_bpf_gen_format_simple_alu_imm
      insn->Op1.type = o_reg;
      insn->Op1.reg = get_rA(value, ops);
      set_rA_dtype(insn);
      insn->Op2.type = o_reg;
      insn->Op2.reg = get_rC(value, ops);
      insn->Op3.type = o_imm;
      insn->Op3.value = get_imm8(value);
      return 4;
    }
    msg("unknown alu %X at %a\n", op, insn->ea);
  }   
  if ( (za && has_disp) || zb == 0x16 )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    insn->Op1.dtype = dt_qword;
    insn->Op2.type = o_reg;
    insn->Op2.reg = get_rB(value, ops);      
    insn->Op3.type = o_imm;
    insn->Op3.value = value & 0xffff;
    insn->Op3.dtype = dt_word;
    return 4;
  }
  if ( has_disp17 )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    insn->Op1.dtype = dt_qword;
    insn->Op2.type = o_far;
    insn->Op2.addr = get_b21(insn->ea, value);
    return 4;
  }
  if ( za && zb && zc )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    set_rA_dtype(insn);
    insn->Op2.type = o_reg;
    insn->Op2.reg = get_rB(value, ops);
    insn->Op3.type = o_reg;
    insn->Op3.reg = get_rC(value, ops);      
    return 4;
  }
  if ( za && zb )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    set_rA_dtype(insn);
    insn->Op2.type = o_reg;
    insn->Op2.reg = get_rB(value, ops);
    return 4;
  }
  if ( za )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    set_rA_dtype(insn);
    return 4;
  }
  if ( zc == 0x18 )
  {
    insn->Op1.type = o_imm;
    insn->Op1.value = value & 0xffff;
    insn->Op1.dtype = dt_word;
    return 4;
  }
  if ( op_idx == sw64_nop || op_idx == sw64_fnop || !ops )
    return 4;
  if ( ops == 0x1 )
  {
    insn->Op1.type = o_reg;
    insn->Op1.reg = get_rA(value, ops);
    insn->Op2.type = o_imm;
    insn->Op2.value = value & 0xffff;
    insn->Op2.dtype = dt_word;
    return 4;
  }
  msg("unknown op %X at %a\n", value, insn->ea);
  return 4;
}