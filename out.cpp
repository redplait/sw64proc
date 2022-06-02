#include "idaidp.hpp"
#include "sw64.h"

class out_sw64_t : public outctx_t
{
public:
  bool out_operand(const op_t &x);
  void out_insn(void);
};
DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_sw64_t)

void out_sw64_t::out_insn(void)
{
    out_mnemonic();
    if ( insn.Op1.type != o_void )
      out_one_operand(0);
    if ( insn.Op2.type != o_void )
    {
      out_symbol(',');
      out_char(' ');
      out_one_operand(1);
    }
    if ( insn.Op3.type != o_void )
    {
      out_symbol(',');
      out_char(' ');
      out_one_operand(2);
    }
    if ( insn.Op4.type != o_void )
    {
      out_symbol(',');
      out_char(' ');
      out_one_operand(3);
    }
  out_immchar_cmts();
  flush_outbuf();
}

bool out_sw64_t::out_operand(const op_t &x)
{
  switch (x.type)
  {
  case o_void:
    return 0;

  case o_reg:
    out_register(ph.reg_names[x.reg]);
    return 1;

  case o_near:
  case o_far:
    if (!out_name_expr(x, x.addr))
      out_value(x);
    return 1;

  case o_imm:
    out_value(x, OOFS_IFSIGN | OOF_SIGNED | OOF_NUMBER | OOFW_IMM);
    return 1;
  }
    return 0;
}