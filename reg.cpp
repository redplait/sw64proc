#include "idaidp.hpp"
#include <idp.hpp>
#include <ua.hpp>
#include "sw64.h"

#include "ops.inc"
#include "names.inc"

extern int sw64disasm(uint32 value, insn_t *insn);
extern int is_sp_based(const insn_t *insn, const op_t *op);
extern void emu_insn(const insn_t *insn);

static const char *const register_names[] = {
#include "regs.inc"
};

static const asm_t sw64_asm =
{
//   AS_ASCIIC
   ASH_HEXF3    // 0x34
  |ASD_DECF0    // 34
  |ASB_BINF2    // %01010
  |ASO_OCTF1    // 0123
  |AS_ONEDUP,
  0,
  "sw64 Assembler",
  0,
  NULL,         // header lines
  ".org",        // org
  ".end",        // end

  "//",         // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".dword",     // double words
  ".qword",     // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  ".double",    // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  ".bs#s(c,) #d, #v", // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",        // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  ".pc",          // current IP (instruction pointer)
  NULL,         // func_header
  NULL,         // func_footer
  ".global",     // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extrn",      // "extrn"  name keyword
                // .extern directive requires an explicit object size
  NULL,         // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  AS2_BYTE1CHAR,// One symbol per processor byte
};

static const asm_t *const asms[] = { &sw64_asm, NULL };

static const char *const shnames[] = {
  "sw64",
  NULL
};

static const char *const lnames[] = {
  "Sunway sw64 processor", 
  NULL 
};

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(new sw64_t);
  return 0;
}

ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list)
{
  switch ( code )
  {
    case idb_event::closebase:
    case idb_event::savebase:
      pm.helper.altset(-1, pm.idpflags);
      break;
  }
  return 0;
}

const char *sw64_t::set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded)
{
  if ( keyword == NULL )
  {
    sval_t val = idpflags;
    bool code = ask_long(&val, "idpflags");
    if ( !code )
      return IDPOPT_OK;
    setflag(idpflags, USE_GOT, *(int*)val != 0);
    return IDPOPT_OK;
  } else {
    if ( !strcmp(keyword, "USE_GOT") )
      setflag(idpflags, USE_GOT, *(int*)value != 0);
    else
      return IDPOPT_BADKEY;
    if ( idb_loaded )
      helper.altset(-1, idpflags);
    return IDPOPT_OK;
  }
}

ssize_t idaapi sw64_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
#ifdef _DEBUG
  msg("msgid: %X\n", msgid);
#endif
  switch ( msgid )
  {
    case processor_t::ev_loader_elf_machine:
     {
       // from https://www.hex-rays.com/products/ida/support/sdkdoc/structprocessor__t.html
       linput_t *li = va_arg(va, linput_t *);
       int machine_type = va_arg(va, int);
       const char **procname = va_arg(va, const char **);
       proc_def_t **p_pd = va_arg(va, proc_def_t **);
//       elf_loader_t *loader = va_arg(va, elf_loader_t *);
//       reader_t *reader = va_arg(va, reader_t *);
       msg("elf: %d\n", machine_type);
       if ( machine_type == 39190 )
       {
         *procname = shnames[0];
         return machine_type;
       }
       break;
     }

    case processor_t::ev_init:
      hook_event_listener(HT_IDB, &idb_listener, &LPH);
      helper.create("$ sunway");
      inf_set_be(false);
      break;

    case processor_t::ev_oldfile:
      idpflags = (ushort)helper.altval(-1) & 1;
      break;

    case processor_t::ev_term:
      unhook_event_listener(HT_IDB, &idb_listener);
      break;

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        out->flags |= INSN_64BIT;
        int res = sw64disasm(out->get_next_dword(), out);
#ifdef _DEBUG
    msg("%a: %d\n", out->ea, res);
#endif /* _DEBUG */
        return res;
      }

    case processor_t::ev_emu_insn:
    {
       const insn_t *insn = va_arg(va, const insn_t *);
       emu_insn(insn);
       return 1;
    }

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char **errmsg = va_arg(va, const char **);
        bool idb_loaded = va_argi(va, bool);
        const char *ret = set_idp_options(keyword, value_type, value, idb_loaded);
        if ( ret == IDPOPT_OK )
          return 1;
        if ( errmsg != NULL )
          *errmsg = ret;
        return -1;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(insn, op);
        return 1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
     {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
     }
  }
  return code;
}

static const uchar retcode_1[] = { 1, 0, 0xFA, 0x0B };
static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { 0, NULL }
};

processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  0x8002,                 // id
                          // flag
  PRN_HEX
  | PR_USE64
  | PR_DEFSEG64
  | PR_ALIGN
  | PR_NO_SEGMOVE,
                         // flag2
  PR2_IDP_OPTS,          // the module has processor-specific configuration options
  8,                     // 8 bits in a byte for code segments
  8,                     // 8 bits in a byte for other segments
  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  qnumber(register_names)-2,qnumber(register_names)-1, // first, last segment register
  0,                    // size of a segment register
  qnumber(register_names)-2,qnumber(register_names)-1, // virtual CS,DS

  NULL,                 // No known code start sequences
  retcodes,

  sw64_sys_call_b,
  sw64_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 19 },     // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  sw64_ret,             // Icode of return instruction
};
