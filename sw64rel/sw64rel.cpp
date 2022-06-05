#include <elfio/elfio.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <fixup.hpp>
#include <name.hpp>
#include <offset.hpp>

struct sw64_relocs
{
  // This function is called when the user invokes the plugin.
  bool idaapi run(size_t);
 protected:
  int read_symbols();
  void apply_relocs();
  int fill_fd(fixup_data_t &fd, ea_t offset, int symbol, bool force = false);
  void fill_squad(fixup_data_t &fd, ea_t offset, ea_t addend);
  void fill_srel32(fixup_data_t &fd, ea_t offset, ea_t addend);
  void make_off(ea_t offset, ea_t target);
  void rename_j(ea_t offset);

  ELFIO::elfio reader;
  std::map<int, ea_t> m_symbols;
  std::map<int, std::string> m_external;
  std::string imp;
};

// ripped from kernel-openEuler-22.03-LTS/arch/sw_64/include/asm/elf.h 
#define R_SW64_NONE		0	/* No reloc */
#define R_SW64_REFLONG		1	/* Direct 32 bit */
#define R_SW64_REFQUAD		2	/* Direct 64 bit */
#define R_SW64_GPREL32		3	/* GP relative 32 bit */
#define R_SW64_LITERAL		4	/* GP relative 16 bit w/optimization */
#define R_SW64_LITUSE		5	/* Optimization hint for LITERAL */
#define R_SW64_GPDISP		6	/* Add displacement to GP */
#define R_SW64_BRADDR		7	/* PC+4 relative 23 bit shifted */
#define R_SW64_HINT		8	/* PC+4 relative 16 bit shifted */
#define R_SW64_SREL16		9	/* PC relative 16 bit */
#define R_SW64_SREL32		10	/* PC relative 32 bit */
#define R_SW64_SREL64		11	/* PC relative 64 bit */
#define R_SW64_GPRELHIGH	17	/* GP relative 32 bit, high 16 bits */
#define R_SW64_GPRELLOW		18	/* GP relative 32 bit, low 16 bits */
#define R_SW64_GPREL16		19	/* GP relative 16 bit */
#define R_SW64_COPY		24	/* Copy symbol at runtime */
#define R_SW64_GLOB_DAT		25	/* Create GOT entry */
#define R_SW64_JMP_SLOT		26	/* Create PLT entry */
#define R_SW64_RELATIVE		27	/* Adjust by program base */
#define R_SW64_BRSGP		28
#define R_SW64_TLSGD		29
#define R_SW64_TLS_LDM		30
#define R_SW64_DTPMOD64		31
#define R_SW64_GOTDTPREL	32
#define R_SW64_DTPREL64		33
#define R_SW64_DTPRELHI		34
#define R_SW64_DTPRELLO		35
#define R_SW64_DTPREL16		36
#define R_SW64_GOTTPREL		37
#define R_SW64_TPREL64		38
#define R_SW64_TPRELHI		39
#define R_SW64_TPRELLO		40
#define R_SW64_TPREL16		41
#define R_SW64_LITERAL_GOT	43	/* GP relative */

using namespace ELFIO;

void sw64_relocs::rename_j(ea_t offset)
{
 // first check that we have the only reffered function
 ea_t prev = BADADDR;
 for ( ea_t addr = get_first_dref_to(offset); addr != BADADDR; addr = get_next_dref_to(offset, addr) )
 {
#ifdef _DEBUG
   msg("dto %a %a\n", offset, addr);
#endif
   auto s = getseg(addr);
   if ( s == NULL )
     return;
   qstring sname;
   if ( -1 == get_segm_name(&sname, s, 0) )
     return;
   // ignore all xrefs from LOAD section
   if ( !strcmp(sname.c_str(), "LOAD") )
     continue;
   if ( prev != BADADDR )
     return;
   prev = addr;
 }
 if ( prev == BADADDR )
    return;
 auto f = get_func(prev);
 if ( f == NULL )
   return;
 qstring fname = "j_";
 fname += imp.c_str();
 set_name(f->start_ea, fname.c_str(), SN_AUTO | SN_NOCHECK | SN_PUBLIC);
}

void sw64_relocs::fill_squad(fixup_data_t &fd, ea_t offset, ea_t added)
{
  fd.set_type(FIXUP_OFF64);
  auto val = get_qword(offset);
  fd.off = val + added;
  if ( !val )
    patch_qword(offset, fd.off);
  make_off(offset, fd.off);
}

void sw64_relocs::fill_srel32(fixup_data_t &fd, ea_t offset, ea_t added)
{
  fd.set_type(FIXUP_OFF32);
  auto val = get_dword(offset);
  fd.off = val + added;
  patch_dword(offset, fd.off);
  make_off(offset, fd.off);
}

int sw64_relocs::fill_fd(fixup_data_t &fd, ea_t offset, int symbol, bool force)
{
  fd.set_type(FIXUP_OFF64);
  auto si = m_symbols.find(symbol);
  if ( si != m_symbols.end() )
     fd.off = si->second;
  else {
     auto ei = m_external.find(symbol);
     if ( ei == m_external.end() )
     {
       msg("unknown symbol %d\n", symbol);
       return 0;
     }
     fd.off = get_name_ea(BADADDR, ei->second.c_str());
     if ( fd.off == BADADDR )
     {
        msg("unknown symbol %d: %s\n", symbol, ei->second.c_str());
        return 0;
     }
     imp = ei->second;
  }
  auto val = get_qword(offset);
  if ( !val || force )
  {
    patch_qword(offset, fd.off);
    make_off(offset, fd.off);
  }
  return 1;
}

void sw64_relocs::make_off(ea_t offset, ea_t target)
{
  op_offset(offset, 0, REF_OFF64, target);
  add_dref(offset, target, dr_O);
}

void sw64_relocs::apply_relocs()
{
  int total_relocs = 0;
  int res = 0;
  int unknown = 0;
  int not_found = 0;
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     int pfx_size = 0;
     if ( sec->get_type() == SHT_RELA )
       pfx_size = 5; // .rela
     else if ( sec->get_type() == SHT_REL )
       pfx_size = 4; // .rel
     else
       continue;
     // get segment
     segment_t *s = NULL;
     if ( pfx_size )
       s = get_segm_by_name( sec->get_name().c_str() + pfx_size ); 
     const_relocation_section_accessor rsa(reader, sec);
     Elf_Xword relno = rsa.get_entries_num();
     total_relocs += relno;
     for ( int i = 0; i < relno; i++ ) 
     {
       Elf64_Addr offset;
       Elf_Word   symbol;
       Elf_Word   type;
       Elf_Sxword addend;
       rsa.get_entry(i, offset, symbol, type, addend );
       if ( s != NULL )
       {
          if ( offset < s->start_ea )
            offset += s->start_ea;
       }
       fixup_data_t fd;
       switch(type)
       {
         case R_SW64_SREL32:
            fill_srel32(fd, offset, addend);
            set_fixup(offset, fd);
            res++;
            break;         
         case R_SW64_REFQUAD:
          if ( addend )
          {
            fill_squad(fd, offset, addend);
            set_fixup(offset, fd);
            res++;
            break;
          }
         case R_SW64_DTPMOD64:
         case R_SW64_DTPREL64:
         case R_SW64_GLOB_DAT:
           // reloc to symbol or external
           if ( !fill_fd(fd, offset, symbol, type == R_SW64_REFQUAD) )
           {
             not_found++;
             break;
           }
           set_fixup(offset, fd);
           res++;
          break;
         case R_SW64_RELATIVE:
           // check if such fixup already exists
           if ( exists_fixup(offset) )
             continue;
           fd.set_type(FIXUP_OFF64);
           fd.off = get_qword(offset);
           set_fixup(offset, fd);
           make_off(offset, fd.off);
           res++;
          break;
         case R_SW64_JMP_SLOT:
           if ( symbol )
           {
             if ( !fill_fd(fd, offset, symbol, true) )
             {
               not_found++;
               break;
             }
             set_fixup(offset, fd);
             // rename only reffered function with "j_" prefix
             if ( !imp.empty() )
               rename_j(offset);
             imp.clear();
             res++;
           }
          break;
         default:
          unknown++;
          msg("unknown reltype %d at %a\n", type, offset);
       }   
     }
  }
  msg("total_relocs %d, processed %d, unknown relocs %d, not found symbols %d\n", total_relocs, res, unknown, not_found);
}

int sw64_relocs::read_symbols()
{
  int res = 0;
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
    section* sec = reader.sections[i];
    if ( SHT_SYMTAB != sec->get_type() &&
         SHT_DYNSYM != sec->get_type() )
      continue;
    symbol_section_accessor symbols( reader, sec );
    Elf_Xword sym_no = symbols.get_symbols_num();
    if ( !sym_no )
      continue;
    res += sym_no;
    for ( Elf_Xword i = 0; i < sym_no; ++i ) 
    {
      std::string   name;
      Elf64_Addr    value   = 0;
      Elf_Xword     size    = 0;
      unsigned char bind    = 0;
      unsigned char type    = 0;
      Elf_Half      sect_id = 0;
      unsigned char other   = 0;
      symbols.get_symbol( i, name, value, size, bind, type, sect_id, other );
      // if bind is local and section != 0 - value is relative to section address
      if ( bind == STB_LOCAL && sect_id )
      {
        section* lsec = reader.sections[sect_id];
        if ( lsec != NULL )
          m_symbols[i] = value + lsec->get_address();
        continue;
      }
      if ( bind == STB_GLOBAL && !value && sect_id )
      {
        section* lsec = reader.sections[sect_id];
        if ( lsec != NULL )
          m_symbols[i] = value + lsec->get_address();
        continue;
      }
      if ( value )
        m_symbols[i] = value;
      else if ( !name.empty() )
        m_external[i] = name;
    }
  }
  return res;
}

bool idaapi sw64_relocs::run(size_t unused)
{
  // 1) get input file-name
  char buf[1024];
  if ( !get_input_file_path(buf, _countof(buf)) )
  {
    msg("get_input_file_path failed\n");
    return false;
  }
  // 2) read elf
  if ( !reader.load(buf) )
  {
    msg("File %s is not found or it is not an ELF file\n", buf);
    return false;
  }
  // 3) check machine
  if ( reader.get_class() == ELFCLASS32 )
  {
    msg("file %s is 32bit\n", buf);
    return false;
  }
  auto machine = reader.get_machine();
  if ( machine != 0x9916 )
  {
    msg("unknown machine %d (0x%X)\n", machine, machine);
    return false;
  }
  // 4) read symbols
  if ( !read_symbols() )
  {
    msg("cannot read symbols from %s\n", buf);
    return false;
  }
  // 5) apply relocs
  apply_relocs();
  return true;
}

bool idaapi sw64_relocs_run(size_t unused)
{
  sw64_relocs rel;
  return rel.run(unused);
}

static plugmod_t *idaapi sw64_init()
{
  if ( inf_get_filetype() != f_ELF )
    return PLUGIN_SKIP;
  processor_t &ph = PH;
msg("sw64rel: %X\n", ph.id);
  return PLUGIN_OK;
}

static const char comment[] = "sw64 elf relocs plugin";
static const char help[] =
  "sw64 ELF relocs plugin\n"
  "\n"
  "bcs you can't just go ahead and implement your own proc_def_t.\n";
static const char desired_name[] = "sw64 elf relocs plugin";
static const char desired_hotkey[] = "";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_UNL, // plugin flags
  sw64_init,              // initialize
  nullptr,
  sw64_relocs_run,
  comment,              // long comment about the plugin. not used.
  help,                 // multiline help about the plugin. not used.
  desired_name,         // the preferred short name of the plugin
  desired_hotkey        // the preferred hotkey to run the plugin
};
