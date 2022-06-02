int decode_sw64(uint32 value, sw64_insn_type_t &op, uint32 &mask, uint32 &ops)
{
 mask = 0xFFFFFFFF;
 switch(value & mask) {
 case 0x2:
  op = sw64_draina;
  ops = 0x0;
  return 1;
 case 0x80:
  op = sw64_bpt;
  ops = 0x0;
  return 1;
 case 0x81:
  op = sw64_bugchk;
  ops = 0x0;
  return 1;
 case 0x83:
  op = sw64_callsys;
  ops = 0x0;
  return 1;
 case 0x86:
  op = sw64_imb;
  ops = 0x0;
  return 1;
 case 0x9E:
  op = sw64_rduniq;
  ops = 0x0;
  return 1;
 case 0x9F:
  op = sw64_wruniq;
  ops = 0x0;
  return 1;
 case 0xAA:
  op = sw64_gentrap;
  ops = 0x0;
  return 1;
 case 0xBFA0001:
  op = sw64_ret;
  ops = 0x0;
  return 1;
 }
 mask = 0xFFFFFFE0;
 switch(value & mask) {
 case 0x481F4740:
  op = sw64_implver;
  ops = 0x0;
  return 1;
 }
 mask = 0xFFFF1FFF;
 switch(value & mask) {
 case 0x43FF075F:
  op = sw64_nop;
  ops = 0x0;
  return 1;
 case 0x63FF061F:
  op = sw64_fnop;
  ops = 0x0;
  return 1;
 }
 mask = 0xFC1FFFFF;
 switch(value & mask) {
 case 0x181F0020:
  op = sw64_rtc;
  ops = 0x1;
  return 1;
 case 0x181F0040:
  op = sw64_rcid;
  ops = 0x1;
  return 1;
 case 0x181F009F:
  op = sw64_halt;
  ops = 0x0;
  return 1;
 case 0x181F1000:
  op = sw64_rd_f;
  ops = 0x1;
  return 1;
 case 0x181F1020:
  op = sw64_wr_f;
  ops = 0x1;
  return 1;
 }
 mask = 0xFC1F1FFF;
 switch(value & mask) {
 case 0x401F075F:
  op = sw64_clr;
  ops = 0x30000;
  return 1;
 case 0x601F061F:
  op = sw64_fclr;
  ops = 0x60000;
  return 1;
 }
 mask = 0xFC1F1FE0;
 switch(value & mask) {
 case 0x481F0000:
  op = sw64_sextl;
  ops = 0x30000;
  return 1;
 case 0x481F0020:
  op = sw64_negw;
  ops = 0x30000;
  return 1;
 case 0x481F0120:
  op = sw64_negl;
  ops = 0x30000;
  return 1;
 case 0x481F0740:
  op = sw64_mov;
  ops = 0x30000;
  return 1;
 case 0x481F0760:
  op = sw64_not;
  ops = 0x30000;
  return 1;
 case 0x481F0D40:
  op = sw64_sextb;
  ops = 0x30000;
  return 1;
 case 0x481F0D60:
  op = sw64_sexth;
  ops = 0x30000;
  return 1;
 case 0x401F0E00:
  op = sw64_fimovs;
  ops = 0x30004;
  return 1;
 case 0x401F0F00:
  op = sw64_fimovd;
  ops = 0x30004;
  return 1;
 case 0x601F0600:
  op = sw64_fmov;
  ops = 0x60004;
  return 1;
 case 0x601F0640:
  op = sw64_fneg;
  ops = 0x60004;
  return 1;
 case 0x601F0800:
  op = sw64_ifmovs;
  ops = 0x60001;
  return 1;
 case 0x601F0820:
  op = sw64_ifmovd;
  ops = 0x60001;
  return 1;
 case 0x601F0A00:
  op = sw64_rfpcr;
  ops = 0xD0004;
  return 1;
 case 0x601F0A20:
  op = sw64_wfpcr;
  ops = 0xD0004;
  return 1;
 case 0x681F0300:
  op = sw64_ctpopow;
  ops = 0x120004;
  return 1;
 case 0x681F0320:
  op = sw64_ctlzow;
  ops = 0x120004;
  return 1;
 case 0x681F1200:
  op = sw64_vfmov;
  ops = 0x60004;
  return 1;
 }
 mask = 0xFC100000;
 switch(value & mask) {
 case 0x1C000000:
  op = sw64_pri_ret;
  ops = 0x1;
  return 1;
 case 0x1C100000:
  op = sw64_pri_ret_b;
  ops = 0x1;
  return 1;
 }
 mask = 0xFC00FFFF;
 switch(value & mask) {
 case 0x18000000:
  op = sw64_memb;
  ops = 0x0;
  return 1;
 case 0x18000001:
  op = sw64_imemb;
  ops = 0x0;
  return 1;
 case 0x18000020:
  op = sw64_rtc;
  ops = 0x201;
  return 1;
 case 0x18001040:
  op = sw64_rtid;
  ops = 0x1;
  return 1;
 case 0x8800F81F:
  op = sw64_wh64;
  ops = 0xA00;
  return 1;
 }
 mask = 0xFC00FF00;
 switch(value & mask) {
 case 0x1800FE00:
  op = sw64_pri_rcsr;
  ops = 0x82601;
  return 1;
 case 0x1800FF00:
  op = sw64_pri_wcsr;
  ops = 0x82601;
  return 1;
 }
 mask = 0xFC00FC00;
 switch(value & mask) {
 case 0x64000000:
  op = sw64_fmas;
  ops = 0x12230504;
  return 1;
 case 0x64000400:
  op = sw64_fmad;
  ops = 0x12230504;
  return 1;
 case 0x64000800:
  op = sw64_fmss;
  ops = 0x12230504;
  return 1;
 case 0x64000C00:
  op = sw64_fmsd;
  ops = 0x12230504;
  return 1;
 case 0x64001000:
  op = sw64_fnmas;
  ops = 0x12230504;
  return 1;
 case 0x64001400:
  op = sw64_fnmad;
  ops = 0x12230504;
  return 1;
 case 0x64001800:
  op = sw64_fnmss;
  ops = 0x12230504;
  return 1;
 case 0x64001C00:
  op = sw64_fnmsd;
  ops = 0x12230504;
  return 1;
 case 0x64004000:
  op = sw64_fseleq;
  ops = 0x14230504;
  return 1;
 case 0x64004400:
  op = sw64_fselne;
  ops = 0x14230504;
  return 1;
 case 0x64004800:
  op = sw64_fsellt;
  ops = 0x14230504;
  return 1;
 case 0x64004C00:
  op = sw64_fselle;
  ops = 0x14230504;
  return 1;
 case 0x64005000:
  op = sw64_fselgt;
  ops = 0x14230504;
  return 1;
 case 0x64005400:
  op = sw64_fselge;
  ops = 0x14230504;
  return 1;
 case 0x6C000000:
  op = sw64_vmas;
  ops = 0x12230504;
  return 1;
 case 0x6C000400:
  op = sw64_vmad;
  ops = 0x12230504;
  return 1;
 case 0x6C000800:
  op = sw64_vmss;
  ops = 0x12230504;
  return 1;
 case 0x6C000C00:
  op = sw64_vmsd;
  ops = 0x12230504;
  return 1;
 case 0x6C001000:
  op = sw64_vnmas;
  ops = 0x12230504;
  return 1;
 case 0x6C001400:
  op = sw64_vnmad;
  ops = 0x12230504;
  return 1;
 case 0x6C001800:
  op = sw64_vnmss;
  ops = 0x12230504;
  return 1;
 case 0x6C001C00:
  op = sw64_vnmsd;
  ops = 0x12230504;
  return 1;
 case 0x6C004000:
  op = sw64_vfseleq;
  ops = 0x12230504;
  return 1;
 case 0x6C004800:
  op = sw64_vfsellt;
  ops = 0x12230504;
  return 1;
 case 0x6C004C00:
  op = sw64_vfselle;
  ops = 0x12230504;
  return 1;
 case 0x6C006000:
  op = sw64_vseleqw;
  ops = 0x12230504;
  return 1;
 case 0x6C00E000:
  op = sw64_vseleqw;
  ops = 0x12240504;
  return 1;
 case 0x6C006400:
  op = sw64_vsellbcw;
  ops = 0x12230504;
  return 1;
 case 0x6C00E400:
  op = sw64_vsellbcw;
  ops = 0x12240504;
  return 1;
 case 0x6C006800:
  op = sw64_vselltw;
  ops = 0x12230504;
  return 1;
 case 0x6C00E800:
  op = sw64_vselltw;
  ops = 0x12240504;
  return 1;
 case 0x6C006C00:
  op = sw64_vsellew;
  ops = 0x12230504;
  return 1;
 case 0x6C00EC00:
  op = sw64_vsellew;
  ops = 0x12240504;
  return 1;
 case 0x6C008000:
  op = sw64_vinsw;
  ops = 0x12240504;
  return 1;
 case 0x6C008400:
  op = sw64_vinsf;
  ops = 0x12240504;
  return 1;
 case 0x6C008800:
  op = sw64_vextw;
  ops = 0x122404;
  return 1;
 case 0x6C008C00:
  op = sw64_vextf;
  ops = 0x122404;
  return 1;
 case 0x6C009000:
  op = sw64_vcpyw;
  ops = 0x1204;
  return 1;
 case 0x6C009400:
  op = sw64_vcpyf;
  ops = 0x1204;
  return 1;
 case 0x6C009800:
  op = sw64_vconw;
  ops = 0x12230504;
  return 1;
 case 0x6C009C00:
  op = sw64_vshfw;
  ops = 0x12230504;
  return 1;
 case 0x6C00A000:
  op = sw64_vcons;
  ops = 0x12230504;
  return 1;
 case 0x6C00A400:
  op = sw64_vcond;
  ops = 0x12230504;
  return 1;
 }
 mask = 0xFC00F000;
 switch(value & mask) {
 case 0x20000000:
  op = sw64_lldw;
  ops = 0xA2701;
  return 1;
 case 0x20001000:
  op = sw64_lldl;
  ops = 0xA2701;
  return 1;
 case 0x20002000:
  op = sw64_ldw_inc;
  ops = 0xA2701;
  return 1;
 case 0x20003000:
  op = sw64_ldl_inc;
  ops = 0xA2701;
  return 1;
 case 0x20004000:
  op = sw64_ldw_dec;
  ops = 0xA2701;
  return 1;
 case 0x20005000:
  op = sw64_ldl_dec;
  ops = 0xA2701;
  return 1;
 case 0x20006000:
  op = sw64_ldw_set;
  ops = 0xA2701;
  return 1;
 case 0x20007000:
  op = sw64_ldl_set;
  ops = 0xA2701;
  return 1;
 case 0x20008000:
  op = sw64_lstw;
  ops = 0xA2701;
  return 1;
 case 0x20009000:
  op = sw64_lstl;
  ops = 0xA2701;
  return 1;
 case 0x2000A000:
  op = sw64_ldw_nc;
  ops = 0xA2701;
  return 1;
 case 0x2000B000:
  op = sw64_ldl_nc;
  ops = 0xA2701;
  return 1;
 case 0x2000C000:
  op = sw64_ldd_nc;
  ops = 0xA2704;
  return 1;
 case 0x2000D000:
  op = sw64_stw_nc;
  ops = 0xA2701;
  return 1;
 case 0x2000E000:
  op = sw64_stl_nc;
  ops = 0xA2701;
  return 1;
 case 0x2000F000:
  op = sw64_std_nc;
  ops = 0xA2704;
  return 1;
 case 0x70000000:
  op = sw64_vldw_u;
  ops = 0xA2704;
  return 1;
 case 0x70001000:
  op = sw64_vstw_u;
  ops = 0xA2704;
  return 1;
 case 0x70002000:
  op = sw64_vlds_u;
  ops = 0xA2704;
  return 1;
 case 0x70003000:
  op = sw64_vsts_u;
  ops = 0xA2704;
  return 1;
 case 0x70004000:
  op = sw64_vldd_u;
  ops = 0xA2704;
  return 1;
 case 0x70005000:
  op = sw64_vstd_u;
  ops = 0xA2704;
  return 1;
 case 0x70008000:
  op = sw64_vstw_ul;
  ops = 0xA2704;
  return 1;
 case 0x70009000:
  op = sw64_vstw_uh;
  ops = 0xA2704;
  return 1;
 case 0x7000A000:
  op = sw64_vsts_ul;
  ops = 0xA2704;
  return 1;
 case 0x7000B000:
  op = sw64_vsts_uh;
  ops = 0xA2704;
  return 1;
 case 0x7000C000:
  op = sw64_vstd_ul;
  ops = 0xA2704;
  return 1;
 case 0x7000D000:
  op = sw64_vstd_uh;
  ops = 0xA2704;
  return 1;
 case 0x7000E000:
  op = sw64_vldd_nc;
  ops = 0xA2704;
  return 1;
 case 0x7000F000:
  op = sw64_vstd_nc;
  ops = 0xA2704;
  return 1;
 case 0x94000000:
  op = sw64_pri_ldw_p;
  ops = 0xA1B01;
  return 1;
 case 0x94002000:
  op = sw64_pri_ldw_inc_p;
  ops = 0xA1B01;
  return 1;
 case 0x94004000:
  op = sw64_pri_ldw_dec_p;
  ops = 0xA1B01;
  return 1;
 case 0x94006000:
  op = sw64_pri_ldw_set_p;
  ops = 0xA1B01;
  return 1;
 case 0x94008000:
  op = sw64_pri_ldw_v;
  ops = 0xA1B01;
  return 1;
 case 0x9400A000:
  op = sw64_pri_ldw_vpte;
  ops = 0xA1B01;
  return 1;
 case 0x94001000:
  op = sw64_pri_ldl_p;
  ops = 0xA1B01;
  return 1;
 case 0x94003000:
  op = sw64_pri_ldl_inc_p;
  ops = 0xA1B01;
  return 1;
 case 0x94005000:
  op = sw64_pri_ldl_dec_p;
  ops = 0xA1B01;
  return 1;
 case 0x94007000:
  op = sw64_pri_ldl_set_p;
  ops = 0xA1B01;
  return 1;
 case 0x94009000:
  op = sw64_pri_ldl_v;
  ops = 0xA1B01;
  return 1;
 case 0x9400B000:
  op = sw64_pri_ldl_vpte;
  ops = 0xA1B01;
  return 1;
 case 0xB4000000:
  op = sw64_pri_stw_p;
  ops = 0xA1B01;
  return 1;
 case 0xB4008000:
  op = sw64_pri_stw_v;
  ops = 0xA1B01;
  return 1;
 case 0xB4001000:
  op = sw64_pri_stl_p;
  ops = 0xA1B01;
  return 1;
 case 0xB4009000:
  op = sw64_pri_stl_v;
  ops = 0xA1B01;
  return 1;
 }
 mask = 0xFC001FFF;
 switch(value & mask) {
 case 0x4000001F:
  op = sw64_sextl;
  ops = 0xF0200;
  return 1;
 case 0x4000003F:
  op = sw64_negw;
  ops = 0xF0200;
  return 1;
 case 0x4000013F:
  op = sw64_negl;
  ops = 0xF0200;
  return 1;
 case 0x4000075F:
  op = sw64_mov;
  ops = 0x30200;
  return 1;
 case 0x401F075F:
  op = sw64_amask;
  ops = 0x30200;
  return 1;
 case 0x4000077F:
  op = sw64_not;
  ops = 0xF0200;
  return 1;
 case 0x6000011F:
  op = sw64_fsqrts;
  ops = 0x120500;
  return 1;
 case 0x6000013F:
  op = sw64_fsqrtd;
  ops = 0x120500;
  return 1;
 case 0x6000041F:
  op = sw64_fcvtsd;
  ops = 0x120500;
  return 1;
 case 0x6000043F:
  op = sw64_fcvtds;
  ops = 0x120500;
  return 1;
 case 0x6000045F:
  op = sw64_fcvtdl_g;
  ops = 0x120500;
  return 1;
 case 0x6000047F:
  op = sw64_fcvtdl_p;
  ops = 0x120500;
  return 1;
 case 0x6000049F:
  op = sw64_fcvtdl_z;
  ops = 0x120500;
  return 1;
 case 0x600004BF:
  op = sw64_fcvtdl_n;
  ops = 0x120500;
  return 1;
 case 0x600004FF:
  op = sw64_fcvtdl;
  ops = 0x120500;
  return 1;
 case 0x6000051F:
  op = sw64_fcvtwl;
  ops = 0x120500;
  return 1;
 case 0x6000053F:
  op = sw64_fcvtlw;
  ops = 0x120500;
  return 1;
 case 0x600005BF:
  op = sw64_fcvtls;
  ops = 0x120500;
  return 1;
 case 0x600005FF:
  op = sw64_fcvtld;
  ops = 0x120500;
  return 1;
 case 0x6000061F:
  op = sw64_fabs;
  ops = 0x120500;
  return 1;
 case 0x6800111F:
  op = sw64_vsqrts;
  ops = 0x120500;
  return 1;
 case 0x6800113F:
  op = sw64_vsqrtd;
  ops = 0x120500;
  return 1;
 }
 mask = 0xFC001FE0;
 switch(value & mask) {
 case 0x40000000:
  op = sw64_addw;
  ops = 0xF0201;
  return 1;
 case 0x48000000:
  op = sw64_addw;
  ops = 0xF1501;
  return 1;
 case 0x40000020:
  op = sw64_subw;
  ops = 0xF0201;
  return 1;
 case 0x48000020:
  op = sw64_subw;
  ops = 0xF1501;
  return 1;
 case 0x40000040:
  op = sw64_s4addw;
  ops = 0xF0201;
  return 1;
 case 0x48000040:
  op = sw64_s4addw;
  ops = 0xF1501;
  return 1;
 case 0x40000060:
  op = sw64_s4subw;
  ops = 0xF0201;
  return 1;
 case 0x48000060:
  op = sw64_s4subw;
  ops = 0xF1501;
  return 1;
 case 0x40000080:
  op = sw64_s8addw;
  ops = 0xF0201;
  return 1;
 case 0x48000080:
  op = sw64_s8addw;
  ops = 0xF1501;
  return 1;
 case 0x400000A0:
  op = sw64_s8subw;
  ops = 0xF0201;
  return 1;
 case 0x480000A0:
  op = sw64_s8subw;
  ops = 0xF1501;
  return 1;
 case 0x40000100:
  op = sw64_addl;
  ops = 0xF0201;
  return 1;
 case 0x48000100:
  op = sw64_addl;
  ops = 0xF1501;
  return 1;
 case 0x40000120:
  op = sw64_subl;
  ops = 0xF0201;
  return 1;
 case 0x48000120:
  op = sw64_subl;
  ops = 0xF1501;
  return 1;
 case 0x40000140:
  op = sw64_s4addl;
  ops = 0xF0201;
  return 1;
 case 0x48000140:
  op = sw64_s4addl;
  ops = 0xF1501;
  return 1;
 case 0x40000160:
  op = sw64_s4subl;
  ops = 0xF0201;
  return 1;
 case 0x48000160:
  op = sw64_s4subl;
  ops = 0xF1501;
  return 1;
 case 0x40000180:
  op = sw64_s8addl;
  ops = 0xF0201;
  return 1;
 case 0x48000180:
  op = sw64_s8addl;
  ops = 0xF1501;
  return 1;
 case 0x400001A0:
  op = sw64_s8subl;
  ops = 0xF0201;
  return 1;
 case 0x480001A0:
  op = sw64_s8subl;
  ops = 0xF1501;
  return 1;
 case 0x40000200:
  op = sw64_mulw;
  ops = 0xF0201;
  return 1;
 case 0x48000200:
  op = sw64_mulw;
  ops = 0xF1501;
  return 1;
 case 0x40000220:
  op = sw64_divw;
  ops = 0xF0201;
  return 1;
 case 0x40000240:
  op = sw64_udivw;
  ops = 0xF0201;
  return 1;
 case 0x40000260:
  op = sw64_remw;
  ops = 0xF0201;
  return 1;
 case 0x40000280:
  op = sw64_uremw;
  ops = 0xF0201;
  return 1;
 case 0x40000300:
  op = sw64_mull;
  ops = 0xF0201;
  return 1;
 case 0x48000300:
  op = sw64_mull;
  ops = 0xF1501;
  return 1;
 case 0x40000320:
  op = sw64_umulh;
  ops = 0xF0201;
  return 1;
 case 0x48000320:
  op = sw64_umulh;
  ops = 0xF1501;
  return 1;
 case 0x40000500:
  op = sw64_cmpeq;
  ops = 0xF0201;
  return 1;
 case 0x48000500:
  op = sw64_cmpeq;
  ops = 0xF1501;
  return 1;
 case 0x40000520:
  op = sw64_cmplt;
  ops = 0xF0201;
  return 1;
 case 0x48000520:
  op = sw64_cmplt;
  ops = 0xF1501;
  return 1;
 case 0x40000540:
  op = sw64_cmple;
  ops = 0xF0201;
  return 1;
 case 0x48000540:
  op = sw64_cmple;
  ops = 0xF1501;
  return 1;
 case 0x40000560:
  op = sw64_cmpult;
  ops = 0xF0201;
  return 1;
 case 0x48000560:
  op = sw64_cmpult;
  ops = 0xF1501;
  return 1;
 case 0x40000580:
  op = sw64_cmpule;
  ops = 0xF0201;
  return 1;
 case 0x48000580:
  op = sw64_cmpule;
  ops = 0xF1501;
  return 1;
 case 0x40000700:
  op = sw64_and;
  ops = 0xF0201;
  return 1;
 case 0x48000700:
  op = sw64_and;
  ops = 0xF1501;
  return 1;
 case 0x40000720:
  op = sw64_bic;
  ops = 0xF0201;
  return 1;
 case 0x48000720:
  op = sw64_bic;
  ops = 0xF1501;
  return 1;
 case 0x40000740:
  op = sw64_or;
  ops = 0xF0201;
  return 1;
 case 0x48000740:
  op = sw64_or;
  ops = 0xF1501;
  return 1;
 case 0x40000760:
  op = sw64_ornot;
  ops = 0xF0201;
  return 1;
 case 0x48000760:
  op = sw64_ornot;
  ops = 0xF1501;
  return 1;
 case 0x40000780:
  op = sw64_xor;
  ops = 0xF0201;
  return 1;
 case 0x48000780:
  op = sw64_xor;
  ops = 0xF1501;
  return 1;
 case 0x400007A0:
  op = sw64_eqv;
  ops = 0xF0201;
  return 1;
 case 0x480007A0:
  op = sw64_eqv;
  ops = 0xF1501;
  return 1;
 case 0x40000800:
  op = sw64_inslb;
  ops = 0xF0201;
  return 1;
 case 0x48000800:
  op = sw64_inslb;
  ops = 0xF1501;
  return 1;
 case 0x40000820:
  op = sw64_inslh;
  ops = 0xF0201;
  return 1;
 case 0x48000820:
  op = sw64_inslh;
  ops = 0xF1501;
  return 1;
 case 0x40000840:
  op = sw64_inslw;
  ops = 0xF0201;
  return 1;
 case 0x48000840:
  op = sw64_inslw;
  ops = 0xF1501;
  return 1;
 case 0x40000860:
  op = sw64_insll;
  ops = 0xF0201;
  return 1;
 case 0x48000860:
  op = sw64_insll;
  ops = 0xF1501;
  return 1;
 case 0x40000880:
  op = sw64_inshb;
  ops = 0xF0201;
  return 1;
 case 0x48000880:
  op = sw64_inshb;
  ops = 0xF1501;
  return 1;
 case 0x400008A0:
  op = sw64_inshh;
  ops = 0xF0201;
  return 1;
 case 0x480008A0:
  op = sw64_inshh;
  ops = 0xF1501;
  return 1;
 case 0x400008C0:
  op = sw64_inshw;
  ops = 0xF0201;
  return 1;
 case 0x480008C0:
  op = sw64_inshw;
  ops = 0xF1501;
  return 1;
 case 0x400008E0:
  op = sw64_inshl;
  ops = 0xF0201;
  return 1;
 case 0x480008E0:
  op = sw64_inshl;
  ops = 0xF1501;
  return 1;
 case 0x40000900:
  op = sw64_sll;
  ops = 0xF0201;
  return 1;
 case 0x48000900:
  op = sw64_sll;
  ops = 0xF1501;
  return 1;
 case 0x40000920:
  op = sw64_srl;
  ops = 0xF0201;
  return 1;
 case 0x48000920:
  op = sw64_srl;
  ops = 0xF1501;
  return 1;
 case 0x40000940:
  op = sw64_sra;
  ops = 0xF0201;
  return 1;
 case 0x48000940:
  op = sw64_sra;
  ops = 0xF1501;
  return 1;
 case 0x40000980:
  op = sw64_sllw2;
  ops = 0xF0201;
  return 1;
 case 0x48000980:
  op = sw64_sllw2;
  ops = 0xF1501;
  return 1;
 case 0x400009A0:
  op = sw64_srlw2;
  ops = 0xF0201;
  return 1;
 case 0x480009A0:
  op = sw64_srlw2;
  ops = 0xF1501;
  return 1;
 case 0x400009C0:
  op = sw64_sraw2;
  ops = 0xF0201;
  return 1;
 case 0x480009C0:
  op = sw64_sraw2;
  ops = 0xF1501;
  return 1;
 case 0x40000A00:
  op = sw64_extlb;
  ops = 0xF0201;
  return 1;
 case 0x48000A00:
  op = sw64_extlb;
  ops = 0xF1501;
  return 1;
 case 0x40000A20:
  op = sw64_extlh;
  ops = 0xF0201;
  return 1;
 case 0x48000A20:
  op = sw64_extlh;
  ops = 0xF1501;
  return 1;
 case 0x40000A40:
  op = sw64_extlw;
  ops = 0xF0201;
  return 1;
 case 0x48000A40:
  op = sw64_extlw;
  ops = 0xF1501;
  return 1;
 case 0x40000A60:
  op = sw64_extll;
  ops = 0xF0201;
  return 1;
 case 0x48000A60:
  op = sw64_extll;
  ops = 0xF1501;
  return 1;
 case 0x40000A80:
  op = sw64_exthb;
  ops = 0xF0201;
  return 1;
 case 0x48000A80:
  op = sw64_exthb;
  ops = 0xF1501;
  return 1;
 case 0x40000AA0:
  op = sw64_exthh;
  ops = 0xF0201;
  return 1;
 case 0x48000AA0:
  op = sw64_exthh;
  ops = 0xF1501;
  return 1;
 case 0x40000AC0:
  op = sw64_exthw;
  ops = 0xF0201;
  return 1;
 case 0x48000AC0:
  op = sw64_exthw;
  ops = 0xF1501;
  return 1;
 case 0x40000AE0:
  op = sw64_exthl;
  ops = 0xF0201;
  return 1;
 case 0x48000AE0:
  op = sw64_exthl;
  ops = 0xF1501;
  return 1;
 case 0x40000B00:
  op = sw64_ctpop;
  ops = 0xF0207;
  return 1;
 case 0x40000B20:
  op = sw64_ctlz;
  ops = 0xF0207;
  return 1;
 case 0x40000B40:
  op = sw64_cttz;
  ops = 0xF0207;
  return 1;
 case 0x40000C00:
  op = sw64_masklb;
  ops = 0xF0201;
  return 1;
 case 0x48000C00:
  op = sw64_masklb;
  ops = 0xF1501;
  return 1;
 case 0x40000C20:
  op = sw64_masklh;
  ops = 0xF0201;
  return 1;
 case 0x48000C20:
  op = sw64_masklh;
  ops = 0xF1501;
  return 1;
 case 0x40000C40:
  op = sw64_masklw;
  ops = 0xF0201;
  return 1;
 case 0x48000C40:
  op = sw64_masklw;
  ops = 0xF1501;
  return 1;
 case 0x40000C60:
  op = sw64_maskll;
  ops = 0xF0201;
  return 1;
 case 0x48000C60:
  op = sw64_maskll;
  ops = 0xF1501;
  return 1;
 case 0x40000C80:
  op = sw64_maskhb;
  ops = 0xF0201;
  return 1;
 case 0x48000C80:
  op = sw64_maskhb;
  ops = 0xF1501;
  return 1;
 case 0x40000CA0:
  op = sw64_maskhh;
  ops = 0xF0201;
  return 1;
 case 0x48000CA0:
  op = sw64_maskhh;
  ops = 0xF1501;
  return 1;
 case 0x40000CC0:
  op = sw64_maskhw;
  ops = 0xF0201;
  return 1;
 case 0x48000CC0:
  op = sw64_maskhw;
  ops = 0xF1501;
  return 1;
 case 0x40000CE0:
  op = sw64_maskhl;
  ops = 0xF0201;
  return 1;
 case 0x48000CE0:
  op = sw64_maskhl;
  ops = 0xF1501;
  return 1;
 case 0x40000D00:
  op = sw64_zap;
  ops = 0xF0201;
  return 1;
 case 0x48000D00:
  op = sw64_zap;
  ops = 0xF1501;
  return 1;
 case 0x40000D20:
  op = sw64_zapnot;
  ops = 0xF0201;
  return 1;
 case 0x48000D20:
  op = sw64_zapnot;
  ops = 0xF1501;
  return 1;
 case 0x40000D40:
  op = sw64_sextb;
  ops = 0xF0207;
  return 1;
 case 0x40000D60:
  op = sw64_sexth;
  ops = 0xF0207;
  return 1;
 case 0x40000D80:
  op = sw64_cmpgeb;
  ops = 0xF0201;
  return 1;
 case 0x48000D80:
  op = sw64_cmpgeb;
  ops = 0xF1501;
  return 1;
 case 0x60000000:
  op = sw64_fadds;
  ops = 0x120504;
  return 1;
 case 0x60000020:
  op = sw64_faddd;
  ops = 0x120504;
  return 1;
 case 0x60000040:
  op = sw64_fsubs;
  ops = 0x120504;
  return 1;
 case 0x60000060:
  op = sw64_fsubd;
  ops = 0x120504;
  return 1;
 case 0x60000080:
  op = sw64_fmuls;
  ops = 0x120504;
  return 1;
 case 0x600000A0:
  op = sw64_fmuld;
  ops = 0x120504;
  return 1;
 case 0x600000C0:
  op = sw64_fdivs;
  ops = 0x120504;
  return 1;
 case 0x600000E0:
  op = sw64_fdivd;
  ops = 0x120504;
  return 1;
 case 0x60000200:
  op = sw64_fcmpeq;
  ops = 0x120504;
  return 1;
 case 0x60000220:
  op = sw64_fcmple;
  ops = 0x120504;
  return 1;
 case 0x60000240:
  op = sw64_fcmplt;
  ops = 0x120504;
  return 1;
 case 0x60000260:
  op = sw64_fcmpun;
  ops = 0x120504;
  return 1;
 case 0x60000600:
  op = sw64_fcpys;
  ops = 0x120504;
  return 1;
 case 0x60000620:
  op = sw64_fcpyse;
  ops = 0x120504;
  return 1;
 case 0x60000640:
  op = sw64_fcpysn;
  ops = 0x120504;
  return 1;
 case 0x60000A80:
  op = sw64_setfpec0;
  ops = 0x0;
  return 1;
 case 0x60000AA0:
  op = sw64_setfpec1;
  ops = 0x0;
  return 1;
 case 0x60000AC0:
  op = sw64_setfpec2;
  ops = 0x0;
  return 1;
 case 0x60000AE0:
  op = sw64_setfpec3;
  ops = 0x0;
  return 1;
 case 0x68000000:
  op = sw64_vaddw;
  ops = 0x120504;
  return 1;
 case 0x68000400:
  op = sw64_vaddw;
  ops = 0x121504;
  return 1;
 case 0x68000020:
  op = sw64_vsubw;
  ops = 0x120504;
  return 1;
 case 0x68000420:
  op = sw64_vsubw;
  ops = 0x121504;
  return 1;
 case 0x68000040:
  op = sw64_vcmpgew;
  ops = 0x120504;
  return 1;
 case 0x68000440:
  op = sw64_vcmpgew;
  ops = 0x121504;
  return 1;
 case 0x68000060:
  op = sw64_vcmpeqw;
  ops = 0x120504;
  return 1;
 case 0x68000460:
  op = sw64_vcmpeqw;
  ops = 0x121504;
  return 1;
 case 0x68000080:
  op = sw64_vcmplew;
  ops = 0x120504;
  return 1;
 case 0x68000480:
  op = sw64_vcmplew;
  ops = 0x121504;
  return 1;
 case 0x680000A0:
  op = sw64_vcmpltw;
  ops = 0x120504;
  return 1;
 case 0x680004A0:
  op = sw64_vcmpltw;
  ops = 0x121504;
  return 1;
 case 0x680000C0:
  op = sw64_vcmpulew;
  ops = 0x120504;
  return 1;
 case 0x680004C0:
  op = sw64_vcmpulew;
  ops = 0x121504;
  return 1;
 case 0x680000E0:
  op = sw64_vcmpultw;
  ops = 0x120504;
  return 1;
 case 0x680004E0:
  op = sw64_vcmpultw;
  ops = 0x121504;
  return 1;
 case 0x68000100:
  op = sw64_vsllw;
  ops = 0x120504;
  return 1;
 case 0x68000500:
  op = sw64_vsllw;
  ops = 0x121504;
  return 1;
 case 0x68000120:
  op = sw64_vsrlw;
  ops = 0x120504;
  return 1;
 case 0x68000520:
  op = sw64_vsrlw;
  ops = 0x121504;
  return 1;
 case 0x68000140:
  op = sw64_vsraw;
  ops = 0x120504;
  return 1;
 case 0x68000540:
  op = sw64_vsraw;
  ops = 0x121504;
  return 1;
 case 0x68000160:
  op = sw64_vrolw;
  ops = 0x120504;
  return 1;
 case 0x68000560:
  op = sw64_vrolw;
  ops = 0x121504;
  return 1;
 case 0x68000180:
  op = sw64_sllow;
  ops = 0x120504;
  return 1;
 case 0x68000580:
  op = sw64_sllow;
  ops = 0x121504;
  return 1;
 case 0x680001A0:
  op = sw64_srlow;
  ops = 0x120504;
  return 1;
 case 0x680005A0:
  op = sw64_srlow;
  ops = 0x121504;
  return 1;
 case 0x680001C0:
  op = sw64_vaddl;
  ops = 0x120504;
  return 1;
 case 0x680005C0:
  op = sw64_vaddl;
  ops = 0x121504;
  return 1;
 case 0x680001E0:
  op = sw64_vsubl;
  ops = 0x120504;
  return 1;
 case 0x680005E0:
  op = sw64_vsubl;
  ops = 0x121504;
  return 1;
 case 0x68000800:
  op = sw64_vucaddw;
  ops = 0x120504;
  return 1;
 case 0x68000C00:
  op = sw64_vucaddw;
  ops = 0x121504;
  return 1;
 case 0x68000820:
  op = sw64_vucsubw;
  ops = 0x120504;
  return 1;
 case 0x68000C20:
  op = sw64_vucsubw;
  ops = 0x121504;
  return 1;
 case 0x68000840:
  op = sw64_vucaddh;
  ops = 0x120504;
  return 1;
 case 0x68000C40:
  op = sw64_vucaddh;
  ops = 0x121504;
  return 1;
 case 0x68000860:
  op = sw64_vucsubh;
  ops = 0x120504;
  return 1;
 case 0x68000C60:
  op = sw64_vucsubh;
  ops = 0x121504;
  return 1;
 case 0x68000880:
  op = sw64_vucaddb;
  ops = 0x120504;
  return 1;
 case 0x68000C80:
  op = sw64_vucaddb;
  ops = 0x121504;
  return 1;
 case 0x680008A0:
  op = sw64_vucsubb;
  ops = 0x120504;
  return 1;
 case 0x68000CA0:
  op = sw64_vucsubb;
  ops = 0x121504;
  return 1;
 case 0x68001000:
  op = sw64_vadds;
  ops = 0x120504;
  return 1;
 case 0x68001020:
  op = sw64_vaddd;
  ops = 0x120504;
  return 1;
 case 0x68001040:
  op = sw64_vsubs;
  ops = 0x120504;
  return 1;
 case 0x68001060:
  op = sw64_vsubd;
  ops = 0x120504;
  return 1;
 case 0x68001080:
  op = sw64_vmuls;
  ops = 0x120504;
  return 1;
 case 0x680010A0:
  op = sw64_vmuld;
  ops = 0x120504;
  return 1;
 case 0x680010C0:
  op = sw64_vdivs;
  ops = 0x120504;
  return 1;
 case 0x680010E0:
  op = sw64_vdivd;
  ops = 0x120504;
  return 1;
 case 0x68001180:
  op = sw64_vfcmpeq;
  ops = 0x120504;
  return 1;
 case 0x680011A0:
  op = sw64_vfcmple;
  ops = 0x120504;
  return 1;
 case 0x680011C0:
  op = sw64_vfcmplt;
  ops = 0x120504;
  return 1;
 case 0x680011E0:
  op = sw64_vfcmpun;
  ops = 0x120504;
  return 1;
 case 0x68001200:
  op = sw64_vcpys;
  ops = 0x120504;
  return 1;
 case 0x68001220:
  op = sw64_vcpyse;
  ops = 0x120504;
  return 1;
 case 0x68001240:
  op = sw64_vcpysn;
  ops = 0x120504;
  return 1;
 }
 mask = 0xFC001C00;
 switch(value & mask) {
 case 0x44000000:
  op = sw64_seleq;
  ops = 0x11220201;
  return 1;
 case 0x4C000000:
  op = sw64_seleq;
  ops = 0x11221501;
  return 1;
 case 0x44000400:
  op = sw64_selge;
  ops = 0x11220201;
  return 1;
 case 0x4C000400:
  op = sw64_selge;
  ops = 0x11221501;
  return 1;
 case 0x44000800:
  op = sw64_selgt;
  ops = 0x11220201;
  return 1;
 case 0x4C000800:
  op = sw64_selgt;
  ops = 0x11221501;
  return 1;
 case 0x44000C00:
  op = sw64_selle;
  ops = 0x11220201;
  return 1;
 case 0x4C000C00:
  op = sw64_selle;
  ops = 0x11221501;
  return 1;
 case 0x44001000:
  op = sw64_sellt;
  ops = 0x11220201;
  return 1;
 case 0x4C001000:
  op = sw64_sellt;
  ops = 0x11221501;
  return 1;
 case 0x44001400:
  op = sw64_selne;
  ops = 0x11220201;
  return 1;
 case 0x4C001400:
  op = sw64_selne;
  ops = 0x11221501;
  return 1;
 case 0x44001800:
  op = sw64_sellbc;
  ops = 0x11220201;
  return 1;
 case 0x4C001800:
  op = sw64_sellbc;
  ops = 0x11221501;
  return 1;
 case 0x44001C00:
  op = sw64_sellbs;
  ops = 0x11220201;
  return 1;
 case 0x4C001C00:
  op = sw64_sellbs;
  ops = 0x11221501;
  return 1;
 }
 mask = 0xFC00001F;
 switch(value & mask) {
 case 0x1000001F:
  op = sw64_br;
  ops = 0x1700;
  return 1;
 case 0x2400001F:
  op = sw64_fillcs;
  ops = 0xA1600;
  return 1;
 case 0x2800001F:
  op = sw64_e_fillcs;
  ops = 0xA1600;
  return 1;
 case 0x2C00001F:
  op = sw64_fillcs_e;
  ops = 0xA1600;
  return 1;
 case 0x3000001F:
  op = sw64_e_fillde;
  ops = 0xA1600;
  return 1;
 case 0x8000001F:
  op = sw64_flushd;
  ops = 0xA1600;
  return 1;
 case 0x8400001F:
  op = sw64_evictdg;
  ops = 0xA1600;
  return 1;
 case 0x8800001F:
  op = sw64_s_fillcs;
  ops = 0xA1600;
  return 1;
 case 0x8C00001F:
  op = sw64_s_fillde;
  ops = 0xA1600;
  return 1;
 case 0x9000001F:
  op = sw64_evictdl;
  ops = 0xA1600;
  return 1;
 case 0x9800001F:
  op = sw64_fillde;
  ops = 0xA1600;
  return 1;
 case 0x9C00001F:
  op = sw64_fillde_e;
  ops = 0xA1600;
  return 1;
 case 0xFC1E001F:
  op = sw64_unop;
  ops = 0x0;
  return 1;
 }
 mask = 0xFC000000;
 switch(value & mask) {
 case 0x0:
  op = sw64_sys_call_b;
  ops = 0x18;
  return 1;
 case 0x2000000:
  op = sw64_sys_call;
  ops = 0x18;
  return 1;
 case 0x4000000:
  op = sw64_call;
  ops = 0x190B01;
  return 1;
 case 0x8000000:
  op = sw64_ret;
  ops = 0x1A0B01;
  return 1;
 case 0xC000000:
  op = sw64_jmp;
  ops = 0x190B01;
  return 1;
 case 0x10000000:
  op = sw64_br;
  ops = 0x1701;
  return 1;
 case 0x14000000:
  op = sw64_bsr;
  ops = 0x1701;
  return 1;
 case 0x24000000:
  op = sw64_ldwe;
  ops = 0xA1604;
  return 1;
 case 0x28000000:
  op = sw64_ldse;
  ops = 0xA1604;
  return 1;
 case 0x2C000000:
  op = sw64_ldde;
  ops = 0xA1604;
  return 1;
 case 0x30000000:
  op = sw64_vlds;
  ops = 0xA1604;
  return 1;
 case 0x34000000:
  op = sw64_vldd;
  ops = 0xA1604;
  return 1;
 case 0x38000000:
  op = sw64_vsts;
  ops = 0xA1604;
  return 1;
 case 0x3C000000:
  op = sw64_vstd;
  ops = 0xA1604;
  return 1;
 case 0x80000000:
  op = sw64_ldbu;
  ops = 0xA1601;
  return 1;
 case 0x84000000:
  op = sw64_ldhu;
  ops = 0xA1601;
  return 1;
 case 0x88000000:
  op = sw64_ldw;
  ops = 0xA1601;
  return 1;
 case 0x8C000000:
  op = sw64_ldl;
  ops = 0xA1601;
  return 1;
 case 0x90000000:
  op = sw64_ldl_u;
  ops = 0xA1601;
  return 1;
 case 0x98000000:
  op = sw64_flds;
  ops = 0xA1604;
  return 1;
 case 0x9C000000:
  op = sw64_fldd;
  ops = 0xA1604;
  return 1;
 case 0xA0000000:
  op = sw64_stb;
  ops = 0xA1601;
  return 1;
 case 0xA4000000:
  op = sw64_sth;
  ops = 0xA1601;
  return 1;
 case 0xA8000000:
  op = sw64_stw;
  ops = 0xA1601;
  return 1;
 case 0xAC000000:
  op = sw64_stl;
  ops = 0xA1601;
  return 1;
 case 0xB0000000:
  op = sw64_stl_u;
  ops = 0xA1601;
  return 1;
 case 0xB8000000:
  op = sw64_fsts;
  ops = 0xA1604;
  return 1;
 case 0xBC000000:
  op = sw64_fstd;
  ops = 0xA1604;
  return 1;
 case 0xC0000000:
  op = sw64_beq;
  ops = 0x1701;
  return 1;
 case 0xC4000000:
  op = sw64_bne;
  ops = 0x1701;
  return 1;
 case 0xC8000000:
  op = sw64_blt;
  ops = 0x1701;
  return 1;
 case 0xCC000000:
  op = sw64_ble;
  ops = 0x1701;
  return 1;
 case 0xD0000000:
  op = sw64_bgt;
  ops = 0x1701;
  return 1;
 case 0xD4000000:
  op = sw64_bge;
  ops = 0x1701;
  return 1;
 case 0xD8000000:
  op = sw64_blbc;
  ops = 0x1701;
  return 1;
 case 0xDC000000:
  op = sw64_blbs;
  ops = 0x1701;
  return 1;
 case 0xE0000000:
  op = sw64_fbeq;
  ops = 0x1704;
  return 1;
 case 0xE4000000:
  op = sw64_fbne;
  ops = 0x1704;
  return 1;
 case 0xE8000000:
  op = sw64_fblt;
  ops = 0x1704;
  return 1;
 case 0xEC000000:
  op = sw64_fble;
  ops = 0x1704;
  return 1;
 case 0xF0000000:
  op = sw64_fbgt;
  ops = 0x1704;
  return 1;
 case 0xF4000000:
  op = sw64_fbge;
  ops = 0x1704;
  return 1;
 case 0xF8000000:
  op = sw64_ldi;
  ops = 0x81601;
  return 1;
 case 0xFC000000:
  op = sw64_ldih;
  ops = 0x81601;
  return 1;
 }
 mask = 0xF0000000;
 switch(value & mask) {
 case 0x50000000:
  op = sw64_vlog;
  ops = 0x12230504;
  return 1;
 case 0x5000C3E0:
  op = sw64_vbicw;
  ops = 0x120504;
  return 1;
 case 0x5000F3E0:
  op = sw64_vxorw;
  ops = 0x120504;
  return 1;
 case 0x5C0003E0:
  op = sw64_vandw;
  ops = 0x120504;
  return 1;
 case 0x5C000FE0:
  op = sw64_veqvw;
  ops = 0x120504;
  return 1;
 case 0x5C00CFE0:
  op = sw64_vornotw;
  ops = 0x120504;
  return 1;
 case 0x5C00F3E0:
  op = sw64_vbisw;
  ops = 0x120504;
  return 1;
 }
 return 0;
}
