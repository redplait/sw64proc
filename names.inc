const instruc_t Instructions[] = {
 { "sys_call/b", 0 }, /* sw64_sys_call_b 18 */
 { "sys_call", 0 }, /* sw64_sys_call 18 */
 { "draina", 0 }, /* sw64_draina 0 */
 { "bpt", CF_STOP }, /* sw64_bpt 0 */
 { "bugchk", CF_STOP }, /* sw64_bugchk 0 */
 { "callsys", 0 }, /* sw64_callsys 0 */
 { "imb", 0 }, /* sw64_imb 0 */
 { "rduniq", 0 }, /* sw64_rduniq 0 */
 { "wruniq", 0 }, /* sw64_wruniq 0 */
 { "gentrap", 0 }, /* sw64_gentrap 0 */
 { "call", CF_CALL }, /* sw64_call 190B01 */
 { "ret", CF_STOP }, /* sw64_ret 1A0B01 */
 { "jmp", CF_USE1 | CF_JUMP | CF_STOP }, /* sw64_jmp 190B01 */
 { "br", CF_USE1 | CF_JUMP }, /* sw64_br 1700 */
 { "bsr", CF_USE1 | CF_JUMP }, /* sw64_bsr 1701 */
 { "memb", 0 }, /* sw64_memb 0 */
 { "imemb", 0 }, /* sw64_imemb 0 */
 { "rtc", CF_USE3 }, /* sw64_rtc 1 */
 { "rcid", CF_USE3 }, /* sw64_rcid 1 */
 { "halt", CF_STOP }, /* sw64_halt 0 */
 { "rd_f", CF_USE3 }, /* sw64_rd_f 1 */
 { "wr_f", CF_USE3 }, /* sw64_wr_f 1 */
 { "rtid", CF_USE3 }, /* sw64_rtid 1 */
 { "pri_rcsr", CF_USE2| CF_USE3 }, /* sw64_pri_rcsr 82601 */
 { "pri_wcsr", CF_USE2| CF_USE3 }, /* sw64_pri_wcsr 82601 */
 { "pri_ret", CF_USE3 }, /* sw64_pri_ret 1 */
 { "pri_ret/b", CF_USE3 }, /* sw64_pri_ret_b 1 */
 { "lldw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_lldw A2701 */
 { "lldl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_lldl A2701 */
 { "ldw_inc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldw_inc A2701 */
 { "ldl_inc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldl_inc A2701 */
 { "ldw_dec", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldw_dec A2701 */
 { "ldl_dec", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldl_dec A2701 */
 { "ldw_set", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldw_set A2701 */
 { "ldl_set", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldl_set A2701 */
 { "lstw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_lstw A2701 */
 { "lstl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_lstl A2701 */
 { "ldw_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldw_nc A2701 */
 { "ldl_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldl_nc A2701 */
 { "ldd_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldd_nc A2704 */
 { "stw_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_stw_nc A2701 */
 { "stl_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_stl_nc A2701 */
 { "std_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_std_nc A2704 */
 { "fillcs", CF_CHG1| CF_USE2 }, /* sw64_fillcs A1600 */
 { "ldwe", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldwe A1604 */
 { "e_fillcs", CF_CHG1| CF_USE2 }, /* sw64_e_fillcs A1600 */
 { "ldse", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldse A1604 */
 { "fillcs_e", CF_CHG1| CF_USE2 }, /* sw64_fillcs_e A1600 */
 { "ldde", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldde A1604 */
 { "e_fillde", CF_CHG1| CF_USE2 }, /* sw64_e_fillde A1600 */
 { "vlds", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vlds A1604 */
 { "vldd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vldd A1604 */
 { "vsts", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsts A1604 */
 { "vstd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstd A1604 */
 { "addw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_addw F0201 */
 { "sextl", CF_CHG1| CF_USE2 }, /* sw64_sextl F0200 */
 { "subw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_subw F0201 */
 { "negw", CF_CHG1| CF_USE2 }, /* sw64_negw F0200 */
 { "s4addw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s4addw F0201 */
 { "s4subw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s4subw F0201 */
 { "s8addw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s8addw F0201 */
 { "s8subw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s8subw F0201 */
 { "addl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_addl F0201 */
 { "subl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_subl F0201 */
 { "negl", CF_CHG1| CF_USE2 }, /* sw64_negl F0200 */
 { "s4addl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s4addl F0201 */
 { "s4subl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s4subl F0201 */
 { "s8addl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s8addl F0201 */
 { "s8subl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_s8subl F0201 */
 { "mulw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_mulw F0201 */
 { "divw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_divw F0201 */
 { "udivw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_udivw F0201 */
 { "remw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_remw F0201 */
 { "uremw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_uremw F0201 */
 { "mull", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_mull F0201 */
 { "umulh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_umulh F0201 */
 { "cmpeq", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_cmpeq F0201 */
 { "cmplt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_cmplt F0201 */
 { "cmple", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_cmple F0201 */
 { "cmpult", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_cmpult F0201 */
 { "cmpule", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_cmpule F0201 */
 { "and", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_and F0201 */
 { "bic", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_bic F0201 */
 { "nop", 0 }, /* sw64_nop 0 */
 { "clr", CF_CHG1 }, /* sw64_clr 30000 */
 { "mov", CF_CHG1| CF_USE2 }, /* sw64_mov 30200 */
 { "implver", CF_USE2 }, /* sw64_implver 300 */
 { "amask", CF_CHG1| CF_USE2 }, /* sw64_amask 30200 */
 { "or", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_or F0201 */
 { "not", CF_CHG1| CF_USE2 }, /* sw64_not F0200 */
 { "ornot", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ornot F0201 */
 { "xor", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_xor F0201 */
 { "eqv", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_eqv F0201 */
 { "inslb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inslb F0201 */
 { "inslh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inslh F0201 */
 { "inslw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inslw F0201 */
 { "insll", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_insll F0201 */
 { "inshb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inshb F0201 */
 { "inshh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inshh F0201 */
 { "inshw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inshw F0201 */
 { "inshl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_inshl F0201 */
 { "sll", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sll F0201 */
 { "srl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_srl F0201 */
 { "sra", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sra F0201 */
 { "sllw2", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sllw2 F0201 */
 { "srlw2", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_srlw2 F0201 */
 { "sraw2", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sraw2 F0201 */
 { "extlb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_extlb F0201 */
 { "extlh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_extlh F0201 */
 { "extlw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_extlw F0201 */
 { "extll", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_extll F0201 */
 { "exthb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_exthb F0201 */
 { "exthh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_exthh F0201 */
 { "exthw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_exthw F0201 */
 { "exthl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_exthl F0201 */
 { "ctpop", CF_CHG1| CF_USE2 }, /* sw64_ctpop F0200 */
 { "ctlz", CF_CHG1| CF_USE2 }, /* sw64_ctlz F0200 */
 { "cttz", CF_CHG1| CF_USE2 }, /* sw64_cttz F0200 */
 { "masklb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_masklb F0201 */
 { "masklh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_masklh F0201 */
 { "masklw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_masklw F0201 */
 { "maskll", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_maskll F0201 */
 { "maskhb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_maskhb F0201 */
 { "maskhh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_maskhh F0201 */
 { "maskhw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_maskhw F0201 */
 { "maskhl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_maskhl F0201 */
 { "zap", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_zap F0201 */
 { "zapnot", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_zapnot F0201 */
 { "sextb", CF_CHG1| CF_USE2 }, /* sw64_sextb F0200 */
 { "sexth", CF_CHG1| CF_USE2 }, /* sw64_sexth F0200 */
 { "cmpgeb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_cmpgeb F0201 */
 { "fimovs", CF_CHG1| CF_USE3 }, /* sw64_fimovs 30004 */
 { "fimovd", CF_CHG1| CF_USE3 }, /* sw64_fimovd 30004 */
 { "seleq", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_seleq 11220201 */
 { "selge", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_selge 11220201 */
 { "selgt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_selgt 11220201 */
 { "selle", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_selle 11220201 */
 { "sellt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sellt 11220201 */
 { "selne", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_selne 11220201 */
 { "sellbc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sellbc 11220201 */
 { "sellbs", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sellbs 11220201 */
 { "vlog", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vlog 12230504 */
 { "vbicw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vbicw 120504 */
 { "vxorw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vxorw 120504 */
 { "vandw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vandw 120504 */
 { "veqvw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_veqvw 120504 */
 { "vornotw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vornotw 120504 */
 { "vbisw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vbisw 120504 */
 { "fadds", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fadds 120504 */
 { "faddd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_faddd 120504 */
 { "fsubs", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fsubs 120504 */
 { "fsubd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fsubd 120504 */
 { "fmuls", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fmuls 120504 */
 { "fmuld", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fmuld 120504 */
 { "fdivs", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fdivs 120504 */
 { "fdivd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fdivd 120504 */
 { "fsqrts", CF_CHG1| CF_USE2 }, /* sw64_fsqrts 120500 */
 { "fsqrtd", CF_CHG1| CF_USE2 }, /* sw64_fsqrtd 120500 */
 { "fcmpeq", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcmpeq 120504 */
 { "fcmple", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcmple 120504 */
 { "fcmplt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcmplt 120504 */
 { "fcmpun", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcmpun 120504 */
 { "fcvtsd", CF_CHG1| CF_USE2 }, /* sw64_fcvtsd 120500 */
 { "fcvtds", CF_CHG1| CF_USE2 }, /* sw64_fcvtds 120500 */
 { "fcvtdl_g", CF_CHG1| CF_USE2 }, /* sw64_fcvtdl_g 120500 */
 { "fcvtdl_p", CF_CHG1| CF_USE2 }, /* sw64_fcvtdl_p 120500 */
 { "fcvtdl_z", CF_CHG1| CF_USE2 }, /* sw64_fcvtdl_z 120500 */
 { "fcvtdl_n", CF_CHG1| CF_USE2 }, /* sw64_fcvtdl_n 120500 */
 { "fcvtdl", CF_CHG1| CF_USE2 }, /* sw64_fcvtdl 120500 */
 { "fcvtwl", CF_CHG1| CF_USE2 }, /* sw64_fcvtwl 120500 */
 { "fcvtlw", CF_CHG1| CF_USE2 }, /* sw64_fcvtlw 120500 */
 { "fcvtls", CF_CHG1| CF_USE2 }, /* sw64_fcvtls 120500 */
 { "fcvtld", CF_CHG1| CF_USE2 }, /* sw64_fcvtld 120500 */
 { "fnop", 0 }, /* sw64_fnop 0 */
 { "fclr", CF_CHG1 }, /* sw64_fclr 60000 */
 { "fabs", CF_CHG1| CF_USE2 }, /* sw64_fabs 120500 */
 { "fcpys", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcpys 120504 */
 { "fmov", CF_CHG1| CF_USE3 }, /* sw64_fmov 60004 */
 { "fcpyse", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcpyse 120504 */
 { "fneg", CF_CHG1| CF_USE3 }, /* sw64_fneg 60004 */
 { "fcpysn", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fcpysn 120504 */
 { "ifmovs", CF_CHG1| CF_USE3 }, /* sw64_ifmovs 60001 */
 { "ifmovd", CF_CHG1| CF_USE3 }, /* sw64_ifmovd 60001 */
 { "rfpcr", CF_USE3 }, /* sw64_rfpcr D0004 */
 { "wfpcr", CF_USE3 }, /* sw64_wfpcr D0004 */
 { "setfpec0", 0 }, /* sw64_setfpec0 0 */
 { "setfpec1", 0 }, /* sw64_setfpec1 0 */
 { "setfpec2", 0 }, /* sw64_setfpec2 0 */
 { "setfpec3", 0 }, /* sw64_setfpec3 0 */
 { "fmas", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fmas 12230504 */
 { "fmad", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fmad 12230504 */
 { "fmss", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fmss 12230504 */
 { "fmsd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fmsd 12230504 */
 { "fnmas", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fnmas 12230504 */
 { "fnmad", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fnmad 12230504 */
 { "fnmss", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fnmss 12230504 */
 { "fnmsd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fnmsd 12230504 */
 { "fseleq", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fseleq 14230504 */
 { "fselne", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fselne 14230504 */
 { "fsellt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fsellt 14230504 */
 { "fselle", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fselle 14230504 */
 { "fselgt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fselgt 14230504 */
 { "fselge", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fselge 14230504 */
 { "vaddw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vaddw 120504 */
 { "vsubw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsubw 120504 */
 { "vcmpgew", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcmpgew 120504 */
 { "vcmpeqw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcmpeqw 120504 */
 { "vcmplew", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcmplew 120504 */
 { "vcmpltw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcmpltw 120504 */
 { "vcmpulew", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcmpulew 120504 */
 { "vcmpultw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcmpultw 120504 */
 { "vsllw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsllw 120504 */
 { "vsrlw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsrlw 120504 */
 { "vsraw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsraw 120504 */
 { "vrolw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vrolw 120504 */
 { "sllow", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_sllow 120504 */
 { "srlow", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_srlow 120504 */
 { "vaddl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vaddl 120504 */
 { "vsubl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsubl 120504 */
 { "ctpopow", CF_CHG1| CF_USE3 }, /* sw64_ctpopow 120004 */
 { "ctlzow", CF_CHG1| CF_USE3 }, /* sw64_ctlzow 120004 */
 { "vucaddw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vucaddw 120504 */
 { "vucsubw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vucsubw 120504 */
 { "vucaddh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vucaddh 120504 */
 { "vucsubh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vucsubh 120504 */
 { "vucaddb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vucaddb 120504 */
 { "vucsubb", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vucsubb 120504 */
 { "vadds", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vadds 120504 */
 { "vaddd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vaddd 120504 */
 { "vsubs", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsubs 120504 */
 { "vsubd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsubd 120504 */
 { "vmuls", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vmuls 120504 */
 { "vmuld", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vmuld 120504 */
 { "vdivs", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vdivs 120504 */
 { "vdivd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vdivd 120504 */
 { "vsqrts", CF_CHG1| CF_USE2 }, /* sw64_vsqrts 120500 */
 { "vsqrtd", CF_CHG1| CF_USE2 }, /* sw64_vsqrtd 120500 */
 { "vfcmpeq", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfcmpeq 120504 */
 { "vfcmple", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfcmple 120504 */
 { "vfcmplt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfcmplt 120504 */
 { "vfcmpun", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfcmpun 120504 */
 { "vcpys", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcpys 120504 */
 { "vfmov", CF_CHG1| CF_USE3 }, /* sw64_vfmov 60004 */
 { "vcpyse", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcpyse 120504 */
 { "vcpysn", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcpysn 120504 */
 { "vmas", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vmas 12230504 */
 { "vmad", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vmad 12230504 */
 { "vmss", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vmss 12230504 */
 { "vmsd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vmsd 12230504 */
 { "vnmas", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vnmas 12230504 */
 { "vnmad", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vnmad 12230504 */
 { "vnmss", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vnmss 12230504 */
 { "vnmsd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vnmsd 12230504 */
 { "vfseleq", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfseleq 12230504 */
 { "vfsellt", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfsellt 12230504 */
 { "vfselle", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vfselle 12230504 */
 { "vseleqw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vseleqw 12230504 */
 { "vsellbcw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsellbcw 12230504 */
 { "vselltw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vselltw 12230504 */
 { "vsellew", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsellew 12230504 */
 { "vinsw", CF_USE2| CF_USE3 }, /* sw64_vinsw 12240504 */
 { "vinsf", CF_USE2| CF_USE3 }, /* sw64_vinsf 12240504 */
 { "vextw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vextw 122404 */
 { "vextf", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vextf 122404 */
 { "vcpyw", CF_USE2| CF_USE3 }, /* sw64_vcpyw 1204 */
 { "vcpyf", CF_USE2| CF_USE3 }, /* sw64_vcpyf 1204 */
 { "vconw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vconw 12230504 */
 { "vshfw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vshfw 12230504 */
 { "vcons", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcons 12230504 */
 { "vcond", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vcond 12230504 */
 { "vldw_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vldw_u A2704 */
 { "vstw_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstw_u A2704 */
 { "vlds_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vlds_u A2704 */
 { "vsts_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsts_u A2704 */
 { "vldd_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vldd_u A2704 */
 { "vstd_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstd_u A2704 */
 { "vstw_ul", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstw_ul A2704 */
 { "vstw_uh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstw_uh A2704 */
 { "vsts_ul", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsts_ul A2704 */
 { "vsts_uh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vsts_uh A2704 */
 { "vstd_ul", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstd_ul A2704 */
 { "vstd_uh", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstd_uh A2704 */
 { "vldd_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vldd_nc A2704 */
 { "vstd_nc", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_vstd_nc A2704 */
 { "flushd", CF_CHG1| CF_USE2 }, /* sw64_flushd A1600 */
 { "ldbu", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldbu A1601 */
 { "evictdg", CF_CHG1| CF_USE2 }, /* sw64_evictdg A1600 */
 { "ldhu", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldhu A1601 */
 { "s_fillcs", CF_CHG1| CF_USE2 }, /* sw64_s_fillcs A1600 */
 { "ldw", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldw A1601 */
 { "wh64", CF_USE2 }, /* sw64_wh64 A00 */
 { "s_fillde", CF_CHG1| CF_USE2 }, /* sw64_s_fillde A1600 */
 { "ldl", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldl A1601 */
 { "evictdl", CF_CHG1| CF_USE2 }, /* sw64_evictdl A1600 */
 { "ldl_u", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_ldl_u A1601 */
 { "pri_ldw/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldw_p A1B01 */
 { "pri_ldw_inc/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldw_inc_p A1B01 */
 { "pri_ldw_dec/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldw_dec_p A1B01 */
 { "pri_ldw_set/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldw_set_p A1B01 */
 { "pri_ldw/v", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldw_v A1B01 */
 { "pri_ldw/vpte", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldw_vpte A1B01 */
 { "pri_ldl/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldl_p A1B01 */
 { "pri_ldl_inc/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldl_inc_p A1B01 */
 { "pri_ldl_dec/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldl_dec_p A1B01 */
 { "pri_ldl_set/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldl_set_p A1B01 */
 { "pri_ldl/v", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldl_v A1B01 */
 { "pri_ldl/vpte", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_ldl_vpte A1B01 */
 { "fillde", CF_CHG1| CF_USE2 }, /* sw64_fillde A1600 */
 { "flds", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_flds A1604 */
 { "fillde_e", CF_CHG1| CF_USE2 }, /* sw64_fillde_e A1600 */
 { "fldd", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_fldd A1604 */
 { "stb", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_stb A1601 */
 { "sth", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_sth A1601 */
 { "stw", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_stw A1601 */
 { "stl", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_stl A1601 */
 { "stl_u", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_stl_u A1601 */
 { "pri_stw/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_stw_p A1B01 */
 { "pri_stw/v", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_stw_v A1B01 */
 { "pri_stl/p", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_stl_p A1B01 */
 { "pri_stl/v", CF_CHG1| CF_USE2| CF_USE3 }, /* sw64_pri_stl_v A1B01 */
 { "fsts", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_fsts A1604 */
 { "fstd", CF_USE1| CF_USE2| CF_USE3 }, /* sw64_fstd A1604 */
 { "beq", CF_USE1 | CF_JUMP }, /* sw64_beq 1701 */
 { "bne", CF_USE1 | CF_JUMP }, /* sw64_bne 1701 */
 { "blt", CF_USE1 | CF_JUMP }, /* sw64_blt 1701 */
 { "ble", CF_USE1 | CF_JUMP }, /* sw64_ble 1701 */
 { "bgt", CF_USE1 | CF_JUMP }, /* sw64_bgt 1701 */
 { "bge", CF_USE1 | CF_JUMP }, /* sw64_bge 1701 */
 { "blbc", CF_USE1 | CF_JUMP }, /* sw64_blbc 1701 */
 { "blbs", CF_USE1 | CF_JUMP }, /* sw64_blbs 1701 */
 { "fbeq", CF_USE1 | CF_JUMP }, /* sw64_fbeq 1704 */
 { "fbne", CF_USE1 | CF_JUMP }, /* sw64_fbne 1704 */
 { "fblt", CF_USE1 | CF_JUMP }, /* sw64_fblt 1704 */
 { "fble", CF_USE1 | CF_JUMP }, /* sw64_fble 1704 */
 { "fbgt", CF_USE1 | CF_JUMP }, /* sw64_fbgt 1704 */
 { "fbge", CF_USE1 | CF_JUMP }, /* sw64_fbge 1704 */
 { "ldi", CF_USE2| CF_USE3 }, /* sw64_ldi 81601 */
 { "ldih", CF_USE2| CF_USE3 }, /* sw64_ldih 81601 */
 { "unop", 0 }, /* sw64_unop 0 */
};
