struc COFF_FILE_HEADER
    .f_magic:   resw 1
    .f_nscns:   resw 1
    .f_timdat:  resd 1
    .f_symptr:  resd 1
    .f_nsyms:   resd 1
    .f_opthdr:  resw 1
    .f_flags:   resw 1
endstruc

struc COFF_OPTIONAL_HEADER
    .magic:     resw 1
    .vstamp:    resw 1
    .tsize:     resd 1
    .dsize:     resd 1
    .bsize:     resd 1
    .entry:     resd 1
    .tstart:    resd 1
    .dstart:    resd 1
endstruc

struc COFF_SECTION_HEADER
    .s_name:    resb 8
    .s_paddr:
    .s_vsize:   resd 1
    .s_vaddr:   resd 1
    .s_fsize:   resd 1
    .s_scnptr:  resd 1
    .s_relptr:  resd 1
    .s_lnnoptr: resd 1
    .s_nreloc:  resw 1
    .s_nlnno:   resw 1
    .s_flags:   resd 1
endstruc

struc COFF_RELOCATION_ENTRY
    .r_vaddr:   resd 1
    .r_symndx:  resd 1
    .r_type:    resw 1
endstruc

struc COFF_LINE_NUMBER_ENTRY
    .l_addr:    resd 1
    .l_lnno:    resw 1
endstruc

struc COFF_SYMBOL
    .n_name:    resb 8
    .n_value:   resd 1
    .n_scnum:   resw 1
    .n_type:    resw 1
    .n_sclass:  resb 1
    .n_numaux:  resb 1
endstruc
