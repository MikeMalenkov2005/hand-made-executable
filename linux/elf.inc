struc ELF32_FILE_HEADER
    .ei_magic:      resb 4
    .ei_class:      resb 1
    .ei_data:       resb 1
    .ei_version:    resb 1
    .ei_osabi:      resb 1
    .ei_abiversion: resb 1
    .ei_pad:        resb 7
    .e_type:        resw 1
    .e_machine:     resw 1
    .e_version:     resd 1
    .e_entry:       resd 1
    .e_phoff:       resd 1
    .e_shoff:       resd 1
    .e_flags:       resd 1
    .e_ehsize:      resw 1
    .e_phentsize:   resw 1
    .e_phnum:       resw 1
    .e_shentsize:   resw 1
    .e_shnum:       resw 1
    .e_shstrndx:    resw 1
endstruc

struc ELF32_SECTION_HEADER
    .sh_name:       resd 1
    .sh_type:       resd 1
    .sh_flags:      resd 1
    .sh_addr:       resd 1
    .sh_offset:     resd 1
    .sh_size:       resd 1
    .sh_link:       resd 1
    .sh_info:       resd 1
    .sh_addralign:  resd 1
    .sh_entsize:    resd 1
endstruc

struc ELF32_PROGRAM_HEADER
    .p_type:    resd 1
    .p_offset:  resd 1
    .p_vaddr:   resd 1
    .p_paddr:   resd 1
    .p_filesz:  resd 1
    .p_memsz:   resd 1
    .p_flags:   resd 1
    .p_align:   resd 1
endstruc
