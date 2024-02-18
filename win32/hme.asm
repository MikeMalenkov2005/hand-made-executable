org 0
bits 16
%include "win32/mz.inc"

%define RAW(lbl) (lbl - $$)

dos_header:
istruc MZ_HEADER
    at MZ_HEADER.signature,     db "MZ"
    at MZ_HEADER.extra_bytes,   dw RAW(EOF) % 512
    at MZ_HEADER.whole_pages,   dw RAW(EOF) >> 9
    at MZ_HEADER.relocations,   dw 0
    at MZ_HEADER.header_size,   dw MZ_HEADER_size >> 4
    at MZ_HEADER.min_alloc,     dw 0
    at MZ_HEADER.max_alloc,     dw 0xFFFF
    at MZ_HEADER.initial_ss,    dw 0
    at MZ_HEADER.initial_sp,    dw 0
    at MZ_HEADER.checksum,      dw 0
    at MZ_HEADER.initial_ip,    dw 0
    at MZ_HEADER.initial_cs,    dw 0
    at MZ_HEADER.rel_table,     dw 0
    at MZ_HEADER.overlay,       dw 0
    at MZ_HEADER.reserved,      times 4 dw 0
    at MZ_HEADER.oem_id,        dw 0
    at MZ_HEADER.oem_info,      dw 0
    at MZ_HEADER.reserved2,     times 10 dw 0
    at MZ_HEADER.pe_offset,     dd RAW(new_header)
iend

dos_stub:
    push cs
    pop ds
    mov dx, .msg - dos_stub
    mov ah, 9
    int 0x21
    mov ax, 0x4C01
    int 0x21
    .msg: db "This program cannot be run in DOS mode.", 0x0D, 0x0D, 0x0A, '$', 0

align 16, db 0

bits 32

%define IMAGE_BASE  0x400000
%define VALIGN      0x1000
%define FALIGN      0x200
%define SRA(lbl)    (RAW(lbl) % FALIGN)
%define RVA(lbl)    (RAW(lbl) - SRA(lbl)) * (VALIGN / FALIGN) + SRA(lbl)

%include "win32/pe.inc"

new_header:
istruc PE_HEADER
    at PE_HEADER.pe_signature,  db "PE", 0, 0
    at PE_HEADER.pe_coff_file_header
    istruc COFF_FILE_HEADER
        at COFF_FILE_HEADER.f_magic,    dw 0x014C
        at COFF_FILE_HEADER.f_nscns,    dw 2
        at COFF_FILE_HEADER.f_timdat,   dd 0x61CF9980
        at COFF_FILE_HEADER.f_symptr,   dd 0
        at COFF_FILE_HEADER.f_nsyms,    dd 0
        at COFF_FILE_HEADER.f_opthdr,   dw PE_HEADER_size - PE_HEADER.pe_coff_optional_header
        at COFF_FILE_HEADER.f_flags,    dw 0x010F
    iend
    at PE_HEADER.pe_coff_optional_header
    istruc COFF_OPTIONAL_HEADER
        at COFF_OPTIONAL_HEADER.magic,  dw 0x010B
        at COFF_OPTIONAL_HEADER.vstamp, dw 0x0C05
        at COFF_OPTIONAL_HEADER.tsize,  dd TEXT_SECTION_END - TEXT_SECTION_START
        at COFF_OPTIONAL_HEADER.dsize,  dd IDATA_SECTION_END - IDATA_SECTION_START
        at COFF_OPTIONAL_HEADER.bsize,  dd 0
        at COFF_OPTIONAL_HEADER.entry,  dd RVA(entry)
        at COFF_OPTIONAL_HEADER.tstart, dd RVA(TEXT_SECTION_START)
        at COFF_OPTIONAL_HEADER.dstart, dd RVA(IDATA_SECTION_START)
    iend
    at PE_HEADER.pe_coff_extention_header
    istruc COFF_EXTENTION_HEADER
        at COFF_EXTENTION_HEADER.i_base,    dd IMAGE_BASE
        at COFF_EXTENTION_HEADER.i_valgn,   dd VALIGN
        at COFF_EXTENTION_HEADER.i_falgn,   dd FALIGN
        at COFF_EXTENTION_HEADER.i_osvstmp, dd 4
        at COFF_EXTENTION_HEADER.i_imvstmp, dd 0
        at COFF_EXTENTION_HEADER.i_ssvstmp, dd 4
        at COFF_EXTENTION_HEADER.i_win32v,  dd 0
        at COFF_EXTENTION_HEADER.i_size,    dd RVA(EOF)
        at COFF_EXTENTION_HEADER.i_hdrsize, dd RVA(HEADER_END)
        at COFF_EXTENTION_HEADER.i_check,   dd 0
        at COFF_EXTENTION_HEADER.i_subsys,  dw 2
        at COFF_EXTENTION_HEADER.i_dllflgs, dw 0
        at COFF_EXTENTION_HEADER.i_stckres, dd 0x100000
        at COFF_EXTENTION_HEADER.i_stckcom, dd 0x1000
        at COFF_EXTENTION_HEADER.i_heapres, dd 0x100000
        at COFF_EXTENTION_HEADER.i_heapcom, dd 0x1000
        at COFF_EXTENTION_HEADER.i_ldrflgs, dd 0
        at COFF_EXTENTION_HEADER.i_ndatdir, dd PE_DATA_DIRECTORIES
        at COFF_EXTENTION_HEADER.i_datdirs
        dq 0
        dd RVA(import_table), import_table_end - import_table
        times PE_DATA_DIRECTORIES - ((COFF_EXTENTION_HEADER_size - COFF_EXTENTION_HEADER.i_datdirs) >> 3) dq 0
    iend
iend
TEXT_SECTION_HEADER:
istruc COFF_SECTION_HEADER
    at COFF_SECTION_HEADER.s_name,    db ".text", 0, 0, 0
    at COFF_SECTION_HEADER.s_vsize,   dd TEXT_END - TEXT_SECTION_START
    at COFF_SECTION_HEADER.s_vaddr,   dd RVA(TEXT_SECTION_START)
    at COFF_SECTION_HEADER.s_fsize,   dd TEXT_SECTION_END - TEXT_SECTION_START
    at COFF_SECTION_HEADER.s_scnptr,  dd RAW(TEXT_SECTION_START)
    at COFF_SECTION_HEADER.s_relptr,  dd 0
    at COFF_SECTION_HEADER.s_lnnoptr, dd 0
    at COFF_SECTION_HEADER.s_nreloc,  dw 0
    at COFF_SECTION_HEADER.s_nlnno,   dw 0
    at COFF_SECTION_HEADER.s_flags,   dd 0x60000060
iend
IDATA_SECTION_HEADER:
istruc COFF_SECTION_HEADER
    at COFF_SECTION_HEADER.s_name,    db ".idata", 0, 0
    at COFF_SECTION_HEADER.s_vsize,   dd IDATA_END - IDATA_SECTION_START
    at COFF_SECTION_HEADER.s_vaddr,   dd RVA(IDATA_SECTION_START)
    at COFF_SECTION_HEADER.s_fsize,   dd IDATA_SECTION_END - IDATA_SECTION_START
    at COFF_SECTION_HEADER.s_scnptr,  dd RAW(IDATA_SECTION_START)
    at COFF_SECTION_HEADER.s_relptr,  dd 0
    at COFF_SECTION_HEADER.s_lnnoptr, dd 0
    at COFF_SECTION_HEADER.s_nreloc,  dw 0
    at COFF_SECTION_HEADER.s_nlnno,   dw 0
    at COFF_SECTION_HEADER.s_flags,   dd 0x40000040
iend
align FALIGN, db 0
HEADER_END:

TEXT_SECTION_START:
    entry:
        mov edx, RVA(msg)+IMAGE_BASE
        xor eax, eax
        push eax
        push edx
        push edx
        push eax
        call MessageBoxA
        push eax
        call ExitProcess
    ExitProcess: jmp dword [0+RVA(import_address_table.kernel32)+IMAGE_BASE]
    MessageBoxA: jmp dword [0+RVA(import_address_table.user32)+IMAGE_BASE]
    msg: db "TEST", 0
    TEXT_END:
align FALIGN, db 0
TEXT_SECTION_END:

IDATA_SECTION_START:
    import_address_table:
        .kernel32:
            dd RVA(import_names.ExitProcess), 0
        .user32:
            dd RVA(import_names.MessageBoxA), 0
    import_table:
        .kernel32:
            istruc PE_IMPORT_TABLE_ENTRY
                at PE_IMPORT_TABLE_ENTRY.lookup_table,  dd RVA(import_lookup_table.kernel32)
                at PE_IMPORT_TABLE_ENTRY.time_date,     dd 0
                at PE_IMPORT_TABLE_ENTRY.forward_chain, dd 0
                at PE_IMPORT_TABLE_ENTRY.library_name,  dd RVA(lib_names.kernel32)
                at PE_IMPORT_TABLE_ENTRY.import_table,  dd RVA(import_address_table.kernel32)
            iend
        .user32:
            istruc PE_IMPORT_TABLE_ENTRY
                at PE_IMPORT_TABLE_ENTRY.lookup_table,  dd RVA(import_lookup_table.user32)
                at PE_IMPORT_TABLE_ENTRY.time_date,     dd 0
                at PE_IMPORT_TABLE_ENTRY.forward_chain, dd 0
                at PE_IMPORT_TABLE_ENTRY.library_name,  dd RVA(lib_names.user32)
                at PE_IMPORT_TABLE_ENTRY.import_table,  dd RVA(import_address_table.user32)
            iend
        .zeros: times 5 dd 0
    import_table_end:
    import_lookup_table:
        .kernel32:
            dd RVA(import_names.ExitProcess), 0
        .user32:
            dd RVA(import_names.MessageBoxA), 0
    import_names:
        .ExitProcess:
            dw 0
            db "ExitProcess", 0
        .MessageBoxA:
            dw 0
            db "MessageBoxA", 0
    lib_names:
        .kernel32: db "KERNEL32.dll", 0
        .user32: db "User32.dll", 0
    IDATA_END:
align FALIGN, db 0
IDATA_SECTION_END:

EOF:
