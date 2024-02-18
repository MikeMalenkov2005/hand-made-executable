%include "win32/coff.inc"

%define PE_DATA_DIRECTORIES 16

struc COFF_EXTENTION_HEADER
    .i_base:    resd 1
    .i_valgn:   resd 1
    .i_falgn:   resd 1
    .i_osvstmp: resd 1
    .i_imvstmp: resd 1
    .i_ssvstmp: resd 1
    .i_win32v:  resd 1
    .i_size:    resd 1
    .i_hdrsize: resd 1
    .i_check:   resd 1
    .i_subsys:  resw 1
    .i_dllflgs: resw 1
    .i_stckres: resd 1
    .i_stckcom: resd 1
    .i_heapres: resd 1
    .i_heapcom: resd 1
    .i_ldrflgs: resd 1
    .i_ndatdir: resd 1
    .i_datdirs: resq PE_DATA_DIRECTORIES
endstruc

struc PE_HEADER
    .pe_signature:              resb 4
    .pe_coff_file_header:       resb COFF_FILE_HEADER_size
    .pe_coff_optional_header:   resb COFF_OPTIONAL_HEADER_size
    .pe_coff_extention_header:  resb COFF_EXTENTION_HEADER_size
endstruc
