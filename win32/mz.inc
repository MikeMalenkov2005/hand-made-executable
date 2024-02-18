struc MZ_HEADER
    .signature:     resw 1
    .extra_bytes:   resw 1
    .whole_pages:   resw 1
    .relocations:   resw 1
    .header_size:   resw 1
    .min_alloc:     resw 1
    .max_alloc:     resw 1
    .initial_ss:    resw 1
    .initial_sp:    resw 1
    .checksum:      resw 1
    .initial_ip:    resw 1
    .initial_cs:    resw 1
    .rel_table:     resw 1
    .overlay:       resw 1
    .reserved:      resw 4
    .oem_id:        resw 1
    .oem_info:      resw 1
    .reserved2:     resw 10
    .pe_offset:     resd 1
endstruc
