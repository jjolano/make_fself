#pragma once

#include <stdint.h>

typedef struct {
	uint32_t magic;		// 0x53434500
	uint32_t version;	// 0x2
	uint16_t keyrev;	// 0x8000 (devkit)
	uint16_t type;		// 0x1 (self)
	uint32_t meta_off;	// generated from ELF
	
	uint64_t head_len;	// generated from ELF
	uint64_t data_len;
} sce_header; // 32 bytes

typedef struct {
	uint64_t header_type;			// 0x3 (self)
	uint64_t appinfo_offset;		// 0x70
	uint64_t elf_offset;			// 0x90
	uint64_t phdr_offset;			// generated from ELF
	uint64_t shdr_offset;			// generated from ELF
	uint64_t section_info_offset;	// generated from ELF
	uint64_t sceversion_offset;		// generated from ELF
	uint64_t controlinfo_offset;	// generated from ELF
	uint64_t controlinfo_length;	// generated from ELF
	uint64_t padding;
} self_header; // 80 bytes

typedef struct {
	uint64_t auth_id;		// 0x1010000001000003
	uint32_t vendor_id;		// 0x1000002
	uint32_t self_type;		// 0x4 (application)

	uint64_t version;		// 0x0001000000000000
	uint64_t padding;
} app_info; // 32 bytes

typedef struct {
	uint64_t offset;
	uint64_t size;
	uint32_t compressed;
	uint32_t unknown1;
	uint32_t unknown2;
	uint32_t encrypted;
} segment_info; // 32 bytes

typedef struct {
	uint32_t subheader_type;	// 0x1
	uint32_t present;			// 0x0
	uint32_t size;				// 0x10 (sizeof(sceversion_info)?)
	uint32_t unknown4;			// 0x0
} sceversion_info; // 16 bytes

typedef struct {
	uint16_t unknown1;
	uint16_t unknown2;	// 0x1
	uint32_t unknown3;	// 0x30 (sizeof(sceversion_data)?)
	uint32_t unknown4;	// 0x0
	uint32_t unknown5;	// 0x1

	uint64_t offset;	// 0x0
	uint64_t size;		// 0x0

	uint8_t control_flags[16];
} sceversion_data; // 48 bytes

typedef struct {
	uint32_t type;		// 0x2
	uint32_t size;		// 0x40 (sizeof(control_info)?)
	uint64_t next;		// 0x0

	uint8_t digest1[20];
	uint8_t digest2[20];

	uint64_t padding;
} control_info;
