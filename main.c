#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libelf.h>
#include <openssl/sha.h>

#include "bytes.h"
#include "fself.h"

int main(int argc, char* argv[])
{
	printf("make_fself v0.1 by jjolano\n");

	if(argc < 3)
	{
		printf("usage: %s input.elf output.self\n", argv[0]);
		return 1;
	}

	uint8_t* elf_data;

	FILE* filep = fopen(argv[1], "rb");

	if(filep == NULL)
	{
		perror(argv[1]);
		return 1;
	}

	printf("Loading ELF to memory ...\n");

	fseek(filep, 0, SEEK_END);
	int elf_size = ftell(filep);
	fseek(filep, 0, SEEK_SET);

	elf_data = (uint8_t*)malloc(elf_size);

	if(elf_data == NULL)
	{
		perror("error");
		fclose(filep);
		return 1;
	}

	fread(elf_data, 1, elf_size, filep);
	fclose(filep);

	Elf64_Ehdr elf_header = {};
	memcpy(&elf_header, elf_data, sizeof(elf_header));

	// generate self header
	printf("Calculating offsets ...\n");

	sce_header sce_header = {};
	self_header self_header = {};
	app_info app_info = {};
	segment_info* segment_info_m;
	sceversion_info sceversion_info = {};
	sceversion_data sceversion_data = {};
	control_info control_info = {};

	uint32_t fself_header_size = sizeof(sce_header) + sizeof(self_header) + sizeof(app_info);

	uint64_t phdr_offset = _ES64(elf_header.e_phoff) + fself_header_size;
	uint16_t phdr_count = _ES16(elf_header.e_phnum);

	uint64_t section_info_offset = fself_header_size + _ES16(elf_header.e_ehsize) + (_ES16(elf_header.e_phentsize) * phdr_count);

	uint64_t sceversion_offset = section_info_offset + (phdr_count * sizeof(segment_info));

	uint64_t controlinfo_offset = sceversion_offset + sizeof(sceversion_info);

	sce_header.magic = _ES32(0x53434500);
	sce_header.version = _ES32(0x2);
	sce_header.keyrev = _ES16(0x8000);
	sce_header.type = _ES16(0x1);
	sce_header.meta_off = _ES32(controlinfo_offset + sizeof(sceversion_data) + (sizeof(control_info) / 2));
	sce_header.head_len = _ES64(controlinfo_offset + sizeof(sceversion_data) + sizeof(control_info));
	sce_header.data_len = _ES64(elf_size);

	uint64_t shdr_offset = _ES64(elf_header.e_shoff) + _ES64(sce_header.head_len);

	printf("Calculating segments ...\n");
	segment_info_m = (segment_info*)malloc(sizeof(segment_info) * phdr_count);

	int i;
	for(i = 0; i < phdr_count; i++)
	{
		Elf64_Phdr elf_phdr = {};
		segment_info segment_info = {};

		memcpy(&elf_phdr, elf_data + _ES64(elf_header.e_phoff) + (i * sizeof(elf_phdr)), sizeof(elf_phdr));

		segment_info.offset = _ES64(_ES64(elf_phdr.p_offset) + _ES64(sce_header.head_len));
		segment_info.size = elf_phdr.p_filesz;
		
		segment_info.compressed = _ES32(0x1);
		segment_info.encrypted = _ES32(0x2);

		segment_info_m[i] = segment_info;
	}

	self_header.header_type = _ES64(0x3);
	self_header.appinfo_offset = _ES64(0x70);
	self_header.elf_offset = _ES64(0x90);
	self_header.phdr_offset = _ES64(phdr_offset);
	self_header.shdr_offset = _ES64(shdr_offset);
	self_header.section_info_offset = _ES64(section_info_offset);
	self_header.sceversion_offset = _ES64(sceversion_offset);
	self_header.controlinfo_offset = _ES64(controlinfo_offset);
	self_header.controlinfo_length = _ES64(sizeof(control_info) + sizeof(sceversion_data));

	app_info.auth_id = _ES64(0x1010000001000003);
	app_info.vendor_id = _ES32(0x1000002);
	app_info.self_type = _ES32(0x4);
	app_info.version = _ES64(0x0001000000000000);

	sceversion_info.subheader_type = _ES32(0x1);
	sceversion_info.size = _ES32(sizeof(sceversion_info));

	sceversion_data.unknown2 = _ES16(0x1);
	sceversion_data.unknown3 = _ES32(sizeof(sceversion_data));
	sceversion_data.unknown5 = _ES32(0x1);

	control_info.type = _ES32(0x2);
	control_info.size = _ES32(sizeof(control_info));

	printf("Calculating hashes ...\n");

	uint8_t sha[SHA_DIGEST_LENGTH] = {0x62, 0x7c, 0xb1, 0x80, 0x8a, 0xb9, 0x38, 0xe3, 0x2c, 0x8c, 0x09, 0x17, 0x08, 0x72, 0x6a, 0x57, 0x9e, 0x25, 0x86, 0xe4};

	memcpy(control_info.digest1, sha, sizeof(control_info.digest1));
	SHA1(elf_data, elf_size, control_info.digest2);

	// write self
	printf("FSELF built - writing to file ...\n");

	filep = fopen(argv[2], "wb");

	if(filep == NULL)
	{
		perror(argv[2]);
		return 1;
	}

	fwrite(&sce_header, 1, sizeof(sce_header), filep);
	fwrite(&self_header, 1, sizeof(self_header), filep);
	fwrite(&app_info, 1, sizeof(app_info), filep);
	fwrite(elf_data, 1, _ES16(elf_header.e_ehsize) + (_ES16(elf_header.e_phentsize) * phdr_count), filep);
	fwrite(segment_info_m, 1, sizeof(segment_info) * phdr_count, filep);
	fwrite(&sceversion_info, 1, sizeof(sceversion_info), filep);
	fwrite(&sceversion_data, 1, sizeof(sceversion_data), filep);
	fwrite(&control_info, 1, sizeof(control_info), filep);
	fwrite(elf_data, 1, elf_size, filep);
	fclose(filep);

	printf("SELF file successfully written.\n");

	return 0;
}
