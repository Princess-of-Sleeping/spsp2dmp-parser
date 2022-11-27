
#include <string.h>
#include <stdio.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


int AesCbcDecrypt(const void *src, void *dst, size_t length, const void *key, int key_size, void *iv){

	EVP_CIPHER_CTX *de;
	int p_len = length;

	de = EVP_CIPHER_CTX_new();

	EVP_CIPHER_CTX_init(de);

	if(key_size == 128){
		EVP_DecryptInit_ex(de, EVP_aes_128_cbc(), NULL, key, iv);
	}else if(key_size == 192){
		EVP_DecryptInit_ex(de, EVP_aes_192_cbc(), NULL, key, iv);
	}else if(key_size == 256){
		EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, key, iv);
	}

	EVP_DecryptUpdate(de, dst, &p_len, src, length);

	EVP_CIPHER_CTX_cleanup(de);

	return 0;
}

typedef struct { // size is 0x30-bytes
	char magic[8];			// "\x0\x0FACECS"
	uint64_t version;

	uint64_t hmac_key_id;		// always 1 ?
	uint64_t number_of_sections;

	uint64_t header_size;
	uint64_t total_sections_size;
} Spsp2dmpHeader_t;

typedef struct { // size is 0x40-bytes
	uint64_t section_id;
	uint64_t section_start_offset;

	uint64_t section_length;
	uint64_t hmac_key_id;

	uint64_t encryption_key_id;	// Always 2 ?
	char encryption_iv[0x10];
	uint64_t Filler;
} Spsp2dmpSectionMetaBlock_t;

typedef struct { // size is 0x30-bytes
	uint64_t section_id;
	char hmac_hash[0x20];
	uint64_t Filler;
} Spsp2dmpSectionHashBlock_t;

typedef struct { // size is 0x20-bytes
	char hmac_hash[0x20];
} Spsp2dmpHeaderHashBlock_t;


const char spsp2dmp_encryption_key[0x20] = {
	0xC8, 0x15, 0xC3, 0x6F, 0xF2, 0xF8, 0x95, 0x64, 0xA2, 0xF7, 0xAE, 0x13, 0xCB, 0x6D, 0x47, 0xAC,
	0xE2, 0xA1, 0x28, 0xF5, 0x26, 0x36, 0xF2, 0x90, 0x58, 0x87, 0x1F, 0x64, 0xAD, 0x6D, 0x99, 0xDE
};

const char ce_kek[0x10] = {
	0x84, 0x5C, 0x65, 0x5B, 0x50, 0x3B, 0x54, 0x71, 0x7A, 0xDD, 0x49, 0x99, 0x43, 0x6B, 0x5B, 0x5B
};

const char ce_iv[0x10] = {
	0x08, 0x09, 0x0A, 0x0C, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

const char coredump_encryption_iv[0x10] = {
	0x0B, 0xE6, 0x47, 0x73, 0x40, 0xC4, 0x46, 0x0F, 0xDB, 0xB9, 0xC0, 0x2D, 0xB1, 0x3C, 0xE9, 0x64
};


typedef struct KernelInfo {
	struct KernelInfo *next;
	const char *name;
	const void *data;
	int size;
} KernelInfo;

typedef struct SceKernelProcessDecryptContext {
	void *spsp2dmp;
	void *psp2dmp;
	void *kernel_info;
	char coredump_encryption_key[0x20];
} SceKernelProcessDecryptContext;

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;

#define EI_NIDENT (16)

typedef struct {
	unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
	Elf32_Half	e_type;			/* Object file type */
	Elf32_Half	e_machine;		/* Architecture */
	Elf32_Word	e_version;		/* Object file version */
	Elf32_Addr	e_entry;		/* Entry point virtual address */
	Elf32_Off	e_phoff;		/* Program header table file offset */
	Elf32_Off	e_shoff;		/* Section header table file offset */
	Elf32_Word	e_flags;		/* Processor-specific flags */
	Elf32_Half	e_ehsize;		/* ELF header size in bytes */
	Elf32_Half	e_phentsize;		/* Program header table entry size */
	Elf32_Half	e_phnum;		/* Program header table entry count */
	Elf32_Half	e_shentsize;		/* Section header table entry size */
	Elf32_Half	e_shnum;		/* Section header table entry count */
	Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;

typedef struct {
	Elf32_Word	p_type;			/* Segment type */
	Elf32_Off	p_offset;		/* Segment file offset */
	Elf32_Addr	p_vaddr;		/* Segment virtual address */
	Elf32_Addr	p_paddr;		/* Segment physical address */
	Elf32_Word	p_filesz;		/* Segment size in file */
	Elf32_Word	p_memsz;		/* Segment size in memory */
	Elf32_Word	p_flags;		/* Segment flags */
	Elf32_Word	p_align;		/* Segment alignment */
} Elf32_Phdr;

typedef int (* elf_parse_callback)(const Elf32_Phdr *pPhdr, void *argp);

int elf_do_parse(const void *elf_data, elf_parse_callback callback, void *argp){

	int res;
	const Elf32_Ehdr *pEhdr;
	const Elf32_Phdr *pPhdr;

	pEhdr = elf_data;
	pPhdr = elf_data + pEhdr->e_phoff;

	for(int i=0;i<pEhdr->e_phnum;i++){
		res = callback(&(pPhdr[i]), argp);
		if(res < 0){
			return res;
		}
	}

	return 0;
}

int kernel_info_elf_parse_callback(const Elf32_Phdr *pPhdr, void *argp){

	SceKernelProcessDecryptContext *ctx = argp;

	printf("KERNEL_INFO - type:0x%X paddr:0x%08X filesz:0x%X\n", pPhdr->p_type, pPhdr->p_paddr, pPhdr->p_filesz);

	char iv[0x10], path[0x400];

	if(pPhdr->p_type == 4){
		memcpy(iv, ce_iv, sizeof(iv));
		AesCbcDecrypt(
			ctx->kernel_info + pPhdr->p_offset + 0x44,
			ctx->coredump_encryption_key,
			0x20,
			ce_kek,
			128,
			iv
		);
	}else{
		memcpy(iv, coredump_encryption_iv, sizeof(iv));
		AesCbcDecrypt(
			ctx->kernel_info + pPhdr->p_offset,
			ctx->kernel_info + pPhdr->p_offset,
			pPhdr->p_filesz,
			ctx->coredump_encryption_key,
			256,
			iv
		);
	}

	snprintf(path, sizeof(path), "./KERNEL_INFO-%d_0x%08X.bin", pPhdr->p_type, pPhdr->p_paddr);

	FILE *fd = fopen(path, "wb");
	if(fd != NULL){
		fwrite(ctx->kernel_info + pPhdr->p_offset, pPhdr->p_filesz, 1, fd);
		fclose(fd);
		fd = NULL;
	}

	return 0;
}

int psp2dmp_elf_parse_callback(const Elf32_Phdr *pPhdr, void *argp){

	SceKernelProcessDecryptContext *ctx = argp;
	char path[0x400];

	const char *name = ctx->psp2dmp + pPhdr->p_offset + 0xC;

	printf("[%-27s] 0x%X\n", name, pPhdr->p_filesz);

	if(strcmp(name, "KERNEL_INFO") == 0){
		ctx->kernel_info = ctx->psp2dmp + pPhdr->p_offset + 0x28;
		elf_do_parse(ctx->kernel_info, kernel_info_elf_parse_callback, ctx);
	}else{
		snprintf(path, sizeof(path), "./%s.bin", name);
		FILE *fd = fopen(path, "wb");
		if(fd != NULL){
			fwrite(ctx->psp2dmp + pPhdr->p_offset, pPhdr->p_filesz, 1, fd);
			fclose(fd);
			fd = NULL;
		}
	}

	return 0;
}

int gzip_decompress(void *out, uInt outsize, void *in, uInt insize){

	int res, res2;
	z_stream ds;

	memset(&ds, 0, sizeof(ds));
	ds.zalloc    = Z_NULL;
	ds.zfree     = Z_NULL;
	ds.opaque    = Z_NULL;
	ds.next_in   = in;
	ds.avail_in  = insize;
	ds.next_out  = out;
	ds.avail_out = outsize;

	res = inflateInit2(&ds, MAX_WBITS + 16);
	if(res < 0){
		return res;
	}

	res = inflate(&ds, Z_FINISH);
	if(res < 0){
		return res;
	}

	res2 = inflateEnd(&ds);
	if(res2 < 0){
		res = res2;
	}

	return res;
}

int main(int argc, char **argp){

	int res;
	FILE *fd;

	SceKernelProcessDecryptContext ctx;

	memset(&ctx, 0, sizeof(ctx));

	size_t spsp2dmp_size = 0x8000000; // 128MiB

	ctx.spsp2dmp = malloc(spsp2dmp_size);

	fd = fopen("./psp2core-SceKernelProcess.spsp2dmp", "rb");
	if(fd == NULL){
		printf("Failed open to .spsp2dmp\n");
		return EXIT_FAILURE;
	}

	res = fread(ctx.spsp2dmp, 1, spsp2dmp_size, fd);
	if(res < 0){
		free(ctx.spsp2dmp);
		ctx.spsp2dmp = NULL;
	}

	spsp2dmp_size = res;

	fclose(fd);
	fd = NULL;

	if(ctx.spsp2dmp == NULL){
		printf("Failed file read\n");
		return EXIT_FAILURE;
	}

	char iv[0x10];

	memset(iv, 0, sizeof(iv));

	AesCbcDecrypt(ctx.spsp2dmp + 0x130, ctx.spsp2dmp + 0x130, spsp2dmp_size - 0x130, spsp2dmp_encryption_key, 128, ctx.spsp2dmp + 0x58);

	long unsigned int psp2dmp_size = *(size_t *)(ctx.spsp2dmp + 0x40);

	long unsigned int temp_size = *(uint32_t *)(ctx.spsp2dmp + 0x130 + psp2dmp_size - 4);
	ctx.psp2dmp = malloc(temp_size);

	res = gzip_decompress(ctx.psp2dmp, temp_size, ctx.spsp2dmp + 0x130, psp2dmp_size);

	free(ctx.spsp2dmp);
	ctx.spsp2dmp = NULL;

	if(res < 0){
		printf("gzip_decompress: %d\n", res);
		free(ctx.psp2dmp);
		return EXIT_FAILURE;
	}

	fd = fopen("./psp2core-SceKernelProcess.psp2dmp", "wb");
	if(fd != NULL){
		fwrite(ctx.psp2dmp, temp_size, 1, fd);

		fclose(fd);
		fd = NULL;
	}else{
		printf("Failed open to .psp2dmp\n");
	}

	elf_do_parse(ctx.psp2dmp, psp2dmp_elf_parse_callback, &ctx);

	free(ctx.psp2dmp);

	return 0;
}
