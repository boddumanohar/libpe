/*
	pev - the PE file analyzer toolkit

	pedis.c - PE disassembler

	Copyright (C) 2012 - 2017 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.
*/

//#include "common.h"
#include "../lib/libudis86/udis86.h"
//#include <errno.h>
#include <limits.h>
//#include "plugins.h"


#define SPACES 32 // spaces # for text-based output

#define SYN_ATT 1
#define SYN_INTEL 0

char *insert_spaces(const char *s)
{
	size_t size;
	char *new;

	size = strlen(s);

	if (!size)
		return NULL;

	size = size + (size/2);

	new = malloc_s(size+1);
	memset(new, 0, size+1);

	for (unsigned int i=0, j=0, pos=0; i < size; i++)
	{
		if (pos==2)
		{
			new[i] = ' ';
			pos=0;
		}
		else
		{
			new[i] = s[j++];
			pos++;
		}
	}
	return new;
}

bool is_ret_instruction(unsigned char opcode)
{
	switch (opcode)
	{
		case 0xc9: // leave
		//case 0xc2: // ret
		case 0xc3: // ret
		case 0xca: // retf
		//case 0xcb: // retf
			return true;

		default:
			return false;
	}
}

void _disassemble_offset(pe_ctx_t *ctx, const options_t *options, ud_t *ud_obj, uint64_t offset)
{
	if (ctx == NULL || offset == 0)
		return;

	uint64_t instr_counter = 0; // counter for disassembled instructions
	uint64_t byte_counter = 0; // counter for disassembled bytes

	while (ud_disassemble(ud_obj))
	{
		char ofs[MAX_MSG], value[MAX_MSG], *bytes;
		const uint8_t *opcode = ud_insn_ptr(ud_obj);

		instr_counter++; // increment instruction counter
		byte_counter += ud_insn_len(ud_obj);

		if (options->nbytes && byte_counter >= options->nbytes)
			return;

		const ud_mnemonic_code_t mnic = ud_insn_mnemonic(ud_obj);
		const ud_operand_t *operand = ud_insn_opr(ud_obj, 0);
		const ud_type_t op_type = operand != NULL ? operand->type : 0;

		snprintf(ofs, MAX_MSG, "%"PRIx64, (options->offset_is_rva ? ctx->pe.imagebase : 0) + offset + ud_insn_off(ud_obj));
		bytes = insert_spaces(ud_insn_hex(ud_obj));

		if (!bytes)
			return;

		// correct near operand addresses for calls and jumps if (op_type && (op_type != UD_OP_MEM) && (mnic == UD_Icall || (mnic >= UD_Ijo && mnic <= UD_Ijmp)))
		{
			char *instr_asm = strdup(ud_insn_asm(ud_obj));
			char *instr = strtok(instr_asm, "0x");

			snprintf(value,
				MAX_MSG,
				"%s%*c%s%#"PRIx64,
				bytes,
				SPACES - (int) strlen(bytes),
				' ',
				instr ? instr : "",
				ctx->pe.imagebase + offset + ud_insn_off(ud_obj) + ud_obj->operand[0].lval.sdword + ud_insn_len(ud_obj)
			);
			free(instr_asm);
		}
		else
			snprintf(value, MAX_MSG, "%s%*c%s", bytes, SPACES - (int) strlen(bytes), ' ', ud_insn_asm(ud_obj));

		free(bytes);
		output(ofs, value);

		// for sections, we stop at end of section
		if (options->section && instr_counter >= options->ninstructions)
			break;
		else if (instr_counter >= options->ninstructions && options->ninstructions)
			break;
		else if (options->entrypoint)
		{
			// search for LEAVE or RET insrtuctions
			for (unsigned int i=0; i < ud_insn_len(ud_obj); i++)
				if (is_ret_instruction(opcode[i]))
					return;
		}
	}
}

bool is_okay() {
IMAGE_OPTIONAL_HEADER *optional = pe_optional(&ctx);
	if (optional == NULL)
		return EXIT_FAILURE;

	ud_t ud_obj; // libudis86 object
	ud_init(&ud_obj);

	uint8_t mode_bits = 0;
	switch (optional->type) {
		default:
			EXIT_ERROR("Unsupported architecture.");
			return EXIT_FAILURE;
		case MAGIC_PE32: mode_bits = 32; break;
		case MAGIC_PE64: mode_bits = 64; break;
	}

	// set disassembly mode according with PE architecture
	ud_set_mode(&ud_obj, options->mode ? options->mode : mode_bits);

	uint64_t offset = 0;         // offset to start disassembly

	if (options->entrypoint)
		offset = pe_rva2ofs(&ctx, ctx.pe.entrypoint);
	else if (options->offset)
		offset = options->offset_is_rva ? pe_rva2ofs(&ctx, options->offset) : options->offset;
	else if (options->section) {
		IMAGE_SECTION_HEADER *section = pe_section_by_name(&ctx, options->section);

		if (section) { // section found
			offset = section->PointerToRawData;
			if (!options->ninstructions)
				options->ninstructions = section->SizeOfRawData;
		}
		else
			EXIT_ERROR("invalid section name");
	} else {
		usage();
		return EXIT_FAILURE;
	}

	if (!offset) {
		fprintf(stderr, "unable to reach file offset (%#"PRIx64")\n", offset);
		return EXIT_FAILURE;
	}

}

void prepare() {
ud_set_syntax(&ud_obj, options->syntax ? UD_SYN_ATT : UD_SYN_INTEL);
	ud_set_input_buffer(&ud_obj, ctx.map_addr, pe_filesize(&ctx));
	//ud_set_input_file(&ud_obj, ctx.stream);
	ud_input_skip(&ud_obj, offset);

}

int disassemble_offset()
{
	_disassemble_offset(&ctx, options, &ud_obj, offset);

	return EXIT_SUCCESS;
}

// TODO : see what has to be done about argument s
//
