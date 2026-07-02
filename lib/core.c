// SPDX-License-Identifier: GPL-2.0-only
/*
 * core.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <asm/compiler.h>
#ifndef ptrauth_strip_kernel_insn_pac
#define ptrauth_strip_kernel_insn_pac(x) (x)
#endif
#include "core.h"

int safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

unsigned long read_fp(void)
{
	unsigned long fp;
	asm volatile("mov %0, x29\n" : "=r"(fp));
	return fp;
}

int is_ktxt(unsigned long addr)
{
	unsigned long v;
	if (addr < 0xFFFF800000000000ULL)
		return 0;
	return read_val(addr, &v);
}

int read_val(unsigned long addr, unsigned long *val)
{
	return !safe_read(val, (void *)addr, sizeof(*val));
}

int walk_stack(struct fp_ret *out, int max)
{
	unsigned long fp = read_fp();
	unsigned long tmp;
	int n = 0;

	for (int i = 0; i < max; i++) {
		if (!fp)
			break;
		if (safe_read(&tmp, (void *)(fp + 8), sizeof(tmp)))
			break;
		out[n].addr = ptrauth_strip_kernel_insn_pac(tmp);
		n++;
		if (safe_read(&fp, (void *)fp, sizeof(fp)))
			break;
	}
	return n;
}

void dump_frames(struct fp_ret *frames, int n)
{
	pr_info("[ksymless] x29 stack (%d frames):\n", n);
	for (int i = 0; i < n; i++)
		pr_info("  [%2d] 0x%lx\n", i, frames[i].addr);
}

unsigned long sys_call_table_addr;
unsigned long b_target_found;

static unsigned int adrp_buf[MAX_SCAN];

int scan_adrp_add(unsigned long base, int ninst,
		  struct adrp_entry *out, int max)
{
	int found = 0;

	if (ninst > MAX_SCAN)
		ninst = MAX_SCAN;
	if (safe_read(adrp_buf, (void *)base, ninst * 4))
		return 0;

	for (int i = 0; i < ninst - 2 && found < max; i++) {
		unsigned int adrp = adrp_buf[i];
		if ((adrp & 0x9F000000) != 0x90000000)
			continue;

		int rd = adrp & 0x1F;
		unsigned int nxt = adrp_buf[i + 1];
		unsigned long imm12;
		int valid = 0;

		if ((nxt & 0xFFC00000) == 0x91000000)
			valid = ((nxt >> 5) & 0x1F) == rd &&
				(nxt & 0x1F) == rd;
		if (!valid && (nxt & 0xFFC00000) == 0xF9400000)
			valid = ((nxt >> 5) & 0x1F) == rd &&
				(nxt & 0x1F) == rd;
		if (!valid)
			continue;

		imm12 = (nxt >> 10) & 0xFFF;
		unsigned long immhi = (adrp >> 5) & 0x7FFFF;
		unsigned long immlo = (adrp >> 29) & 3;
		unsigned long imm = (immhi << 2) | immlo;
		unsigned long pc = base + i * 4;

		out[found].pc = pc;
		out[found].target = (pc & ~0xFFF) + (imm << 12) + imm12;
		out[found].rd = rd;
		out[found].has_b = 0;
		out[found].b_target = 0;

		unsigned int bop = adrp_buf[i + 2];
		if ((bop & 0xFC000000) == 0x14000000) {
			long imm26 = bop & 0x3FFFFFF;
			if (imm26 & 0x2000000)
				imm26 |= ~0x3FFFFFF;
			out[found].has_b = 1;
			out[found].b_target = pc + 2 * 4 + imm26 * 4;
		} else if ((bop & 0xFC000000) == 0x94000000) {
			long imm26 = bop & 0x3FFFFFF;
			if (imm26 & 0x2000000)
				imm26 |= ~0x3FFFFFF;
			out[found].has_b = 2;
			out[found].b_target = pc + 2 * 4 + imm26 * 4;
		}

		found++;
	}
	return found;
}

static int check_sct(unsigned long addr)
{
	unsigned long v;
	for (int i = 0; i < 20; i++) {
		if (!read_val(addr + i * 8, &v))
			return 0;
		if (!is_ktxt(v))
			return 0;
	}
	return 1;
}

unsigned long find_sct(struct fp_ret *frames, int nf)
{
	struct adrp_entry adrps[MAX_ADRP];
	int na;
	unsigned long best = 0;

	pr_info("[ksymless] scanning frames for do_el0_svc:\n");

	for (int i = nf - 1; i >= 0; i--) {
		unsigned long addr = frames[i].addr;
		if (addr < 0xFFFF800000000000ULL)
			continue;
		unsigned long base = addr - 128;
		na = scan_adrp_add(base, MAX_SCAN, adrps, MAX_ADRP);
		if (!na)
			continue;

		for (int j = 0; j < na; j++) {
			if (!adrps[j].has_b)
				continue;
			unsigned long sct = adrps[j].target;
			if (!check_sct(sct))
				continue;
			pr_info("[ksymless] SCT candidate @ 0x%lx\n", sct);
			if (!best) {
				best = sct;
				sys_call_table_addr = sct;
				b_target_found = adrps[j].b_target;
			}
		}
	}

	if (!best)
		pr_info("[ksymless] SCT not found\n");
	return best;
}

void dump_sct(void)
{
	unsigned long v;
	pr_info("[ksymless] sys_call_table entries:\n");
	for (int i = 0; i < 8; i++)
		if (read_val(sys_call_table_addr + i * 8, &v))
			pr_info("  [%3d] 0x%lx\n", i, v);
}

unsigned long sprint_addr;
unsigned long kernel_base;
unsigned long klbase_addr;
unsigned long klbase_val;
unsigned long kloffs_addr;
unsigned long klindex_addr;
unsigned long klseqs_addr;
unsigned int  klnum_val;
unsigned long klmarks_addr;
unsigned long kltable_addr;
unsigned long klnames_addr;
unsigned long klnum_addr;

unsigned long (*ksymless_klp)(const char *name);

static unsigned int bigbuf[16 * 1024];

static int check_token_index(unsigned short *ti)
{
	if (ti[0] != 0)
		return 0;
	for (int i = 1; i < 256; i++)
		if (ti[i] <= ti[i - 1])
			return 0;
	return 1;
}

static void find_kloffs_by_signature(unsigned long start)
{
	int best_len = 0;
	unsigned long best_addr = 0;

	for (unsigned long pg = start; ; pg += 16 * 0x1000) {
		if (safe_read(bigbuf, (void *)pg, 16 * 0x1000))
			break;

		for (int pi = 0; pi < 16; pi++) {
			unsigned int *buf = &bigbuf[pi * 1024];
			unsigned long base = pg + pi * 0x1000;

			for (int off = 0; off < 0x1000; off += 4) {
				if (buf[off / 4] != 0)
					continue;

				if (off < 512)
					continue;
				unsigned short *ti = (unsigned short *)((unsigned char *)buf + off - 512);
				if (!check_token_index(ti))
					continue;

				unsigned long ti_kern = base + off - 512;
				unsigned long cand = ti_kern + 512;
				if (cand & 7)
					cand = (cand + 7) & ~7ULL;

				unsigned int z;
				if (safe_read(&z, (void *)cand, 4) || z != 0)
					continue;

				int vok = 1;
				unsigned int ovals[4];
				int skip = 0;
				for (skip = 0; skip < 20; skip++) {
					u32 zv;
					if (safe_read(&zv, (void *)(cand + skip * 4), 4))
						break;
					if (zv != 0)
						break;
				}
				for (int i = 0; i < 4 && vok; i++) {
					ovals[i] = 0;
					if (safe_read(&ovals[i], (void *)(cand + (skip + i) * 4), 4))
						break;
					char name[64];
					sprint_symbol(name, klbase_val + ovals[i]);
					if (name[0] == '0' && name[1] == 'x')
						vok = 0;
				}
				if (!vok)
					continue;

				int len = 0, prev = -1;
				for (int i = 0; i < 500000; i++) {
					unsigned int v;
					if (safe_read(&v, (void *)(cand + i * 4), 4))
						break;
					if ((int)v < prev)
						break;
					prev = (int)v;
					len++;
				}

				if (len > best_len) {
					best_len = len;
					best_addr = cand;
				}
			}
		}
	}

	kloffs_addr = best_addr;
	klnum_val = best_len;
}

void find_kallsyms_base(void)
{
	sprint_addr = (unsigned long)&sprint_symbol;
	kernel_base = sprint_addr & ~0x1FFFFFULL;
	klbase_val = kernel_base;

	unsigned long start = kernel_base + 0x100000;

	find_kloffs_by_signature(start);

	if (!kloffs_addr) {
		pr_info("[ksymless] layout: offsets not found\n");
		return;
	}

	klbase_addr = (kloffs_addr + klnum_val * 4 + 7) & ~7ULL;
	klseqs_addr = klbase_addr + 8;
	klindex_addr = kloffs_addr - 512;

	u64 v64;
	if (!safe_read(&v64, (void *)klbase_addr, 8))
		klbase_val = v64;

	if (klindex_addr && klnum_val) {
		unsigned short ti255;
		if (!safe_read(&ti255, (void *)(klindex_addr + 255 * 2), 2)) {
			unsigned long pos = klindex_addr - 1;
			unsigned char c;
			while (pos > 0) {
				if (safe_read(&c, (void *)pos, 1) || c != 0)
					break;
				pos--;
			}
			while (pos > 0) {
				if (safe_read(&c, (void *)pos, 1))
					break;
				if (c == 0)
					break;
				pos--;
			}
			kltable_addr = pos + 1 - ti255;
		}
	}

	if (kltable_addr && klnum_val) {
		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned long marks_size = markers_cnt * 4;
		unsigned long marks_end = (kltable_addr + 7) & ~7ULL;
		klmarks_addr = marks_end - marks_size;
	}

	if (klmarks_addr && klnum_val) {
		unsigned long end_addr = klmarks_addr > 0x300000 ?
			klmarks_addr - 0x300000 : kernel_base;
		end_addr &= ~3ULL;
		for (unsigned long addr = klmarks_addr & ~3ULL;
		     addr >= end_addr; addr -= 4) {
			unsigned int v32;
			if (safe_read(&v32, (void *)addr, 4))
				continue;
			if (v32 == klnum_val) {
				klnum_addr = addr;
				break;
			}
		}
	}

	if (klnum_addr)
		klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;

	if (klbase_addr && kloffs_addr) {
		unsigned long addr = kallsyms_name_to_addr("kallsyms_lookup_name");
		if (addr)
			ksymless_klp = (unsigned long (*)(const char *))addr;
	}

	pr_info("[ksymless] %u symbols\n", klnum_val);
}

unsigned long sym_addr(int idx)
{
	u32 off;
	if (safe_read(&off, (void *)(kloffs_addr + idx * 4), 4))
		return 0;
	return klbase_val + off;
}

int expand_sym(unsigned int off, char *buf, int max)
{
	unsigned char lb;
	unsigned int len;
	if (safe_read(&lb, (const void *)(klnames_addr + off), 1))
		return 0;
	len = lb;
	unsigned int off1 = off + 1;

	if (len & 0x80) {
		if (safe_read(&lb, (const void *)(klnames_addr + off1), 1))
			return 0;
		len = (len & 0x7F) | (lb << 7);
		off1++;
	}

	int skipped = 0;
	for (unsigned int i = 0; i < len && max > 1; i++) {
		unsigned char c;
		if (safe_read(&c, (const void *)(klnames_addr + off1 + i), 1))
			return 0;
		unsigned short ti;
		if (safe_read(&ti, (const void *)(klindex_addr + c * 2), 2))
			return 0;
		unsigned int ti_idx = ti;
		const char *tptr = (const char *)(kltable_addr + ti_idx);
		while (*tptr) {
			if (skipped) {
				*buf++ = *tptr;
				max--;
			} else {
				skipped = 1;
			}
			tptr++;
		}
	}
	if (max)
		*buf = '\0';
	return (int)(off1 + len - off);
}

unsigned int get_sym_seq(int idx)
{
	unsigned int i, seq = 0;

	if (klseqs_addr) {
		unsigned char buf[3];
		if (safe_read(buf, (const void *)(klseqs_addr + idx * 3), 3))
			return (unsigned int)idx;
		for (i = 0; i < 3; i++)
			seq = (seq << 8) | buf[i];
		return seq;
	}
	return (unsigned int)idx;
}

unsigned int get_sym_offset(unsigned int seq)
{
	const u8 *p = (const u8 *)klnames_addr;
	unsigned char lb;
	for (unsigned int i = 0; i < seq; i++) {
		if (safe_read(&lb, (void *)p, 1))
			return 0;
		int len = lb;
		if (len & 0x80) {
			if (safe_read(&lb, (void *)(p + 1), 1))
				return 0;
			len = ((len & 0x7F) | (lb << 7)) + 1;
		}
		p = p + len + 1;
	}
	return p - (const u8 *)klnames_addr;
}

unsigned long kallsyms_name_to_addr(const char *name)
{
	int low = 0, high = (int)klnum_val - 1;
	char nbuf[256];

	while (low <= high) {
		int mid = low + (high - low) / 2;
		unsigned int seq = get_sym_seq(mid);
		unsigned int off = get_sym_offset(seq);
		expand_sym(off, nbuf, sizeof(nbuf));
		int r = strcmp(name, nbuf);
		if (r > 0)
			low = mid + 1;
		else if (r < 0)
			high = mid - 1;
		else
			return sym_addr(seq);
	}
	return 0;
}

int sym_name_at(unsigned long addr, char *buf, int max)
{
	int low = 0, high = (int)klnum_val;

	while (high - low > 1) {
		int mid = low + (high - low) / 2;
		if (sym_addr(mid) <= addr)
			low = mid;
		else
			high = mid;
	}

	unsigned int off = get_sym_offset(low);
	expand_sym(off, buf, max);
	return low;
}
