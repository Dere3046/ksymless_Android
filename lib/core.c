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
#include <linux/version.h>
#include <asm/compiler.h>
#ifndef ptrauth_strip_kernel_insn_pac
#define ptrauth_strip_kernel_insn_pac(x) (x)
#endif
#include "core.h"

#ifdef KSYMLESS_DEBUG
#define ks_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define ks_dbg(fmt, ...) do {} while (0)
#endif

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
ks_dbg("[ksymless] x29 stack (%d frames):\n", n);
	for (int i = 0; i < n; i++)
ks_dbg("  [%2d] 0x%lx\n", i, frames[i].addr);
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

ks_dbg("[ksymless] scanning frames for do_el0_svc:\n");

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
ks_dbg("[ksymless] SCT candidate @ 0x%lx\n", sct);
			if (!best) {
				best = sct;
				sys_call_table_addr = sct;
				b_target_found = adrps[j].b_target;
			}
		}
	}

	if (!best)
ks_dbg("[ksymless] SCT not found\n");
	return best;
}

void dump_sct(void)
{
	unsigned long v;
ks_dbg("[ksymless] sys_call_table entries:\n");
	for (int i = 0; i < 8; i++)
		if (read_val(sys_call_table_addr + i * 8, &v))
ks_dbg("  [%3d] 0x%lx\n", i, v);
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

int is_v1_layout;

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

static void find_kloffs_v2(unsigned long start)
{
	int best_len = 0;
	unsigned long best_addr = 0;
	unsigned long best_ti = 0;
#ifdef KSYMLESS_DEBUG
	int off_hits = 0, ti_ok = 0, spr_pass = 0, spr_fail = 0, pages = 0;
#endif

	for (unsigned long pg = start; ; pg += 16 * 0x1000) {
		if (safe_read(bigbuf, (void *)pg, 16 * 0x1000)) {
ks_dbg("[ksymless] v2 scan term pg=0x%lx (%d pages)\n", pg, pages);
			break;
		}
		pages++;

		for (int pi = 0; pi < 16; pi++) {
			unsigned int *buf = &bigbuf[pi * 1024];
			unsigned long base = pg + pi * 0x1000;

			for (int off = 0; off < 0x1000; off += 4) {
				if (buf[off / 4] != 0)
					continue;
				off_hits++;
				if (pi == 0 && off < 512)
					continue;
				unsigned short *ti = (unsigned short *)((unsigned char *)buf + off - 512);
				if (!check_token_index(ti))
					continue;
				ti_ok++;

				unsigned long ti_kern = base + off - 512;
				unsigned long cand = ti_kern + 512;
				if (cand & 7)
					cand = (cand + 7) & ~7ULL;

				unsigned int z;
				if (safe_read(&z, (void *)cand, 4) || z != 0)
					continue;

				char name[KSYM_SYMBOL_LEN];
				unsigned int ovals[4];
				int skip = 0;
				for (skip = 0; skip < 20; skip++) {
					u32 zv;
					if (safe_read(&zv, (void *)(cand + skip * 4), 4))
						break;
					if (zv != 0)
						break;
				}
				int vok = 1;
				for (int i = 0; i < 4 && vok; i++) {
					ovals[i] = 0;
					if (safe_read(&ovals[i], (void *)(cand + (skip + i) * 4), 4))
						break;
					sprint_symbol(name, klbase_val + ovals[i]);
					if (name[0] == '0' && name[1] == 'x')
						vok = 0;
				}
				if (!vok) {
#ifdef KSYMLESS_DEBUG
					spr_fail++;
#endif
					continue;
				}
#ifdef KSYMLESS_DEBUG
				spr_pass++;
#endif

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

				ks_dbg("[ksymless] ti hit pg=0x%lx sorted=%d\n",
					base, len);

				if (len > best_len) {
					best_len = len;
					best_addr = cand;
					best_ti = ti_kern;
				}
			}
		}
	}

	kloffs_addr = best_addr;
	klnum_val = best_len;
	klindex_addr = best_ti;

ks_dbg("[ksymless] off_hits=%d ti_ok=%d spr_pass=%d spr_fail=%d\n",
		off_hits, ti_ok, spr_pass, spr_fail);
ks_dbg("[ksymless] v2 best: addr=0x%lx sorted=%u\n", best_addr, best_len);
}

static int discover_v1(unsigned long ti_addr)
{
	int best_len = 0;
	unsigned long best_addr = 0;
	int pages = 0;

	for (unsigned long pg = ti_addr & ~0xFFFULL; pg >= kernel_base; pg -= 16 * 0x1000) {
		if (safe_read(bigbuf, (void *)pg, 16 * 0x1000))
			continue;
		pages++;

		for (int pi = 15; pi >= 0; pi--) {
			unsigned int *buf = &bigbuf[pi * 1024];
			unsigned long base = pg + pi * 0x1000;

			for (int off = 0; off < 0x1000; off += 4) {
				int run = 0, prev = -1;
				int max_i = (4096 - off) / 4;
				for (int i = 0; i < max_i; i++) {
					unsigned int v = buf[(off + i * 4) / 4];
					if ((int)v < prev)
						break;
					prev = (int)v;
					run++;
				}
				if (run < max_i)
					continue;

				unsigned long cand = base + off;
				for (int i = run; i < 500000; i++) {
					unsigned int v;
					if (safe_read(&v, (void *)(cand + i * 4), 4))
						break;
					if ((int)v < prev)
						break;
					prev = (int)v;
					run++;
				}

				if (run < best_len || run < 10000)
					continue;

				unsigned long rb_check = (cand + run * 4 + 7) & ~7ULL;
				if (rb_check >= ti_addr + 0x10000)
					continue;
				u64 rb;
				if (safe_read(&rb, (void *)rb_check, 8))
					continue;
				if ((rb & ~0x1FFFFFULL) != kernel_base)
					continue;
				unsigned long ns_check = (rb_check + 8 + 7) & ~7ULL;
				unsigned int ns;
				if (safe_read(&ns, (void *)ns_check, 4) || ns != (unsigned int)run)
					continue;

				int skip = 0;
				for (skip = 0; skip < 20; skip++) {
					u32 zv;
					if (safe_read(&zv, (void *)(cand + skip * 4), 4))
						break;
					if (zv != 0)
						break;
				}
				u32 v0;
				char name[KSYM_SYMBOL_LEN];
				if (safe_read(&v0, (void *)(cand + skip * 4), 4))
					continue;
				sprint_symbol(name, klbase_val + v0);
				if (name[0] == '0' && name[1] == 'x')
					continue;

				ks_dbg("[ksymless] v1 hit pg=0x%lx sorted=%d %s\n",
					base, run, name);

				if (run > best_len) {
					best_len = run;
					best_addr = cand;
				}
			}
		}
	}

	if (!best_addr)
		return 0;
	kloffs_addr = best_addr;
	klnum_val = best_len;
	klindex_addr = ti_addr;
ks_dbg("[ksymless] v1 best: addr=0x%lx sorted=%u (%d pages)\n",
		best_addr, best_len, pages);
	return 1;
}

static unsigned long find_token_index(unsigned long start)
{
	for (unsigned long pg = start; ; pg += 16 * 0x1000) {
		if (safe_read(bigbuf, (void *)pg, 16 * 0x1000))
			break;

		for (int pi = 0; pi < 16; pi++) {
			unsigned int *buf = &bigbuf[pi * 1024];
			unsigned long base = pg + pi * 0x1000;

			for (int off = 512; off < 0x1000; off += 4) {
				unsigned short *ti = (unsigned short *)((unsigned char *)buf + off - 512);
				if (ti[0] != 0)
					continue;
				if (!check_token_index(ti))
					continue;
				return base + off - 512;
			}
		}
	}
	return 0;
}

void find_kallsyms_base(void)
{
	sprint_addr = (unsigned long)&sprint_symbol;
	kernel_base = sprint_addr & ~0x1FFFFFULL;
	klbase_val = kernel_base;

ks_dbg("[ksymless] sprint=0x%lx kernel_base=0x%lx\n",
		sprint_addr, kernel_base);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	is_v1_layout = 0;
	find_kloffs_v2(sprint_addr);
#else
	is_v1_layout = 1;
	unsigned long ti_addr = find_token_index(sprint_addr & ~0xFFFULL);
	if (!ti_addr) {
ks_dbg("[ksymless] token_index not found\n");
		return;
	}
ks_dbg("[ksymless] ti=0x%lx\n", ti_addr);
	if (!discover_v1(ti_addr)) {
ks_dbg("[ksymless] layout: offsets not found\n");
		return;
	}
#endif

	if (!kloffs_addr) {
ks_dbg("[ksymless] layout: offsets not found\n");
		return;
	}

	if (is_v1_layout) {
		unsigned long rb_addr = (kloffs_addr + klnum_val * 4 + 7) & ~7ULL;
		klbase_addr = rb_addr;
		u64 v64;
		if (!safe_read(&v64, (void *)rb_addr, 8))
			klbase_val = v64;
		klnum_addr = (rb_addr + 8 + 7) & ~7ULL;
		{
			u32 ns;
			if (safe_read(&ns, (void *)klnum_addr, 4) || ns != klnum_val)
				klnum_addr = 0;
		}
		klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;

		for (unsigned long pg = klnames_addr; ; pg += 16 * 0x1000) {
			if (safe_read(bigbuf, (void *)pg, 16 * 0x1000))
				break;
			for (int pi = 0; pi < 16; pi++) {
				unsigned int *buf = &bigbuf[pi * 1024];
				unsigned long base = pg + pi * 0x1000;
				for (int off = 512; off < 0x1000; off += 4) {
					unsigned short *ti = (unsigned short *)((unsigned char *)buf + off - 512);
					if (ti[0] != 0)
						continue;
					if (!check_token_index(ti))
						continue;
					klindex_addr = base + off - 512;
					goto found_index;
				}
			}
		}
found_index:

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
					if (pos + 1 > ti255)
					kltable_addr = pos + 1 - ti255;
			}
		}

		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned long marks_size = markers_cnt * 4;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
		klseqs_addr = (kltable_addr - klnum_val * 3) & ~7ULL;
		klmarks_addr = (klseqs_addr - marks_size) & ~7ULL;
#else
		klseqs_addr = 0;
		klmarks_addr = (kltable_addr - marks_size) & ~7ULL;
#endif
	} else {
		klbase_addr = (kloffs_addr + klnum_val * 4 + 7) & ~7ULL;
		klseqs_addr = klbase_addr + 8;

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
					if (pos + 1 > ti255)
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
	}

ks_dbg("[ksymless] kallsyms data:\n");
ks_dbg("  klbase  @ 0x%lx = 0x%lx\n", klbase_addr, klbase_val);
ks_dbg("  kloffs  @ 0x%lx\n", kloffs_addr);
ks_dbg("  klnum   @ 0x%lx = %u\n", klnum_addr, klnum_val);
ks_dbg("  klindex @ 0x%lx\n", klindex_addr);
ks_dbg("  klseqs  @ 0x%lx\n", klseqs_addr);
ks_dbg("  kltable @ 0x%lx\n", kltable_addr);
ks_dbg("  klmarks @ 0x%lx\n", klmarks_addr);
ks_dbg("  klnames @ 0x%lx\n", klnames_addr);
	ks_dbg("  layout  v%d\n", is_v1_layout ? 1 : 2);

	if (klbase_addr && kloffs_addr) {
		unsigned long addr = kallsyms_name_to_addr("kallsyms_lookup_name");
		if (addr)
			ksymless_klp = (unsigned long (*)(const char *))addr;
	}
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
		{
			unsigned long tp = kltable_addr + ti_idx;
			for (;;) {
				unsigned char ch;
				if (safe_read(&ch, (const void *)tp, 1))
					break;
				if (!ch)
					break;
				if (skipped) {
					if (max <= 1)
						break;
					*buf++ = ch;
					max--;
				} else {
					skipped = 1;
				}
				tp++;
			}
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
