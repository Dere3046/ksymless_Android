// SPDX-License-Identifier: GPL-2.0-only
/*
 * verify.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include "core.h"
#include "verify.h"

typedef int (*reg_kp_t)(struct kprobe *);
typedef void (*unreg_kp_t)(struct kprobe *);

static reg_kp_t reg_kp;
static unreg_kp_t unreg_kp;
static int kprobe_ok;

static int probe_kprobe(void)
{
	reg_kp = (reg_kp_t)kallsyms_name_to_addr("register_kprobe");
	unreg_kp = (unreg_kp_t)kallsyms_name_to_addr("unregister_kprobe");

	if (!reg_kp || !unreg_kp) {
		kprobe_ok = -1;
		return 0;
	}

	unsigned long addr = kallsyms_name_to_addr("sprint_symbol");
	struct kprobe kp = {
		.addr = (kprobe_opcode_t *)addr,
		.flags = KPROBE_FLAG_DISABLED,
	};
	if (reg_kp(&kp) < 0) {
		kprobe_ok = -1;
		return 0;
	}
	unreg_kp(&kp);
	kprobe_ok = 1;
	return 1;
}

static unsigned long resolve_addr(const char *name)
{
	if (kprobe_ok == 0)
		probe_kprobe();
	if (kprobe_ok < 0)
		return 0;

	unsigned long addr = kallsyms_name_to_addr(name);
	if (!addr)
		return 0;

	struct kprobe kp = {
		.addr = (kprobe_opcode_t *)addr,
		.flags = KPROBE_FLAG_DISABLED,
	};
	if (reg_kp(&kp) < 0)
		return 0;
	unsigned long ret = (unsigned long)kp.addr;
	unreg_kp(&kp);
	return ret;
}

void verify_sct(void)
{
	unsigned long ref;

	if (!sys_call_table_addr)
		return;

	ref = resolve_addr("sys_call_table");
	if (!ref && kprobe_ok < 0) {
		pr_info("[ksymless] SCT: kprobe unavailable, skip\n");
		return;
	}
	if (!ref) {
		unsigned long addr = resolve_addr("kallsyms_lookup_name");
		if (!addr) {
			pr_info("[ksymless] SCT: lookup_name not found\n");
			return;
		}
		ref = (unsigned long)((unsigned long (*)(const char *))addr)("sys_call_table");
	}

	pr_info("[ksymless] SCT: ours=0x%lx kprobe=0x%lx %s\n",
		sys_call_table_addr, ref,
		sys_call_table_addr == ref ? "MATCH" : "MISMATCH");
}

void verify_kallsyms(void)
{
	unsigned long test_addr;
	char truth[256], our[256];

	test_addr = resolve_addr("kallsyms_lookup_name");
	if (!test_addr) {
		pr_info("[ksymless] verify: kprobe unavailable\n");
		return;
	}

	if (!klnum_val || !kloffs_addr || !klbase_addr ||
	    !klnames_addr || !kltable_addr || !klindex_addr) {
		pr_info("[ksymless] verify: kallsyms data incomplete\n");
		return;
	}

	pr_info("[ksymless] verify: bootstrapping...\n");

	sprint_symbol_no_offset(truth, test_addr);

	int idx = sym_name_at(test_addr, our, sizeof(our));
	pr_info("[ksymless] verify: addr->name '%s' %s\n",
		our, strcmp(truth, our) == 0 ? "MATCH" : "MISMATCH");

	unsigned long lookup = kallsyms_name_to_addr("kallsyms_lookup_name");
	pr_info("[ksymless] verify: name->addr 0x%lx %s\n",
		lookup,
		lookup == test_addr ? "MATCH" : "MISMATCH");

}

void dump_kallsyms_layout(void)
{
	if (!klbase_addr || !kloffs_addr) {
		pr_info("[ksymless] layout: insufficient data\n");
		return;
	}

	unsigned long diff = klbase_addr - kloffs_addr;
	unsigned int num = (unsigned int)(diff / 4);
	unsigned int m_cnt = (num + 255) / 256;

	pr_info("[ksymless] layout: %u symbols, %u markers\n", num, m_cnt);
}
