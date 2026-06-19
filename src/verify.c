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

unsigned long resolve(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
		.flags = KPROBE_FLAG_DISABLED,
	};
	if (register_kprobe(&kp) < 0)
		return 0;
	unsigned long addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

void verify_sct(void)
{
	unsigned long ref;

	if (!sys_call_table_addr)
		return;

	ref = resolve("sys_call_table");
	if (!ref)
		ref = (unsigned long)((unsigned long (*)(const char *))
			resolve("kallsyms_lookup_name"))("sys_call_table");

	pr_info("[ksymless] SCT: ours=0x%lx kprobe=0x%lx %s\n",
		sys_call_table_addr, ref,
		sys_call_table_addr == ref ? "MATCH" : "MISMATCH");
}

void verify_kallsyms(void)
{
	unsigned long test_addr;
	char truth[256], our[256];

	test_addr = resolve("kallsyms_lookup_name");
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
