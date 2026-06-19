// SPDX-License-Identifier: GPL-2.0-only
/*
 * verify.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef VERIFY_H
#define VERIFY_H

unsigned long resolve(const char *name);
void verify_sct(void);
void verify_kallsyms(void);
void dump_kallsyms_layout(void);

#endif
