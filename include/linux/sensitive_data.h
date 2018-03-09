/* Sensitive data tree
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef __SENSITIVE_DATA_H
#define __SENSITIVE_DATA_H

#ifdef CONFIG_SENSITIVE_DATA_TREE
extern int register_sensitive_data(void *start_va, unsigned long size, const char *name);
extern int unregister_sensitive_data(void *start_va, unsigned long size, const char *name);
extern bool has_sensitive_data_va(void *start_va, unsigned long size);
extern bool has_sensitive_data_pa(unsigned long start_pa, unsigned long size);
extern int blank_sensitive_data_va(void *start_va, unsigned long sz, void *kbuf);
extern int blank_sensitive_data_pa(unsigned long start_pa, unsigned long size, void *buf);
#else
static inline int register_sensitive_data(void *start_va, unsigned long size, const char *name)
{
       return 0;
}
static inline int unregister_sensitive_data(void *start_va, unsigned long size, const char *name)
{
	return 0;
}
static inline bool has_sensitive_data_va(void *start_va, unsigned long size)
{
	return false;
}
static inline bool has_sensitive_data_pa(unsigned long start_pa, unsigned long size)
{
	return false;
}
static inline int blank_sensitive_data_va(void *start_va, unsigned long sz, void *kbuf)
{
	return 0;
}
static inline int blank_sensitive_data_pa(unsigned long start_pa, unsigned long size, void *buf)
{
	return 0;
}
#endif

#endif /* ! __SENSITIVE_DATA_H */
