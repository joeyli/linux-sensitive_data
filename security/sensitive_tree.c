/* Sensitive data tree
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <linux/list_sort.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/page.h>

struct sensitive_data {
	const char *name;
	unsigned long pa;
	unsigned long va;
	unsigned long size;
	struct list_head list;
};

struct sensitive_page {
	spinlock_t lock;			/* used for update/delete */
	unsigned long pfn;
        struct list_head sdata_list;
};

/*
 * Radix tree of sensitive data, indexed by pfn.
 */
static DEFINE_SPINLOCK(sensitive_page_tree_lock);
static RADIX_TREE(sensitive_page_tree, GFP_ATOMIC);

static inline unsigned long size_inside_page(unsigned long addr,
					     unsigned long size)
{
	unsigned long sz;

	sz = PAGE_SIZE - (addr & (PAGE_SIZE - 1));

	return min(sz, size);
}

static int walk_page_table(unsigned long va, unsigned long *pa, unsigned long *pfn)
{
        struct mm_struct *mm = current->mm;
	unsigned long page_addr = 0;
        unsigned long page_offset = 0;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd, _pmd;
	pte_t *pte;
	int ret = -EINVAL;

	down_read(&mm->mmap_sem);

	pgd = pgd_offset(mm, va);
	if (!pgd_present(*pgd))
		goto out;
	p4d = p4d_offset(pgd, va);
	if (!p4d_present(*p4d))
		goto out;
	pud = pud_offset(p4d, va);
	if (!pud_present(*pud))
		goto out;
	pmd = pmd_offset(pud, va);

	/* make sure the pmd value isn't cached in a register */
	_pmd = READ_ONCE(*pmd);
	if (!pmd_present(_pmd))
		goto out;
	if (pmd_trans_huge(_pmd))
		goto out;
	pte = pte_offset_map(pmd, va);

	if (pfn)
		*pfn = pte_pfn(*pte);
	page_addr = PFN_PHYS(pte_pfn(*pte));
        page_offset = va & ~PAGE_MASK;
	if (pa)
		*pa = page_addr | page_offset;
	ret = 0;
	pr_debug("Found physical address. va: %#010llx	pa: %#010llx\n",
		 (unsigned long long) va, (unsigned long long) *pa);
out:
	up_read(&mm->mmap_sem);
	return ret;
}

static unsigned long va_to_pa(void *va, unsigned long *pfn)
{
	unsigned long pa = virt_to_phys(va);

	if (pfn)
		*pfn = page_to_pfn(virt_to_page(va));
	/* walk page table for static variable */
	if (phys_to_virt(pa) != va &&
	    walk_page_table((unsigned long) va, &pa, pfn))
		pa = 0;

	return pa;
}

static int add_sensitive_data(unsigned long start_va, unsigned long size,
				const char *name)
{
	struct sensitive_page *spage;
	struct sensitive_data *sdata;
	unsigned long pfn;
	int ret = 0;

	if (unlikely(start_va < TASK_SIZE_MAX) || !size)
		return -EINVAL;

	sdata = kmalloc(sizeof(*sdata), GFP_KERNEL);
	if (!sdata)
		return -ENOMEM;
//	sdata->pa = virt_to_phys((void *) start_va);
	sdata->pa = va_to_pa((void *) start_va, &pfn);
	sdata->va = start_va;
	sdata->size = size;
	sdata->name = name;
	INIT_LIST_HEAD(&sdata->list);
/*
	pfn = page_to_pfn(virt_to_page(start_va));

	// walk page table for static variable
	if ((unsigned long) phys_to_virt(sdata->pa) != sdata->va &&
	    walk_page_table(sdata->va, &sdata->pa, &pfn)) {
		ret = -EINVAL;
		goto err;
	}
*/
	if (!sdata->pa) {
		ret = -EINVAL;
		goto err;
	}
	pr_debug("Add sensitive data	va: %#010llx	pfn: %ld\n",
		 (unsigned long long) start_va, pfn);

        rcu_read_lock();
        spage = radix_tree_lookup(&sensitive_page_tree, pfn);
        rcu_read_unlock();

	if (!spage) {
		spage = kmalloc(sizeof(*sdata), GFP_KERNEL);
		if (!spage) {
			ret = -ENOMEM;
			goto err;
		}
		spin_lock_init(&spage->lock);
		spage->pfn = pfn;
		INIT_LIST_HEAD(&spage->sdata_list);
		spin_lock(&sensitive_page_tree_lock);
		ret = radix_tree_insert(&sensitive_page_tree, pfn, spage);
		spin_unlock(&sensitive_page_tree_lock);
	}

	spin_lock(&spage->lock);
	list_add_tail_rcu(&sdata->list, &spage->sdata_list);
	spin_unlock(&spage->lock);

	return ret;
err:
	kfree(sdata);
	return ret;
}

static int remove_sensitive_data(unsigned long va, unsigned long size,
				 const char *name)
{
	struct sensitive_page *spage;
	struct sensitive_data *sdata;
	unsigned long pa, pfn;
	int ret = 0;

	if (unlikely(va < TASK_SIZE_MAX) || !size)
		return -EINVAL;
/*
	pa = virt_to_phys((void *) va);
	pfn = page_to_pfn(virt_to_page(va));
	if ((unsigned long) phys_to_virt(pa) != va &&
	    walk_page_table(va, &pa, &pfn)) {
		ret = -EINVAL;
		goto err;
	}
*/
	pa = va_to_pa((void *) va, &pfn);
	if (!pa)  {
		ret = -EINVAL;
		goto err;
	}

        rcu_read_lock();
        spage = radix_tree_lookup(&sensitive_page_tree, pfn);
        rcu_read_unlock();

	if (spage)
	{
		struct sensitive_data *found = NULL;

		list_for_each_entry_rcu(sdata, &spage->sdata_list, list)
		{
			if ((sdata->pa == pa) && (sdata->size == size) &&
			    (sdata->name == name)) {
				found = sdata;
				break;
			}
		}

		if (found) {
			spin_lock(&spage->lock);
			list_del_rcu(&found->list);
			spin_unlock(&spage->lock);
			kfree(found);
		}
	}

err:
	return ret;
}

int register_sensitive_data(void *start_va, unsigned long size, const char *name)
{
	unsigned long start = (unsigned long) start_va;
	ssize_t sz;
	int ret;

	if (!start_va || !size)
		return -EINVAL;

	while (size > 0) {
		sz = size_inside_page(start, size);
		ret = add_sensitive_data(start, sz, name);
		size -= sz;
		start += sz;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(register_sensitive_data);

int unregister_sensitive_data(void *start_va, unsigned long size,
			      const char *name)
{
	unsigned long start = (unsigned long) start_va;
	ssize_t sz;
	int ret;

	if (!start_va || !size)
		return -EINVAL;

	while (size > 0) {
		sz = size_inside_page(start, size);
		ret = remove_sensitive_data(start, sz, name);
		size -= sz;
		start += sz;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(unregister_sensitive_data);

static bool in_sensitive_page_pa(unsigned long pa)
{
	void *spage;

        rcu_read_lock();
        spage = radix_tree_lookup(&sensitive_page_tree, PHYS_PFN(pa));
        rcu_read_unlock();
	return (spage != NULL);
}

static bool in_sensitive_page_va(void *va)
{
	return in_sensitive_page_pa(va_to_pa(va, NULL));
}

bool has_sensitive_data_pa(unsigned long start, unsigned long size)
{
	ssize_t sz;

	if (in_sensitive_page_pa(start) || in_sensitive_page_pa(start + size - 1))
		return true;

	while (size > 0) {
		sz = size_inside_page(start, size);
		size -= sz;
		start += sz;
		if (in_sensitive_page_pa(start))
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(has_sensitive_data_pa);

bool has_sensitive_data_va(void *start, unsigned long size)
{
	ssize_t sz;

	if (in_sensitive_page_va(start) || in_sensitive_page_va(start + size - 1))
		return true;

	while (size > 0) {
		sz = size_inside_page((unsigned long) start, size);
		size -= sz;
		start += sz;
		if (in_sensitive_page_va(start))
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(has_sensitive_data_va);

static int blank_sensitive_data_impl(unsigned long start_pa,
				     void *start_va,
				     unsigned long size, void *buf)
{
	unsigned long end_pa = start_pa + size - 1;
	struct sensitive_page *spage;
	struct sensitive_data *sdata;
	unsigned long pfn;
	ssize_t blanked = 0;
pr_info("blank_sensitive_data_impl() start_va: %#010llx		size: %ld\n", (unsigned long long) start_va, size);
	pfn = PHYS_PFN(start_pa);
        rcu_read_lock();
        spage = radix_tree_lookup(&sensitive_page_tree, pfn);
        rcu_read_unlock();

	if (spage)
	{
		unsigned long sdata_start;
		unsigned long sdata_end;
		unsigned long blank_start, blank_end, blank_size;
		unsigned long offset;

		list_for_each_entry_rcu(sdata, &spage->sdata_list, list)
		{
			sdata_start = sdata->pa;
			sdata_end = sdata->pa + sdata->size - 1;
                        pr_info("sdata->pa: %#010llx\n", (unsigned long long) sdata->pa);
                        pr_info("sdata->va: %#010llx\n", (unsigned long long) sdata->va);
                        pr_info("sdata->size: %ld\n", sdata->size);
			if ((sdata_end < start_pa) || (sdata_start > end_pa))
				continue;
			/* double check va before blanking */
			if (start_va && virt_to_page(start_va) != virt_to_page(sdata->va)) {
				pr_warn("The virtual address doesn't match.\n");
				continue;
			}
			blank_start = max(start_pa, sdata_start);
			blank_end = min(end_pa, sdata_end);
			blank_size = blank_end - blank_start + 1;
			offset = blank_start - start_pa;
                        pr_info("blank_start: %#010llx\n", (unsigned long long) blank_start);
                        pr_info("blank_end: %#010llx\n", (unsigned long long) blank_end);
                        pr_info("blank_size: %ld\n", blank_size);
                        pr_info("offset: %#010llx\n", (unsigned long long) offset);
			if (blank_size) {
				memset(buf + offset, 0, blank_size);
				blanked += blank_size;
				pr_info("blanked+= %d\n", blanked);
			}
		}
	}

	return blanked;
}

/* the buff is a copy that the start address link with start_va */
ssize_t blank_sensitive_data_va(void *va, unsigned long size, void *buf)
{
	unsigned long pa;
	ssize_t sz, blanked = 0;

	if (!va || !size || !buf)
		return -EINVAL;

	while (size > 0) {
/*
		pa = virt_to_phys(va);
		if (phys_to_virt(pa) != va &&
		    walk_page_table((unsigned long) va, &pa, NULL))
			return -EINVAL;
*/
		pa = va_to_pa(va, NULL);
		if (!pa)
			return -EINVAL;
		sz = size_inside_page(pa, size);
		blanked += blank_sensitive_data_impl(pa, va, sz, buf);
		size -= sz;
		va += sz;
		buf += sz;
	}

	pr_info("blank_sensitive_data_va() blanked: %ld", blanked);
	return blanked;
}
EXPORT_SYMBOL_GPL(blank_sensitive_data_va);

ssize_t blank_sensitive_data_pa(unsigned long pa, unsigned long size,
				void *buf)
{
	ssize_t sz, blanked = 0;

	if (!pa || !size || !buf)
		return -EINVAL;

	while (size > 0) {
		sz = size_inside_page(pa, size);
		blanked += blank_sensitive_data_impl(pa, NULL, sz, buf);
		size -= sz;
		pa += sz;
		buf += sz;
	}

	pr_info("blank_sensitive_data_pa() blanked: %ld", blanked);
	return blanked;
}
EXPORT_SYMBOL_GPL(blank_sensitive_data_pa);
