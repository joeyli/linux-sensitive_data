/* Sensitive data tree testing driver
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/sensitive_data.h>
#include <linux/slab.h>

#include <asm/page.h>

#define STATIC_SDATA "static sensitive data"

//TODO: test static array case
static unsigned long static_sdata[64];		/* 512 bytes */

/* dynamic allocadte sensitive data*/
struct sdata {
	unsigned long offset_in_region;	/* the offset in whole testing region */
	void *va;		/* virtual address */
	unsigned long pa;		/* physical address */
	unsigned long size;
	const char *name;
};

struct sdata sdata_case[7] = {
	{0, 0, 0, 4096, "4k page size"},			/* 4K page size case */
	{4096, 0, 0, 8, "align with page start"},		/* align with the start of page case */
	{(4096 + 2048), 0, 0, 16, "in the middle of page"},		/* in the middle of page */
	{4096 * 2 - 24, 0, 0, 24, "align with the end of page"},/* align with the end of page */
	{4096 * 3 - 32 / 2, 0, 0, 32, "cross page boundary"},	/* cross page boundary */
	{4096 * 4 - 24 - 40, 0, 0, 40, "neighbor"},		/* neighbor before cross pages */
	{4096 * 4 - 24, 0, 0, 8192 + 48, "cross pages"},		/* cross pages */
};

/* The testing region, all sensitive data cases are allocated from
 * this region.
 */
static unsigned long test_region_size = 4096 * 7;
static void *test_region;

static int sdata_test_probe(struct platform_device *pdev)
{
	return 0;
}

static int sdata_test_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct platform_device_id sdata_test_id[] = {
	{ KBUILD_MODNAME },
	{ },
};

static struct platform_driver sdata_test_driver = {
	.probe = sdata_test_probe,
	.remove = sdata_test_remove,
	.driver = {
		.name = KBUILD_MODNAME,
	},
	.id_table = sdata_test_id,
};

static unsigned long va_to_pa(void *vaddr)
{
	struct mm_struct *mm = current->mm;
	unsigned long va = (unsigned long) vaddr;
	unsigned long pa = 0;
	unsigned long page_addr = 0;
	unsigned long page_offset = 0;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd, _pmd;
	pte_t *pte;

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

	page_addr = PFN_PHYS(pte_pfn(*pte));
	page_offset = va & ~PAGE_MASK;
	pa = page_addr | page_offset;
	pr_info("pe_val: %#010llx	page_addr = %#010llx	page_offset = %#010llx\n", (unsigned long long) pte_val(*pte), (unsigned long long) page_addr, (unsigned long long)page_offset);
	pr_info("vaddr = %#010llx	physical addr = %#010llx\n", (unsigned long long)va, (unsigned long long)pa);

out:
	up_read(&mm->mmap_sem);
	return pa;
}

/* attributes */
static ssize_t start_va_show(struct device_driver *drv, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%#010llx\n", (unsigned long long) test_region);
}
static DRIVER_ATTR_RO(start_va);

static ssize_t start_pa_show(struct device_driver *drv, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%#010llx\n", (unsigned long long) virt_to_phys(test_region));
}
static DRIVER_ATTR_RO(start_pa);

static ssize_t size_show(struct device_driver *drv, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%ld\n", test_region_size);
}
static DRIVER_ATTR_RO(size);

static ssize_t static_sdata_va_show(struct device_driver *drv, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%#010llx\n", (unsigned long long) static_sdata);
}
static DRIVER_ATTR_RO(static_sdata_va);

static ssize_t static_sdata_pa_show(struct device_driver *drv, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%#010llx\n", (unsigned long long) va_to_pa(static_sdata));
}
static DRIVER_ATTR_RO(static_sdata_pa);

static ssize_t static_sdata_size_show(struct device_driver *drv, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%ld\n", sizeof(static_sdata));
}
static DRIVER_ATTR_RO(static_sdata_size);

static bool blanked;

static ssize_t blanked_show(struct device_driver *dev, char *buf)
{
	return snprintf(buf, 3, "%d\n", blanked);
}

static ssize_t blanked_store(struct device_driver *drv, const char *buf,
			    size_t count)
{
	bool new_state;
	int i, ret;

	ret = kstrtobool(buf, &new_state);
	if (ret)
		return ret;

	if (new_state == blanked)
		return -EINVAL;
		blanked = new_state;

	blanked = new_state;
	if (blanked)
		register_sensitive_data(static_sdata, sizeof(static_sdata), STATIC_SDATA);
	else
		unregister_sensitive_data(static_sdata, sizeof(static_sdata), STATIC_SDATA);

	for (i = 0; i < sizeof(sdata_case) / sizeof(struct sdata); i++) {
		if (blanked)
			register_sensitive_data(sdata_case[i].va, sdata_case[i].size, sdata_case[i].name);
		else
			unregister_sensitive_data(sdata_case[i].va, sdata_case[i].size, sdata_case[i].name);
		pr_info("%s Case %d %s		va: %#010llx	pa: %#010llx	size: %ld\n",
			(blanked) ? "Blanked" : "Unblanked",
			i, sdata_case[i].name, (unsigned long long) sdata_case[i].va,
			(unsigned long long) sdata_case[i].pa, sdata_case[i].size);
	}

	return count;
}
static DRIVER_ATTR_RW(blanked);

static struct driver_attribute *sdata_test_driver_attributes[] = {
					&driver_attr_start_va, &driver_attr_start_pa,
					&driver_attr_size, &driver_attr_blanked,
					&driver_attr_static_sdata_va, &driver_attr_static_sdata_pa,
					&driver_attr_static_sdata_size
				};

static __init int sdata_test_init(void)
{
	int i, rc = 0;

	/* static sensitive data */
	pr_info("static_sdata: %#010llx	%#010llx	%ld\n", (unsigned long long) static_sdata, (unsigned long long) va_to_pa(static_sdata), sizeof(static_sdata));
	pr_info("pa: %#010llx va:%#010llx\n", virt_to_phys(static_sdata), phys_to_virt(virt_to_phys(static_sdata)));
	memset(static_sdata, 0x11, sizeof(static_sdata));
	register_sensitive_data(static_sdata, sizeof(static_sdata), "static sensitive data");

	/* dynamic sensitive data */
	test_region = kmalloc(test_region_size, GFP_KERNEL);
	memset(test_region, 0x11, test_region_size);
	for (i = 0; i < sizeof(sdata_case) / sizeof(struct sdata); i++) {
		sdata_case[i].va = (void *) (test_region + sdata_case[i].offset_in_region);
		sdata_case[i].pa = virt_to_phys(sdata_case[i].va);
		register_sensitive_data(sdata_case[i].va, sdata_case[i].size, sdata_case[i].name);
		pr_info("Case %d %s		va: %#010llx	pa: %#010llx	size: %ld\n",
			i, sdata_case[i].name, (unsigned long long) sdata_case[i].va,
			(unsigned long long) sdata_case[i].pa, sdata_case[i].size);
		pr_info("pa: %#010llx va:%#010llx\n", virt_to_phys(sdata_case[i].va), phys_to_virt(virt_to_phys(sdata_case[i].va)));
	}
	blanked = true;

	rc = platform_driver_register(&sdata_test_driver);
	if (rc)
		goto err_register;

	i = 0;
	while (!rc && i < ARRAY_SIZE(sdata_test_driver_attributes)) {
		rc = driver_create_file(&sdata_test_driver.driver, sdata_test_driver_attributes[i]);
		i++;
	}

 err_register:
	return rc;
}

static __exit void sdata_test_exit(void)
{
	int i;

	unregister_sensitive_data(static_sdata, sizeof(static_sdata), STATIC_SDATA);

	/* unregister sensitive data */
	for (i = 0; i < sizeof(sdata_case) / sizeof(struct sdata); i++)
		unregister_sensitive_data(sdata_case[i].va, sdata_case[i].size, sdata_case[i].name);

	platform_driver_unregister(&sdata_test_driver);
}

module_init(sdata_test_init);
module_exit(sdata_test_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Lee, Chun-Yi");
