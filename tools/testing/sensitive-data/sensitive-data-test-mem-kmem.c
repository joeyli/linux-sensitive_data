/* Sensitive data tree - mem and kmem testing
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define STATIC_SDATA_VA_FILE "/sys/bus/platform/drivers/sensitive_data_test/static_sdata_va"
#define STATIC_SDATA_PA_FILE "/sys/bus/platform/drivers/sensitive_data_test/static_sdata_pa"
#define STATIC_SDATA_SIZE_FILE "/sys/bus/platform/drivers/sensitive_data_test/static_sdata_size"

#define START_VA_FILE "/sys/bus/platform/drivers/sensitive_data_test/start_va"
#define START_PA_FILE "/sys/bus/platform/drivers/sensitive_data_test/start_pa"
#define SIZE_FILE "/sys/bus/platform/drivers/sensitive_data_test/size"

struct sensitive_area {
	unsigned long va;
	unsigned long pa;
	unsigned long size;
};

static struct sensitive_area static_area = {0};
static struct sensitive_area dynamic_area = {0};

struct blanked_region {
	unsigned long offset;		/* offset of a blanked region */
	unsigned long size;
};

struct test_case {
	struct sensitive_area *area;		/* the area that it includes sensitive data */
	unsigned long offset;			/* start address of case */
	unsigned long window_size;
	struct blanked_region b_regions[5];
	const char *case_name;
};

/*
sensitive data cases:
struct sdata sdata_case[7] = {
        {0, 0, 0, 4096, "4k page size"},                        // 4K page size case

        {4096, 0, 0, 8, "align with page start"},               // align with the start of page case
        {(4096 + 2048), 0, 0, 16, "in the middle of page"},             // in the middle of page
        {4096 * 2 - 24, 0, 0, 24, "align with the end of page"},// align with the end of page

        {4096 * 3 - 32 / 2, 0, 0, 32, "cross page boundary"},   // cross page boundary

        {4096 * 4 - 24 - 40, 0, 0, 40, "neighbor"},             // neighbor before cross pages
        {4096 * 4 - 24, 0, 0, 8192 + 48, "cross pages"},                // cross pages
*/

#define WINDOW1 4096
#define WINDOW2 512

#define TEST_OFFSET_1 0
#define TEST_OFFSET_2 4096 * 0.5
#define TEST_OFFSET_3 4096
#define TEST_OFFSET_4 4096 * 2
#define TEST_OFFSET_5 4096 * 2.5

struct test_case test_cases[] = {
	{&static_area, TEST_OFFSET_1, WINDOW2, {{0, 512}}, "Window1-static-offset1"},
	{&dynamic_area, TEST_OFFSET_1, WINDOW1, {{0, 4096}}, "Window1-dynamic-offset1"},
	{&dynamic_area, TEST_OFFSET_2, WINDOW1, {{0, 2048 + 8}, {0, 8}}, "window1-dynamic-offset2"},
	{&dynamic_area, TEST_OFFSET_3, WINDOW1, {{0, 8}, {2048, 16}, {4096 - 24, 24}}, "window1-dynamic-offset3"},
	{&dynamic_area, TEST_OFFSET_4, WINDOW1, {{4096 - 32 / 2, 32 / 2}}, "window1-dynamic-offset4"},
	{&dynamic_area, TEST_OFFSET_5, WINDOW1, {{2048 - 32 / 2, 32}}, "window1-dynamic-offset5"},
};

static unsigned long read_sysfs_ul(const char *filename)
{
	int fd;
	char buff[19] = {0};

	fd = open(filename, O_RDONLY);
	read(fd, buff, 18);
	close(fd);
	buff[18] = '\0';

	return strtoul(buff, NULL, 16);
}

static int run_testcase(struct test_case tcase, const char *sysfs,
			unsigned long start_addr)
{
	void *window, *window_expect;
	int size, fd, i, ret;
	unsigned long not_match;

	start_addr += tcase.offset;
	printf("Window start (%s):	0x%016lx\n", sysfs, start_addr);

	window = malloc(tcase.window_size);
	memset(window, 0x00, tcase.window_size);

	/* the expect result of window for comparing */
	window_expect = malloc(tcase.window_size);
	memset(window_expect, 0x11, tcase.window_size);
	for (i = 0; i < sizeof(tcase.b_regions) / sizeof(struct blanked_region); i++) {
		struct blanked_region b_region = tcase.b_regions[i];
		memset(window_expect + b_region.offset, 0x00, b_region.size);
	}

	fd = open(sysfs, O_RDONLY);
	if (fd < 0)
	{
		printf("open %s failed", sysfs);
		ret = -1;
		goto err;
	}

	lseek(fd, (off_t) start_addr, SEEK_SET);
	ret = (read(fd, window, tcase.window_size) == tcase.window_size);
	close(fd);

	if (ret) {
		unsigned long *w = window;
		unsigned long *w_expect = window_expect;
		unsigned long not_match = 0;

		for (i = 0; i < tcase.window_size/sizeof(unsigned long); i++) {
			if (w[i] != w_expect[i]) {
				printf("%04d	%016lx	expected: %016lx\n", i, w[i], w_expect[i]);
				not_match++;
			}
		}
		if (not_match)
			printf("	%ld bytes are not matched\n", not_match * 8);
		else
			printf("	Testing pass\n");
		ret = not_match;
	} else
		printf("%s read failed\n", sysfs);

err:
	free(window);
	free(window_expect);
	return ret;
}

int main(int argc, char **argv)
{
	int i;
/*
	static_sdata_va = read_sysfs_ul(STATIC_SDATA_VA_FILE);
	static_sdata_pa = read_sysfs_ul(STATIC_SDATA_PA_FILE);
	static_sdata_size = read_sysfs_ul(STATIC_SDATA_SIZE_FILE);
*/
	static_area.va = read_sysfs_ul(STATIC_SDATA_VA_FILE);
	static_area.pa = read_sysfs_ul(STATIC_SDATA_PA_FILE);
	static_area.size = read_sysfs_ul(STATIC_SDATA_SIZE_FILE);

	printf("Static test region by sensitive-data-test driver:\n");
	printf("	static_sdata_va: 0x%016lx\n", static_area.va);
	printf("	static_sdata_pa: 0x%016lx\n", static_area.pa);
	printf("	static_sdata_size: 0x%016lx\n", static_area.size);
	printf("\n");

	//run_static_sdata_testcase("/dev/kmem");

	dynamic_area.va = read_sysfs_ul(START_VA_FILE);
	dynamic_area.pa = read_sysfs_ul(START_PA_FILE);
	dynamic_area.size = read_sysfs_ul(SIZE_FILE);

	printf("Dynamic test region by sensitive-data-test driver:\n");
	printf("	start_va: 0x%016lx\n", dynamic_area.va);
	printf("	start_pa: 0x%016lx\n", dynamic_area.pa);
	printf("	size: 0x%016lx\n", dynamic_area.size);

	for (i = 0; i < sizeof(test_cases) / sizeof(struct test_case); i++) {
		printf("\n%s\n", test_cases[i].case_name);
		run_testcase(test_cases[i], "/dev/kmem", test_cases[i].area->va);
//		run_testcase(test_cases[i], "/dev/mem", 0x44c7b620);
		run_testcase(test_cases[i], "/dev/mem", test_cases[i].area->pa);
	//	run_testcase(test_cases[i], "/dev/kmem", 0xffffffffc0000000);
//		run_testcase(test_cases[i], "/dev/mem", test_cases[i].area->va - 0xffffffff80000000);
	//	run_testcase(test_cases[i], "/dev/mem", 0xffffffffc0000000 - 0xffffffff80000000);
	}

	//TODO: unregister testing
	return 0;
}
