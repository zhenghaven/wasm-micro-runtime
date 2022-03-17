/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_thread.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BH_PLATFORM_LINUX_SGX
typedef sgx_thread_t       korp_tid;
typedef sgx_thread_mutex_t korp_mutex;
typedef sgx_thread_cond_t  korp_cond;
#endif

#define os_malloc        wasm_os_malloc
#define os_realloc       wasm_os_realloc
#define os_free          wasm_os_free
#define os_printf        wasm_os_printf
#define os_vprintf       wasm_os_vprintf

#define os_time_get_boot_microsecond   wasm_os_time_get_boot_microsecond

#define os_thread_get_stack_boundary   wasm_os_thread_get_stack_boundary

#define os_self_thread   wasm_os_self_thread
#define os_mutex_init    wasm_os_mutex_init
#define os_mutex_destroy wasm_os_mutex_destroy
#define os_mutex_lock    wasm_os_mutex_lock
#define os_mutex_unlock  wasm_os_mutex_unlock

#define os_mmap          wasm_os_mmap
#define os_munmap        wasm_os_munmap
#define os_mprotect      wasm_os_mprotect
#define os_dcache_flush  wasm_os_dcache_flush

#define os_cond_init     wasm_os_cond_init
#define os_cond_destroy  wasm_os_cond_destroy

#define _STACK_SIZE_ADJUSTMENT (32 * 1024)

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (8 * 1024 + _STACK_SIZE_ADJUSTMENT)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef void (*os_print_function_t)(const char *message);

void os_set_print_function(os_print_function_t pf);

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
