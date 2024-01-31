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

#define _STACK_SIZE_ADJUSTMENT (32 * 1024)

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (8 * 1024 + _STACK_SIZE_ADJUSTMENT)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef sgx_thread_t       korp_tid;
typedef sgx_thread_mutex_t korp_mutex;
typedef sgx_thread_cond_t  korp_cond;

typedef void* korp_rwlock;
typedef void* korp_sem;
typedef void* os_raw_file_handle;
typedef void* os_file_handle;
typedef void* os_dir_stream;

typedef void (*os_print_function_t)(const char *message);

void wasm_os_set_print_function(os_print_function_t pf);

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
