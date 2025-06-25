/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

int scnprintf(char *buf, size_t size, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

int vscnprintf(char *buf, size_t size, const char *format, va_list args);
