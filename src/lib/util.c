
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

#include "util.h"

/*
 * like snprintf & vsnprintf, but always return number of char
 * written, this allows usage like this:
 *
 * len += scnprintf(buf + len, size - len, ...)
 */
int
vscnprintf(char *buf, size_t size, const char *format, va_list args)
{
	int ret;

	if (!size)
		return 0;
	ret = vsnprintf(buf, size, format, args);
	if ((size_t)ret > size - 1)
		return size - 1;
	return ret;
}

int
scnprintf(char *buf, size_t size, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vscnprintf(buf, size, format, ap);
	va_end(ap);
	return ret;
}
