/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <getopt.h>

#include "util.h"
#include "option.h"

/* sheep options */

#define SD_OPT_NONE     0x00
#define SD_OPT_STRING   0x01
#define SD_OPT_NUMBER   0x02
#define SD_OPT_BOOL     0x04
#define SD_OPT_SIZE     0x08

void sd_opt_usage(struct sd_option *opt, const char *arg,
		  const char *desc)
{
	struct sd_opt_param *param;
	bool header_is_printed = false;

	if (!opt->params)
		return;

	fprintf(stderr, "\n");
	fprintf(stderr, "%s\n", desc);

	sd_for_each_opt_param(param, opt->params) {
		char s[256];
		if (strcmp(param->arg, arg) != 0)
			continue;

		if (!header_is_printed) {
			fprintf(stderr, "  -%c %s[:option[,option[,...]]]\n",
				opt->ch, arg);
			fprintf(stderr, "  OPTIONS:\n");
			header_is_printed = true;
		}
		snprintf(s, sizeof(s), "%s=%s", param->key, param->usage);
		fprintf(stderr, "    %-32s%s\n", s, param->desc);
	}

	if (!header_is_printed)
		fprintf(stderr, "  -%c %s\n", opt->ch, arg);
}

bool sd_opt_is_number(const struct sd_opt_value *val)
{
	return !!(val->type & SD_OPT_NUMBER);
}

bool sd_opt_is_bool(const struct sd_opt_value *val)
{
	return !!(val->type & SD_OPT_BOOL);
}

bool sd_opt_is_size(const struct sd_opt_value *val)
{
	return !!(val->type & SD_OPT_SIZE);
}

bool sd_opt_is_valid_number(const struct sd_opt_value *val,
			    int64_t min_val, int64_t max_val)
{
	return sd_opt_is_number(val) &&
		min_val <= val->num && val->num <= max_val;
}

char *build_short_options(const struct sd_option *sd_opts)
{
	static char sopts[256], *p;
	const struct sd_option *opt;

	p = sopts;
	sd_for_each_option(opt, sd_opts) {
		*p++ = opt->ch;
		if (opt->has_arg)
			*p++ = ':';
	}
	*p = '\0';

	return sopts;
}

struct option *build_long_options(const struct sd_option *sd_opts)
{
	static struct option lopts[256], *p;
	const struct sd_option *opt;

	p = lopts;
	sd_for_each_option(opt, sd_opts) {
		p->name = opt->name;
		p->has_arg = opt->has_arg;
		p->flag = NULL;
		p->val = opt->ch;
		p++;
	}
	memset(p, 0, sizeof(struct option));

	return lopts;
}

static void parse_sd_opt_value(struct sd_opt_value *val, const char *str)
{
	char *p, *postfix;
	double sizef;

	val->str = xstrdup(str);
	val->type = SD_OPT_STRING;

	val->num = strtoll(str, &p, 10);
	if (str < p)
		val->type |= SD_OPT_NUMBER;

	if (strcasecmp(str, "true") == 0 || strcasecmp(str, "t") == 0 ||
	    strcasecmp(str, "on") == 0 || strcmp(str, "1") == 0) {
		val->boolean = true;
		val->type |= SD_OPT_BOOL;
	} else if (strcasecmp(str, "false") == 0 || strcasecmp(str, "f") == 0 ||
		   strcasecmp(str, "off") == 0 || strcmp(str, "0") == 0) {
		val->boolean = false;
		val->type |= SD_OPT_BOOL;
	}

	sizef = strtod(str, &postfix);
	if (str < postfix) {
		switch (*postfix) {
		case 'T':
			sizef *= 1024;
		case 'G':
			sizef *= 1024;
		case 'M':
			sizef *= 1024;
		case 'K':
		case 'k':
			sizef *= 1024;
		case 'b':
		case '\0':
			val->size = (uint64_t)sizef;
		}
		val->type |= SD_OPT_SIZE;
	}
}

struct sd_opt_value *sd_opt_param_get(struct sd_opt_param *params,
				      const char *arg, const char *key)
{
	struct sd_opt_param *param;

	sd_for_each_opt_param(param, params) {
		if (strcmp(param->arg, arg) == 0 &&
		    strcmp(param->key, key) == 0) {
			if (param->value.str == NULL)
				return NULL;
			return &param->value;
		}
	}

	return NULL;
}

static int parse_sd_opt_param(struct sd_opt_param *params, const char *arg,
			      const char *key, const char *value)
{
	struct sd_opt_value *opt_val = NULL;
	struct sd_opt_param *param;

	sd_for_each_opt_param(param, params) {
		if (strcmp(param->arg, arg) == 0 &&
		    strcmp(param->key, key) == 0) {
			opt_val = &param->value;
			parse_sd_opt_value(opt_val, value);
			return 0;
		}
	}

	fprintf(stderr, "%s: Invalid parameter '%s'\n", arg, key);
	return -1;
}

/* parse key=value pairs */
static int parse_sd_opt_params(struct sd_opt_param *params, const char *arg,
			       char *str)
{
	const char *key, *value;

	key = strtok(str, "=");
	if (!key)
		return 0;

	value = strtok(NULL, "=");
	if (!value) {
		fprintf(stderr, "%s: Invalid format '%s'\n", arg, key);
		return -1;
	}
	while (key && value) {
		int ret;
		char *next_key = NULL, *next_value = NULL;

		next_value = strtok(NULL, "=");
		if (next_value) {
			next_key = strrchr(value, ',');
			if (next_key)
				*next_key++ = '\0';
			else
				next_value = NULL;
		}

		ret = parse_sd_opt_param(params, arg, key, value);
		if (ret < 0)
			return ret;

		key = next_key;
		value = next_value;
	}

	return 0;
}

static void parse_sd_option(struct sd_option *opt, char *str)
{
	const char *arg;

	if (str == NULL)
		return;

	arg = strtok(str, ":");
	parse_sd_opt_value(&opt->arg, arg);

	str = strtok(NULL, "");
	if (str) {
		int ret;

		ret = parse_sd_opt_params(opt->params, arg, str);
		if (ret < 0) {
			sd_opt_usage(opt, arg, "Usage:");
			exit(1);
		}
	}
}

struct sd_option *sd_getopt(int argc, char * const argv[],
			    struct sd_option *opts)
{
	int ch;
	static struct option *long_options;
	static const char *short_options;
	struct sd_option *opt;

	if (long_options == NULL) {
		/* initialize */
		long_options = build_long_options(opts);
		short_options = build_short_options(opts);
	}

	ch = getopt_long(argc, argv, short_options, long_options, NULL);
	if (ch < 0)
		return NULL;

	sd_for_each_option(opt, opts) {
		if (opt->ch == ch) {
			parse_sd_option(opt, optarg);
			return opt;
		}
	}

	panic("internal error\n");
}
