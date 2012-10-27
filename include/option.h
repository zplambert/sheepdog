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
#ifndef __SD_OPTION_H__
#define __SD_OPTION_H__

#include <stdbool.h>
#include <stdint.h>

/*
 * Sheep command option syntax
 *
 * --<option> <arg>[:<key>=<value>[,<key>=<value>[,...]]]
 *
 * E.g.
 * --cluster zookeeper:servers=10.0.0.1,10.0.0.2
 * --writecache object:size=100M,directio=true
 */

struct sd_opt_value {
	uint8_t type;

	char *str;
	int64_t num;
	bool boolean;
	uint64_t size;
};

struct sd_opt_param {
	const char *arg;
	const char *key;
	const char *usage;
	const char *desc;

	struct sd_opt_value value;
};

struct sd_option {
	int ch;
	const char *name;
	bool has_arg;
	struct sd_opt_param *params;
	const char *desc;

	struct sd_opt_value arg;
};

void sd_opt_usage(struct sd_option *opt, const char *arg,
		  const char *desc);
bool sd_opt_is_number(const struct sd_opt_value *val);
bool sd_opt_is_bool(const struct sd_opt_value *val);
bool sd_opt_is_size(const struct sd_opt_value *val);
bool sd_opt_is_valid_number(const struct sd_opt_value *val,
			    int64_t min_val, int64_t max_val);

char *build_short_options(const struct sd_option *opts);
struct option *build_long_options(const struct sd_option *opts);

struct sd_opt_value *sd_opt_param_get(struct sd_opt_param *params,
				      const char *arg, const char *key);
struct sd_option *sd_getopt(int argc, char * const argv[],
			    struct sd_option *opts);

#define sd_for_each_option(opt, opts)		\
	for (opt = (opts); opt->name; opt++)

#define sd_for_each_opt_param(param, params)	\
	for (param = (params); param->arg; param++)

#endif /* __SD_OPTION_H__ */
