/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "../include/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "sheep_priv.h"
#include "trace/trace.h"
#include "util.h"
#include "option.h"

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"
#define LOG_FILE_NAME "sheep.log"

LIST_HEAD(cluster_drivers);
static const char program_name[] = "sheep";

static struct sd_opt_param cluster_options[] = {
	{"local", "shmfile", "<filename>",
	 "specify a file to be used for shared memory"},
	{"zookeeper", "server", "<host:port>[,...]",
	 "specify ZooKeeper servers with comma separated host:port pairs"},
	{"accord", "server", "<server>",
	 "specify one of Accord servers"},
	{NULL, NULL, NULL, NULL},
};

static struct sd_opt_param write_cache_options[] = {
	{"object", "size", "<size>",
	 "specify a cache size for object cache"},
	{"object", "directio", "<on|off>",
	 "avoid using gateway page cache"},
	{NULL, NULL, NULL, NULL},
};

static struct sd_option sheep_options[] = {
	{'b', "bindaddr", true, NULL, "specify IP address of interface to listen on"},
	{'c', "cluster", true, cluster_options, "specify the cluster driver"},
	{'d', "debug", false, NULL, "include debug messages in the log"},
	{'f', "foreground", false, NULL, "make the program run in the foreground"},
	{'g', "gateway", false, NULL, "make the progam run as a gateway mode"},
	{'h', "help", false, NULL, "display this help and exit"},
	{'j', "journal", false, NULL, "use jouranl to update vdi objects"},
	{'l', "loglevel", true, NULL, "specify the level of logging detail"},
	{'o', "stdout", false, NULL, "log to stdout instead of shared logger"},
	{'p', "port", true, NULL, "specify the TCP port on which to listen"},
	{'P', "pidfile", true, NULL, "create a pid file"},
	{'s', "disk-space", true, NULL, "specify the free disk space"},
	{'u', "upgrade", false, NULL, "upgrade to the latest data layout"},
	{'w', "write-cache", true, write_cache_options, "specify the cache type"},
	{'y', "myaddr", true, NULL, "specify the address advertised to other sheep"},
	{'z', "zone", true, NULL, "specify the zone id"},
	{ 0, NULL, false, NULL, NULL },
};

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		struct sd_option *opt;

		printf("Sheepdog daemon (version %s)\n"
		       "Usage: %s [OPTION]... [PATH]\n"
		       "Options:\n", PACKAGE_VERSION, program_name);

		sd_for_each_option(opt, sheep_options) {
			printf("  -%c, --%-18s%s\n", opt->ch, opt->name,
			       opt->desc);
		}
	}

	exit(status);
}

static void sdlog_help(void)
{
	printf("Available log levels:\n"
	       "  #    Level           Description\n"
	       "  0    SDOG_EMERG      system has failed and is unusable\n"
	       "  1    SDOG_ALERT      action must be taken immediately\n"
	       "  2    SDOG_CRIT       critical conditions\n"
	       "  3    SDOG_ERR        error conditions\n"
	       "  4    SDOG_WARNING    warning conditions\n"
	       "  5    SDOG_NOTICE     normal but significant conditions\n"
	       "  6    SDOG_INFO       informational notices\n"
	       "  7    SDOG_DEBUG      debugging messages\n");
}

static int create_pidfile(const char *filename)
{
	int fd = -1;
	int len;
	char buffer[128];

	fd = open(filename, O_RDWR|O_CREAT|O_SYNC, 0600);
	if (fd == -1)
		return -1;

	if (lockf(fd, F_TLOCK, 0) == -1) {
		close(fd);
		return -1;
	}

	len = snprintf(buffer, sizeof(buffer), "%d\n", getpid());
	if (write(fd, buffer, len) != len) {
		close(fd);
		return -1;
	}

	/* keep pidfile open & locked forever */
	return 0;
}

static int sigfd;

static void signal_handler(int listen_fd, int events, void *data)
{
	struct signalfd_siginfo siginfo;
	int ret;

	ret = read(sigfd, &siginfo, sizeof(siginfo));
	assert(ret == sizeof(siginfo));
	dprintf("signal %d\n", siginfo.ssi_signo);
	switch (siginfo.ssi_signo) {
	case SIGTERM:
		sys->status = SD_STATUS_KILLED;
		break;
	default:
		eprintf("signal %d unhandled\n", siginfo.ssi_signo);
		break;
	}
}

static int init_signal(void)
{
	sigset_t mask;
	int ret;

	ret = trace_init_signal();
	if (ret)
		return ret;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	sigfd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (sigfd < 0) {
		eprintf("failed to create a signal fd: %m\n");
		return -1;
	}

	ret = register_event(sigfd, signal_handler, NULL);
	if (ret) {
		eprintf("failed to register signal handler (%d)\n", ret);
		return -1;
	}

	dprintf("register signal_handler for %d\n", sigfd);

	return 0;
}

static struct cluster_info __sys;
struct cluster_info *sys = &__sys;

static int object_cache_set(struct sd_opt_param *params)
{
	const struct sd_opt_value *opt_val;

	sys->enabled_cache_type |= CACHE_TYPE_OBJECT;

	opt_val = sd_opt_param_get(params, "object", "directio");
	if (opt_val) {
		if (!sd_opt_is_bool(opt_val)) {
			fprintf(stderr, "set directio with on or off\n");
			return -1;
		}
		sys->object_cache_directio = opt_val->boolean;
	}

	opt_val = sd_opt_param_get(params, "object", "size");
	if (!opt_val) {
		fprintf(stderr, "object cache size is not set\n");
		return -1;
	} else if (!sd_opt_is_size(opt_val)) {
		fprintf(stderr, "invalid cache size, %s\n",
			opt_val->str);
		return -1;
	} else if (opt_val->size < SD_DATA_OBJ_SIZE) {
		fprintf(stderr, "Cache size %s is too small\n",
			opt_val->str);
		return -1;
	}
	sys->object_cache_size = opt_val->size / 1024 / 1024;

	return 0;
}

static int disk_cache_set(struct sd_opt_param *params)
{
	sys->enabled_cache_type |= CACHE_TYPE_DISK;
	return 0;
}

static int init_cache_type(struct sd_option *opt)
{
	int i;

	struct cache_type {
		const char *name;
		int (*set)(struct sd_opt_param *);
	};
	struct cache_type cache_types[] = {
		{ "object", object_cache_set },
		{ "disk", disk_cache_set },
		{ NULL, NULL },
	};

	for (i = 0; cache_types[i].name; i++) {
		const char *n = cache_types[i].name;

		if (!strncmp(opt->arg.str, n, strlen(n)))
			return cache_types[i].set(opt->params);
	}
	fprintf(stderr, "invalid cache type: %s\n", opt->arg.str);

	return -1;
}

int main(int argc, char **argv)
{
	int ret, port = SD_LISTEN_PORT;
	const char *dir = DEFAULT_OBJECT_DIR;
	bool is_daemon = true;
	bool to_stdout = false;
	int log_level = SDOG_INFO;
	char path[PATH_MAX];
	int64_t zone = -1;
	int nr_vnodes = SD_DEFAULT_VNODES;
	bool explicit_addr = false;
	int af;
	struct cluster_driver *cdrv;
	char *pid_file = NULL;
	char *bindaddr = NULL;
	unsigned char buf[sizeof(struct in6_addr)];
	int ipv4 = 0;
	int ipv6 = 0;
	struct sd_option *opt;

	signal(SIGPIPE, SIG_IGN);

	while ((opt = sd_getopt(argc, argv, sheep_options)) != NULL) {
		switch (opt->ch) {
		case 'p':
			if (!sd_opt_is_valid_number(&opt->arg, 1, UINT16_MAX)) {
				fprintf(stderr, "Invalid port number '%s'\n",
					opt->arg.str);
				exit(1);
			}
			port = opt->arg.num;
			break;
		case 'P':
			pid_file = opt->arg.str;
			break;
		case 'f':
			is_daemon = false;
			break;
		case 'l':
			if (!sd_opt_is_valid_number(&opt->arg, SDOG_EMERG,
						    SDOG_DEBUG)) {
				fprintf(stderr, "Invalid log level '%s'\n",
					opt->arg.str);
				sdlog_help();
				exit(1);
			}
			log_level = opt->arg.num;
			break;
		case 'y':
			af = strstr(opt->arg.str, ":") ? AF_INET6 : AF_INET;
			if (!str_to_addr(af, opt->arg.str, sys->this_node.nid.addr)) {
				fprintf(stderr,
					"Invalid address: '%s'\n",
					opt->arg.str);
				sdlog_help();
				exit(1);
			}
			explicit_addr = true;
			break;
		case 'd':
			/* removed soon. use loglevel instead */
			log_level = SDOG_DEBUG;
			break;
		case 'g':
			/* same as '-v 0' */
			nr_vnodes = 0;
			break;
		case 'o':
			to_stdout = true;
			break;
		case 'z':
			if (!sd_opt_is_valid_number(&opt->arg, 0, UINT32_MAX)) {
				fprintf(stderr, "Invalid zone id '%s': "
					"must be an integer between 0 and %u\n",
					opt->arg.str, UINT32_MAX);
				exit(1);
			}
			zone = opt->arg.num;
			sys->this_node.zone = zone;
			break;
		case 's':
			if (!sd_opt_is_size(&opt->arg)) {
				fprintf(stderr, "Invalid free space size, %s\n",
					opt->arg.str);
				exit(1);
			}
			sys->disk_space = opt->arg.size;
			break;
		case 'u':
			sys->upgrade = true;
			break;
		case 'c':
			sys->cdrv = find_cdrv(opt->arg.str);
			if (!sys->cdrv) {
				fprintf(stderr, "Invalid cluster driver '%s'\n",
					opt->arg.str);
				fprintf(stderr, "Supported drivers:");
				FOR_EACH_CLUSTER_DRIVER(cdrv) {
					fprintf(stderr, " %s", cdrv->name);
				}
				fprintf(stderr, "\n");
				exit(1);
			}

			sys->cdrv_option = opt->params;
			break;
		case 'w':
			if (init_cache_type(opt) < 0)
				exit(1);
			break;
		case 'j':
			sys->use_journal = true;
			break;
		case 'b':
			/* validate provided address using inet_pton */
			ipv4 = inet_pton(AF_INET, opt->arg.str, buf);
			ipv6 = inet_pton(AF_INET6, opt->arg.str, buf);
			if (ipv4 || ipv6) {
				bindaddr = opt->arg.str;
			} else {
				fprintf(stderr, "Invalid bind address '%s'\n",
					opt->arg.str);
				exit(1);
			}
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}
	if (nr_vnodes == 0) {
		sys->gateway_only = true;
		sys->disk_space = 0;
	}

	if (optind != argc)
		dir = argv[optind];

	snprintf(path, sizeof(path), "%s/" LOG_FILE_NAME, dir);

	srandom(port);

	if (is_daemon && daemon(0, 0))
		exit(1);

	ret = init_base_path(dir);
	if (ret)
		exit(1);

	ret = log_init(program_name, LOG_SPACE_SIZE, to_stdout, log_level, path);
	if (ret)
		exit(1);

	ret = init_store(dir);
	if (ret)
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = create_listen_port(bindaddr, port);
	if (ret)
		exit(1);

	ret = init_unix_domain_socket(dir);
	if (ret)
		exit(1);

	ret = create_cluster(port, zone, nr_vnodes, explicit_addr);
	if (ret) {
		eprintf("failed to create sheepdog cluster\n");
		exit(1);
	}

	local_req_init();

	ret = init_signal();
	if (ret)
		exit(1);

	sys->gateway_wqueue = init_work_queue("gway", false);
	sys->io_wqueue = init_work_queue("io", false);
	sys->recovery_wqueue = init_work_queue("rw", false);
	sys->deletion_wqueue = init_work_queue("deletion", true);
	sys->block_wqueue = init_work_queue("block", true);
	sys->sockfd_wqueue = init_work_queue("sockfd", true);
	if (is_object_cache_enabled()) {
		sys->reclaim_wqueue = init_work_queue("reclaim", true);
		if (!sys->reclaim_wqueue)
			exit(1);
	}
	if (!sys->gateway_wqueue || !sys->io_wqueue || !sys->recovery_wqueue ||
	    !sys->deletion_wqueue || !sys->block_wqueue || !sys->sockfd_wqueue)
		exit(1);

	ret = trace_init();
	if (ret)
		exit(1);

	if (pid_file && (create_pidfile(pid_file) != 0)) {
		fprintf(stderr, "failed to pid file '%s' - %s\n", pid_file,
			strerror(errno));
		exit(1);
	}

	if (chdir(dir) < 0) {
		fprintf(stderr, "failed to chdir to %s: %m\n", dir);
		exit(1);
	}

	vprintf(SDOG_NOTICE, "sheepdog daemon (version %s) started\n", PACKAGE_VERSION);

	while (sys->nr_outstanding_reqs != 0 ||
	       (sys->status != SD_STATUS_KILLED &&
		sys->status != SD_STATUS_SHUTDOWN))
		event_loop(-1);

	vprintf(SDOG_INFO, "shutdown\n");

	leave_cluster();
	log_close();

	if (pid_file)
		unlink(pid_file);

	return 0;
}
