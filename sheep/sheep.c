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
#include <sys/resource.h>
#include <malloc.h>

#include "sheep_priv.h"
#include "trace/trace.h"
#include "util.h"
#include "option.h"

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"
#define LOG_FILE_NAME "sheep.log"

LIST_HEAD(cluster_drivers);
static const char program_name[] = "sheep";

static struct sd_option sheep_options[] = {
	{'b', "bindaddr", true, "specify IP address of interface to listen on"},
	{'c', "cluster", true, "specify the cluster driver"},
	{'d', "debug", false, "include debug messages in the log"},
	{'D', "directio", false, "use direct IO for backend store"},
	{'f', "foreground", false, "make the program run in the foreground"},
	{'F', "log-format", true, "specify log format"},
	{'g', "gateway", false, "make the progam run as a gateway mode"},
	{'h', "help", false, "display this help and exit"},
	{'i', "ioaddr", true, "use separate network card to handle IO requests"},
	{'j', "journal", true, "use jouranl file to log all the write operations"},
	{'l', "loglevel", true, "specify the level of logging detail"},
	{'n', "nosync", false, "drop O_SYNC for write of backend"},
	{'o', "stdout", false, "log to stdout instead of shared logger"},
	{'p', "port", true, "specify the TCP port on which to listen"},
	{'P', "pidfile", true, "create a pid file"},
	{'u', "upgrade", false, "upgrade to the latest data layout"},
	{'v', "version", false, "show the version"},
	{'w', "enable-cache", true, "enable object cache"},
	{'y', "myaddr", true, "specify the address advertised to other sheep"},
	{'z', "zone", true, "specify the zone id"},
	{ 0, NULL, false, NULL },
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
	int uninitialized_var(ret);

	ret = read(sigfd, &siginfo, sizeof(siginfo));
	assert(ret == sizeof(siginfo));
	sd_dprintf("signal %d", siginfo.ssi_signo);
	switch (siginfo.ssi_signo) {
	case SIGTERM:
		sys->status = SD_STATUS_KILLED;
		break;
	default:
		sd_eprintf("signal %d unhandled", siginfo.ssi_signo);
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
		sd_eprintf("failed to create a signal fd: %m");
		return -1;
	}

	ret = register_event(sigfd, signal_handler, NULL);
	if (ret) {
		sd_eprintf("failed to register signal handler (%d)", ret);
		return -1;
	}

	sd_dprintf("register signal_handler for %d", sigfd);

	return 0;
}

static void crash_handler(int signo)
{
	sd_printf(SDOG_EMERG, "sheep exits unexpectedly (%s).",
		  strsignal(signo));

	sd_backtrace();
	sd_dump_variable(__sys);

	reraise_crash_signal(signo, 1);
}

static struct cluster_info __sys;
struct cluster_info *sys = &__sys;

static void parse_arg(char *arg, const char *delim, void (*fn)(char *))
{
	char *savep, *s;

	s = strtok_r(arg, delim, &savep);
	do {
		fn(s);
	} while ((s = strtok_r(NULL, delim, &savep)));
}

static void object_cache_size_set(char *s)
{
	const char *header = "size=";
	int len = strlen(header);
	char *size, *p;
	uint64_t cache_size;
	const uint32_t max_cache_size = UINT32_MAX;

	assert(!strncmp(s, header, len));

	size = s + len;
	cache_size = strtoull(size, &p, 10);
	if (size == p || max_cache_size < cache_size)
		goto err;

	sys->object_cache_size = cache_size;
	return;

err:
	fprintf(stderr, "Invalid object cache option '%s': "
		"size must be an integer between 1 and %"PRIu32" inclusive\n",
		s, max_cache_size);
	exit(1);
}

static void object_cache_directio_set(char *s)
{
	assert(!strcmp(s, "directio"));
	sys->object_cache_directio = true;
}

static char ocpath[PATH_MAX];
static void object_cache_dir_set(char *s)
{
	char *p = s;

	p = p + strlen("dir=");
	snprintf(ocpath, sizeof(ocpath), "%s", p);
}

static void _object_cache_set(char *s)
{
	int i;

	struct object_cache_arg {
		const char *name;
		void (*set)(char *);
	};

	struct object_cache_arg object_cache_args[] = {
		{ "size=", object_cache_size_set },
		{ "directio", object_cache_directio_set },
		{ "dir=", object_cache_dir_set },
		{ NULL, NULL },
	};

	for (i = 0; object_cache_args[i].name; i++) {
		const char *n = object_cache_args[i].name;

		if (!strncmp(s, n, strlen(n))) {
			object_cache_args[i].set(s);
			return;
		}
	}

	fprintf(stderr, "invalid object cache arg: %s\n", s);
	exit(1);
}

static void object_cache_set(char *arg)
{
	sys->enable_object_cache = true;
	sys->object_cache_size = 0;

	parse_arg(arg, ",", _object_cache_set);

	if (sys->object_cache_size == 0) {
		fprintf(stderr, "object cache size is not set\n");
		exit(1);
	}
}

static char jpath[PATH_MAX];
static bool jskip;
static ssize_t jsize;
#define MIN_JOURNAL_SIZE (64) /* 64M */

static void init_journal_arg(char *arg)
{
	const char *d = "dir=", *sz = "size=", *sp = "skip";
	int dl = strlen(d), szl = strlen(sz), spl = strlen(sp);

	if (!strncmp(d, arg, dl)) {
		arg += dl;
		snprintf(jpath, sizeof(jpath), "%s", arg);
	} else if (!strncmp(sz, arg, szl)) {
		arg += szl;
		jsize = strtoll(arg, NULL, 10);
		if (jsize < MIN_JOURNAL_SIZE || jsize == LLONG_MAX) {
			fprintf(stderr, "invalid size %s, "
				"must be bigger than %u(M)\n", arg,
				MIN_JOURNAL_SIZE);
			exit(1);
		}
	} else if (!strncmp(sp, arg, spl)) {
		jskip = true;
	} else {
		fprintf(stderr, "invalid paramters %s\n", arg);
		exit(1);
	}
}

static char *io_addr, *io_pt;
static void init_io_arg(char *arg)
{
	const char *host = "host=", *port = "port=";
	int hl = strlen(host), pl = strlen(port);

	if (!strncmp(host, arg, hl)) {
		arg += hl;
		io_addr = arg;
	} else if (!strncmp(port, arg, pl)) {
		arg += hl;
		io_pt = arg;
	} else {
		fprintf(stderr, "invalid paramters %s. "
			"Use '-i host=a.b.c.d,port=xxx'\n",
			arg);
		exit(1);
	}
}

static size_t get_nr_nodes(void)
{
	struct vnode_info *vinfo;
	size_t nr = 1;

	vinfo = get_vnode_info();
	if (vinfo != NULL)
		nr = vinfo->nr_nodes;
	put_vnode_info(vinfo);

	return nr;
}

static int create_work_queues(void)
{
	if (init_work_queue(get_nr_nodes, trace_register_thread,
			    trace_unregister_thread))
		return -1;

	sys->gateway_wqueue = create_work_queue("gway", WQ_UNLIMITED);
	sys->io_wqueue = create_work_queue("io", WQ_UNLIMITED);
	sys->recovery_wqueue = create_ordered_work_queue("rw");
	sys->deletion_wqueue = create_ordered_work_queue("deletion");
	sys->block_wqueue = create_ordered_work_queue("block");
	sys->sockfd_wqueue = create_ordered_work_queue("sockfd");
	sys->md_wqueue = create_ordered_work_queue("md");
	if (sys->enable_object_cache) {
		sys->oc_reclaim_wqueue =
			create_ordered_work_queue("oc_reclaim");
		sys->oc_push_wqueue = create_work_queue("oc_push", WQ_DYNAMIC);
		if (!sys->oc_reclaim_wqueue || !sys->oc_push_wqueue)
			return -1;
	}
	if (!sys->gateway_wqueue || !sys->io_wqueue || !sys->recovery_wqueue ||
	    !sys->deletion_wqueue || !sys->block_wqueue ||
	    !sys->sockfd_wqueue || !sys->md_wqueue)
			return -1;
	return 0;
}

/*
 * FIXME: Teach sheep handle EMFILE gracefully.
 *
 * For now we only set a large enough vaule to run sheep safely.
 *
 * We just estimate we at most run 100 VMs for each node and each VM consumes 10
 * FDs at peak rush hour.
 */
#define SD_RLIM_NOFILE (SD_MAX_NODES * 100 * 10)

static void check_host_env(void)
{
	struct rlimit r;

	if (getrlimit(RLIMIT_NOFILE, &r) < 0)
		sd_eprintf("failed to get nofile %m");
	/*
	 * 1024 is default for NOFILE on most distributions, which is very
	 * dangerous to run Sheepdog cluster.
	 */
	else if (r.rlim_cur == 1024)
		sd_eprintf("WARN: Allowed open files 1024 too small, "
			   "suggested %u", SD_RLIM_NOFILE);
	else if (r.rlim_cur < SD_RLIM_NOFILE)
		sd_iprintf("Allowed open files %lu, suggested %u", r.rlim_cur,
			   SD_RLIM_NOFILE);

	if (getrlimit(RLIMIT_CORE, &r) < 0)
		sd_eprintf("failed to get core %m");
	else if (r.rlim_cur < RLIM_INFINITY)
		sd_iprintf("Allowed core file size %lu, suggested unlimited",
			   r.rlim_cur);

	/*
	 * Disable glibc's dynamic mmap threshold and set it as 512k.
	 *
	 * We have to disable dynamic threshold because its inefficiency to
	 * release freed memory back to OS. Setting it as 512k practically means
	 * allocation larger than or equal to 512k will use mmap() for malloc()
	 * and munmap() for free(), guaranteeing allocated memory will not be
	 * cached in the glibc's ptmalloc internal pool.
	 *
	 * 512k is not a well tested optimal value for IO request size, I choose
	 * it because it is default value for disk drive that it can transfer at
	 * a time. So default installation of guest will issue at most 512K
	 * sized request.
	 */
	mallopt(M_MMAP_THRESHOLD, 512 * 1024);
}

static int lock_and_daemon(bool daemonize, const char *base_dir)
{
	int ret, devnull_fd = 0, status = 0;
	int pipefd[2];

	ret = pipe(pipefd);
	if (ret < 0)
		panic("pipe() for passing exit status failed: %m");

	if (daemonize) {
		switch (fork()) {
		case 0:
			break;
		case -1:
			panic("fork() failed during daemonize: %m");
			break;
		default:
			ret = read(pipefd[0], &status, sizeof(status));
			if (ret != sizeof(status))
				panic("read exit status failed: %m");

			exit(status);
			break;
		}

		if (setsid() == -1) {
			sd_eprintf("becoming a leader of a new session"
				" failed: %m");
			status = 1;
			goto end;
		}

		switch (fork()) {
		case 0:
			break;
		case -1:
			sd_eprintf("fork() failed during daemonize: %m");
			status = 1;
			goto end;
		default:
			exit(0);
			break;
		}

		if (chdir("/")) {
			sd_eprintf("chdir to / failed: %m");
			status = 1;
			goto end;
		}

		devnull_fd = open("/dev/null", O_RDWR);
		if (devnull_fd < 0) {
			sd_eprintf("opening /dev/null failed: %m");
			status = 1;
			goto end;
		}
	}

	ret = lock_base_dir(base_dir);
	if (ret < 0) {
		sd_eprintf("locking directory: %s failed", base_dir);
		status = 1;
		goto end;
	}

	if (daemonize) {
		/*
		 * now we can use base_dir/sheep.log for logging error messages,
		 * we can close 0, 1, and 2 safely
		 */
		dup2(devnull_fd, 0);
		dup2(devnull_fd, 1);
		dup2(devnull_fd, 2);

		close(devnull_fd);
	}

end:
	ret = write(pipefd[1], &status, sizeof(status));
	if (ret != sizeof(status))
		panic("writing exit status failed: %m");

	return status;
}

int main(int argc, char **argv)
{
	int ch, longindex, ret, port = SD_LISTEN_PORT, io_port = SD_LISTEN_PORT;
	int log_level = SDOG_INFO, nr_vnodes = SD_DEFAULT_VNODES;
	const char *dirp = DEFAULT_OBJECT_DIR, *short_options;
	char *dir, *p, *pid_file = NULL, *bindaddr = NULL, path[PATH_MAX],
	     *argp = NULL;
	bool is_daemon = true, to_stdout = false, explicit_addr = false;
	int64_t zone = -1;
	struct cluster_driver *cdrv;
	struct option *long_options;
	const char *log_format = "default";
	static struct logger_user_info sheep_info;

	install_crash_handler(crash_handler);
	signal(SIGPIPE, SIG_IGN);

	long_options = build_long_options(sheep_options);
	short_options = build_short_options(sheep_options);
	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			port = strtol(optarg, &p, 10);
			if (optarg == p || port < 1 || UINT16_MAX < port
				|| *p != '\0') {
				fprintf(stderr, "Invalid port number '%s'\n",
					optarg);
				exit(1);
			}
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 'f':
			is_daemon = false;
			break;
		case 'l':
			log_level = strtol(optarg, &p, 10);
			if (optarg == p || log_level < SDOG_EMERG ||
			    SDOG_DEBUG < log_level || *p != '\0') {
				fprintf(stderr, "Invalid log level '%s'\n",
					optarg);
				sdlog_help();
				exit(1);
			}
			break;
		case 'n':
			sys->nosync = true;
			break;
		case 'y':
			if (!str_to_addr(optarg, sys->this_node.nid.addr)) {
				fprintf(stderr, "Invalid address: '%s'\n",
					optarg);
				exit(1);
			}
			explicit_addr = true;
			break;
		case 'd':
			/* removed soon. use loglevel instead */
			log_level = SDOG_DEBUG;
			break;
		case 'D':
			sys->backend_dio = true;
			break;
		case 'g':
			/* same as '-v 0' */
			nr_vnodes = 0;
			break;
		case 'o':
			to_stdout = true;
			break;
		case 'z':
			zone = strtol(optarg, &p, 10);
			if (optarg == p || zone < 0 || UINT32_MAX < zone
				|| *p != '\0') {
				fprintf(stderr, "Invalid zone id '%s': "
					"must be an integer between 0 and %u\n",
					optarg, UINT32_MAX);
				exit(1);
			}
			sys->this_node.zone = zone;
			break;
		case 'u':
			sys->upgrade = true;
			break;
		case 'c':
			sys->cdrv = find_cdrv(optarg);
			if (!sys->cdrv) {
				fprintf(stderr, "Invalid cluster driver '%s'\n", optarg);
				fprintf(stderr, "Supported drivers:");
				FOR_EACH_CLUSTER_DRIVER(cdrv) {
					fprintf(stderr, " %s", cdrv->name);
				}
				fprintf(stderr, "\n");
				exit(1);
			}

			sys->cdrv_option = get_cdrv_option(sys->cdrv, optarg);
			break;
		case 'w':
			object_cache_set(optarg);
			break;
		case 'i':
			parse_arg(optarg, ",", init_io_arg);
			if (!str_to_addr(io_addr, sys->this_node.nid.io_addr)) {
				fprintf(stderr, "Bad addr: '%s'\n",
					io_addr);
				exit(1);
			}

			if (io_pt)
				if (sscanf(io_pt, "%u", &io_port) != 1) {
					fprintf(stderr, "Bad port '%s'\n",
						io_pt);
					exit(1);
				}
			sys->this_node.nid.io_port = io_port;
			break;
		case 'j':
			uatomic_set_true(&sys->use_journal);
			parse_arg(optarg, ",", init_journal_arg);
			if (!jsize) {
				fprintf(stderr,
					"you must specify size for journal\n");
				exit(1);
			}
			break;
		case 'b':
			if (!inetaddr_is_valid(optarg))
				exit(1);
			bindaddr = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'v':
			fprintf(stdout, "Sheepdog daemon version %s\n",
				PACKAGE_VERSION);
			exit(0);
			break;
		case 'F':
			log_format = optarg;
			break;
		default:
			usage(1);
			break;
		}
	}

	/*
	 * early_log_init() must be called before any calling of
	 * sd_printf() series
	 */
	sheep_info.port = port;
	early_log_init(log_format, &sheep_info);

	if (nr_vnodes == 0) {
		sys->gateway_only = true;
		sys->disk_space = 0;
	}

	if (optind != argc) {
		argp = strdup(argv[optind]);
		dirp = strtok(argv[optind], ",");
	}

	ret = init_base_path(dirp);
	if (ret)
		exit(1);

	dir = realpath(dirp, NULL);
	if (!dir) {
		fprintf(stderr, "%m\n");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/" LOG_FILE_NAME, dir);

	srandom(port);

	if (lock_and_daemon(is_daemon, dir))
		exit(1);

	ret = log_init(program_name, LOG_SPACE_SIZE, to_stdout, log_level,
		path);
	if (ret)
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = init_global_pathnames(dir, argp);
	free(argp);
	if (ret)
		exit(1);

	ret = init_config_file();
	if (ret)
		exit(1);

	ret = create_listen_port(bindaddr, port);
	if (ret)
		exit(1);

	if (io_addr && create_listen_port(io_addr, io_port))
		exit(1);

	ret = init_unix_domain_socket(dir);
	if (ret)
		exit(1);

	local_req_init();

	ret = init_signal();
	if (ret)
		exit(1);

	/* This function must be called before create_cluster() */
	ret = init_disk_space(dir);
	if (ret)
		exit(1);

	ret = create_cluster(port, zone, nr_vnodes, explicit_addr);
	if (ret) {
		sd_eprintf("failed to create sheepdog cluster");
		exit(1);
	}

	/* We should init journal file before backend init */
	if (uatomic_is_true(&sys->use_journal)) {
		if (!strlen(jpath))
			/* internal journal */
			memcpy(jpath, dir, strlen(dir));
		sd_dprintf("%s, %zd, %d", jpath, jsize, jskip);
		ret = journal_file_init(jpath, jsize, jskip);
		if (ret)
			exit(1);
	}

	/*
	 * After this function, we are multi-threaded.
	 *
	 * Put those init functions that need single threaded environment, for
	 * e.g, signal handling, above this call and those need multi-threaded
	 * environment, for e.g, work queues below.
	 */
	ret = create_work_queues();
	if (ret)
		exit(1);

	ret = init_store_driver(sys->gateway_only);
	if (ret)
		exit(1);

	if (sys->enable_object_cache) {
		if (!strlen(ocpath))
			/* use object cache internally */
			memcpy(ocpath, dir, strlen(dir));
		ret = object_cache_init(ocpath);
		if (ret)
			exit(1);
	}

	ret = trace_init();
	if (ret)
		exit(1);

	if (pid_file && (create_pidfile(pid_file) != 0)) {
		fprintf(stderr, "failed to pid file '%s' - %m\n", pid_file);
		exit(1);
	}

	if (chdir(dir) < 0) {
		fprintf(stderr, "failed to chdir to %s: %m\n", dir);
		exit(1);
	}

	free(dir);
	check_host_env();
	sd_printf(SDOG_NOTICE, "sheepdog daemon (version %s) started",
		  PACKAGE_VERSION);

	while (sys->nr_outstanding_reqs != 0 ||
	       (sys->status != SD_STATUS_KILLED &&
		sys->status != SD_STATUS_SHUTDOWN))
		event_loop(-1);

	sd_printf(SDOG_INFO, "shutdown");

	leave_cluster();

	if (uatomic_is_true(&sys->use_journal)) {
		sd_iprintf("cleaning journal file");
		clean_journal_file(jpath);
	}

	log_close();

	if (pid_file)
		unlink(pid_file);

	return 0;
}
