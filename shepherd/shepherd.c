/*
 * Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <sys/un.h>
#include <netinet/in.h>

#include "net.h"
#include "event.h"
#include "list.h"
#include "internal_proto.h"
#include "sheep.h"
#include "util.h"
#include "option.h"
#include "shepherd.h"

#define EPOLL_SIZE SD_MAX_NODES

enum shepherd_state {
	SPH_STATE_DEFAULT,
	SPH_STATE_JOINING,
};

static enum shepherd_state state = SPH_STATE_DEFAULT;

enum sheep_state {
	SHEEP_STATE_CONNECTED,	/* accept()ed */
	SHEEP_STATE_JOINED,
	SHEEP_STATE_LEAVING,
};

struct sheep {
	int fd;
	struct sd_node node;
	struct sockaddr_in addr;

	enum sheep_state state;

	struct list_head sheep_list;
	struct list_head join_wait_list;
};

static LIST_HEAD(sheep_list_head);
/*
 * nr_joined_sheep is a number of sheeps which is in state of
 * SHEEP_STATE_JOINED, not the length of sheep_list_head
 */
static int nr_joined_sheep;

/*
 * important invariant of shepherd: nr_joined_sheep ? !!master_sheep : true
 *
 * if there is at least one sheep which is in state of SHEEP_STATE_JOINED,
 * master sheep must be elected
 */
static struct sheep *master_sheep;

static bool running;
static const char *progname;

static bool is_sd_node_zero(struct sd_node *node)
{
	static struct sd_node zero_node;
	return !memcmp(node, &zero_node, sizeof(*node));
}

static int build_node_array(struct sd_node *nodes)
{
	int i;
	struct sheep *s;

	i = 0;
	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		nodes[i++] = s->node;
	}

	return i;
}

static struct sheep *find_sheep_by_nid(struct node_id *id)
{
	struct sheep *s;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (!node_id_cmp(&s->node.nid, id))
			return s;
	}

	return NULL;
}

static int remove_efd;

static inline void remove_sheep(struct sheep *sheep)
{
	int ret;

	sd_dprintf("remove_sheep() called, removing %s",
		node_to_str(&sheep->node));

	if (sheep->state == SHEEP_STATE_JOINED)
		nr_joined_sheep--;

	sheep->state = SHEEP_STATE_LEAVING;
	ret = eventfd_write(remove_efd, 1);
	if (ret < 0)
		panic("eventfd_write() failed: %m");

	event_force_refresh();
}

static int master_election(void)
{
	int ret, nr_failed = 0;
	struct sheep *s;
	struct sph_msg msg;

	assert(!master_sheep);

	if (!nr_joined_sheep)
		return 0;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		msg.type = SPH_SRV_MSG_MASTER_ELECTION;
		msg.body_len = 0;

		ret = xwrite(s->fd, &msg, sizeof(msg));
		if (sizeof(msg) != ret) {
			sd_eprintf("xwrite() for failed: %m");
			goto election_failed;
		}

		master_sheep = s;
		break;
election_failed:
		remove_sheep(s);
		nr_failed++;
	}

	if (master_sheep) {
		sd_iprintf("new master elected: %s",
			node_to_str(&master_sheep->node));
	}

	return nr_failed;
}

static int notify_remove_sheep(struct sheep *leaving)
{
	int ret, failed = 0;
	struct sheep *s;
	struct sph_msg snd;

	snd.type = SPH_SRV_MSG_REMOVE;
	snd.body_len = sizeof(struct sd_node);

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		ret = writev2(s->fd, &snd,
			&leaving->node, sizeof(struct sd_node));

		if (sizeof(snd) + sizeof(struct sd_node) != ret) {
			sd_eprintf("writev2() failed: %m");

			remove_sheep(s);
			failed++;
		}
	}

	return failed;
}

static void remove_handler(int fd, int events, void *data)
{
	struct sheep *s;
	int ret, failed = 0;
	eventfd_t val;
	bool election = false;

	ret = eventfd_read(remove_efd, &val);
	if (ret < 0)
		panic("eventfd_read() failed: %m");

	sd_dprintf("removed sheeps: %" PRIu64, val);
	assert(0 < val);


remove:
	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_LEAVING)
			continue;

		sd_printf(SDOG_DEBUG, "removing the node: %s",
			node_to_str(&s->node));

		if (s == master_sheep) {
			sd_printf(SDOG_DEBUG, "removing the master");

			master_sheep = NULL;
			election = true;
		}

		if (!is_sd_node_zero(&s->node))
			/*
			 * This condition can be false when the sheep had
			 * transited from CONNECTED to LEAVING directly.
			 * (sd_node of sheep in CONNECTED state doesn't have
			 * any information, because the member is initialized
			 * when SPH_MSG_NEW_NODE from master sheep is accepted.)
			 *
			 * sheep in CONNECTED state doesn't have to be removed
			 * with notify_remove_sheep(), because other sheeps
			 * don't know its existence.
			 */
			notify_remove_sheep(s);

		goto del;
	}

	goto end;

del:
	sd_iprintf("removed node: %s", node_to_str(&s->node));

	unregister_event(s->fd);
	close(s->fd);

	list_del(&s->sheep_list);
	list_del(&s->join_wait_list);
	free(s);

	event_force_refresh();

	if (--val)
		goto remove;

end:
	if (election) {
		sd_dprintf("master is removed, electing new master");
		failed = master_election();

		assert(nr_joined_sheep ? !!master_sheep : true);
	}

	sd_dprintf("nodes which failed during remove_handler(): %d", failed);
}

static LIST_HEAD(join_wait_queue);

static int release_joining_sheep(void)
{
	ssize_t wbytes;
	struct sheep *waiting;
	struct sph_msg snd;
	int nr_failed = 0;

retry:
	if (list_empty(&join_wait_queue))
		return nr_failed;

	waiting = list_first_entry(&join_wait_queue,
				struct sheep, join_wait_list);
	list_del(&waiting->join_wait_list);
	INIT_LIST_HEAD(&waiting->join_wait_list);

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_JOIN_RETRY;

	wbytes = xwrite(waiting->fd, &snd, sizeof(snd));
	if (sizeof(snd) != wbytes) {
		sd_printf(SDOG_ERR, "xwrite() failed: %m");
		remove_sheep(waiting);

		sd_iprintf("node %s is failed to join",
			node_to_str(&waiting->node));
		nr_failed++;

		goto retry;
	}

	return nr_failed;
}

static void sph_handle_join(struct sph_msg *msg, struct sheep *sheep)
{
	int fd = sheep->fd;
	ssize_t rbytes, wbytes;

	struct sph_msg snd;
	struct sph_msg_join *join;

	if (state == SPH_STATE_JOINING) {
		/* we have to trash opaque from the sheep */
		char *buf;
		buf = xzalloc(msg->body_len);
		rbytes = xread(fd, buf, msg->body_len);
		if (rbytes != msg->body_len) {
			sd_eprintf("xread() failed: %m");
			goto purge_current_sheep;
		}
		free(buf);

		list_add(&sheep->join_wait_list, &join_wait_queue);

		sd_dprintf("there is already a joining sheep");
		return;
	}

	join = xzalloc(msg->body_len);
	rbytes = xread(fd, join, msg->body_len);
	if (msg->body_len != rbytes) {
		sd_eprintf("xread() failed: %m");
		free(join);
		goto purge_current_sheep;
	}

	sheep->node = join->node;

	snd.type = SPH_SRV_MSG_NEW_NODE;
	snd.body_len = msg->body_len;

	if (!nr_joined_sheep) {
		/* this sheep is a new master */
		/* FIXME: is this master_elected need? */
		join->master_elected = true;
	}

	assert(nr_joined_sheep ? !!master_sheep : true);

	wbytes = writev2(!nr_joined_sheep ? fd : master_sheep->fd,
			&snd, join, msg->body_len);
	free(join);

	if (sizeof(snd) + msg->body_len != wbytes) {
		sd_eprintf("writev2() failed: %m");

		if (nr_joined_sheep)
			remove_sheep(master_sheep);

		goto purge_current_sheep;
	}

	state = SPH_STATE_JOINING;
	return;

purge_current_sheep:
	remove_sheep(sheep);
}

static void sph_handle_new_node_reply(struct sph_msg *msg, struct sheep *sheep)
{
	int fd = sheep->fd, removed = 0;
	ssize_t rbytes, wbytes;

	char *opaque;
	int opaque_len;

	struct sph_msg_join *join;
	struct sheep *s, *joining_sheep;
	struct sph_msg snd;
	struct sph_msg_join_reply *join_reply_body;
	struct sph_msg_join_node_finish *join_node_finish;

	enum cluster_join_result join_result;

	if (nr_joined_sheep && sheep != master_sheep) {
		sd_eprintf("sheep which is not a master replied "
			"SPH_CLI_MSG_NEW_NODE_REPLY");
		goto purge_current_sheep;
	}

	sd_dprintf("new node reply from %s", node_to_str(&sheep->node));

	join = xzalloc(msg->body_len);
	rbytes = xread(fd, join, msg->body_len);
	if (msg->body_len != rbytes) {
		sd_eprintf("xread() failed: %m");
		free(join);

		goto purge_current_sheep;
	}

	join_result = join->res;

	sd_dprintf("joining node is %s", node_to_str(&join->node));

	joining_sheep = find_sheep_by_nid(&join->node.nid);
	if (!joining_sheep) {
		/* master is broken */
		sd_eprintf("invalid nid is required, %s",
			node_to_str(&join->node));
		sd_eprintf("purging master sheep: %s and joining one",
			node_to_str(&master_sheep->node));

		remove_sheep(master_sheep);
		goto purge_current_sheep;
	}

	opaque_len = msg->body_len - sizeof(struct sph_msg_join);
	opaque = xzalloc(opaque_len);
	memcpy(opaque, join->opaque, opaque_len);

	sd_printf(SDOG_DEBUG, "length of opaque: %d", opaque_len);
	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_JOIN_REPLY;
	snd.body_len = sizeof(struct sph_msg_join_reply) + opaque_len;

	join_reply_body = xzalloc(snd.body_len);

	join_reply_body->nr_nodes = build_node_array(join_reply_body->nodes);
	/*
	 * the below copy is required because joining sheep is in state
	 * SHEEP_STATE_CONNECTED
	 */
	join_reply_body->nodes[join_reply_body->nr_nodes++] =
		joining_sheep->node;
	memcpy(join_reply_body->opaque, opaque, opaque_len);
	join_reply_body->res = join_result;

	wbytes = writev2(joining_sheep->fd, &snd,
			join_reply_body, snd.body_len);
	free(join_reply_body);
	free(join);

	if (sizeof(snd) + snd.body_len != wbytes) {
		sd_eprintf("writev2() to master failed: %m");

		remove_sheep(master_sheep);
		goto purge_current_sheep;
	}

	snd.type = SPH_SRV_MSG_NEW_NODE_FINISH;
	snd.body_len = sizeof(*join_node_finish) + opaque_len;

	join_node_finish = xzalloc(snd.body_len);
	join_node_finish->new_node = joining_sheep->node;
	memcpy(join_node_finish->opaque, opaque, opaque_len);
	join_node_finish->nr_nodes = build_node_array(join_node_finish->nodes);
	join_node_finish->nodes[join_node_finish->nr_nodes++] =
		joining_sheep->node;
	join_node_finish->res = join_result;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		if (s == joining_sheep)
			continue;

		wbytes = writev2(s->fd, &snd, join_node_finish, snd.body_len);

		if (sizeof(snd) + snd.body_len != wbytes) {
			sd_eprintf("writev2() failed: %m");
			remove_sheep(s);
			removed++;
		}
	}

	free(join_node_finish);
	free(opaque);

	joining_sheep->state = SHEEP_STATE_JOINED;
	nr_joined_sheep++;

	if (nr_joined_sheep == 1) {
		assert(!master_sheep);
		assert(joining_sheep == sheep);

		master_sheep = sheep;

		sd_iprintf("new master elected: %s",
			node_to_str(&sheep->node));
	}
	state = SPH_STATE_DEFAULT;

	removed += release_joining_sheep();
	return;

purge_current_sheep:
	state = SPH_STATE_DEFAULT;

	remove_sheep(sheep);
}

static void sph_handle_notify(struct sph_msg *msg, struct sheep *sheep)
{
	ssize_t rbytes, wbytes;
	int fd = sheep->fd, removed = 0;

	struct sph_msg snd;
	struct sph_msg_notify *notify;
	int notify_msg_len;
	struct sph_msg_notify_forward *notify_forward;
	struct sheep *s;

	notify = xzalloc(msg->body_len);
	rbytes = xread(fd, notify, msg->body_len);
	if (rbytes != msg->body_len) {
		sd_eprintf("xread() failed: %m");
		goto purge_current_sheep;
	}

	notify_forward = xzalloc(msg->body_len + sizeof(*notify_forward));
	notify_msg_len = msg->body_len - sizeof(*notify);

	memcpy(notify_forward->notify_msg, notify->notify_msg, notify_msg_len);
	notify_forward->unblock = notify->unblock;
	free(notify);

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_NOTIFY_FORWARD;
	snd.body_len = notify_msg_len + sizeof(*notify_forward);

	notify_forward->from_node = sheep->node;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		wbytes = writev2(s->fd, &snd, notify_forward, snd.body_len);
		if (sizeof(snd) + snd.body_len != wbytes) {
			sd_eprintf("writev2() failed: %m");
			goto notify_failed;
		}

		continue;

notify_failed:
		remove_sheep(s);
		removed++;
	}

	free(notify_forward);
	return;

purge_current_sheep:
	remove_sheep(sheep);
}

static void sph_handle_block(struct sph_msg *msg, struct sheep *sheep)
{
	int removed = 0;
	struct sheep *s;
	struct sph_msg snd;

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_BLOCK_FORWARD;
	snd.body_len = sizeof(struct sd_node);

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		ssize_t wbytes;

		if (s->state != SHEEP_STATE_JOINED)
			continue;

		wbytes = writev2(s->fd, &snd,
				&sheep->node, sizeof(struct sd_node));
		if (sizeof(snd) + sizeof(struct sd_node) != wbytes) {
			sd_eprintf("writev2() failed: %m");
			goto block_failed;
		}

		continue;

block_failed:	/* FIXME: is this correct behaviour? */
		remove_sheep(s);
		removed++;
	}

	return;
}

static void sph_handle_leave(struct sph_msg *msg, struct sheep *sheep)
{
	struct sheep *s;
	struct sph_msg snd;

	sd_iprintf("%s is leaving", node_to_str(&sheep->node));

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_LEAVE_FORWARD;
	snd.body_len = sizeof(struct sd_node);

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		ssize_t wbytes;

		if (s->state != SHEEP_STATE_JOINED)
			continue;

		wbytes = writev2(s->fd, &snd,
				&sheep->node, sizeof(struct sd_node));
		if (sizeof(snd) + sizeof(struct sd_node) != wbytes) {
			sd_eprintf("writev2() failed: %m");
			goto fwd_leave_failed;
		}

		continue;

fwd_leave_failed:
		remove_sheep(s);
	}
}

static void (*msg_handlers[])(struct sph_msg*, struct sheep *) = {
	[SPH_CLI_MSG_JOIN] = sph_handle_join,
	[SPH_CLI_MSG_NEW_NODE_REPLY] = sph_handle_new_node_reply,
	[SPH_CLI_MSG_NOTIFY] = sph_handle_notify,
	[SPH_CLI_MSG_BLOCK] = sph_handle_block,
	[SPH_CLI_MSG_LEAVE] = sph_handle_leave,
};

static void read_msg_from_sheep(struct sheep *sheep)
{
	int ret;
	struct sph_msg rcv;

	memset(&rcv, 0, sizeof(rcv));
	ret = xread(sheep->fd, &rcv, sizeof(rcv));

	if (ret != sizeof(rcv)) {
		sd_eprintf("xread() failed: %m, ");
		goto remove;
	}

	if (!(0 <= rcv.type && rcv.type < ARRAY_SIZE(msg_handlers))) {
		sd_eprintf("invalid message type: %d, ", rcv.type);
		sd_eprintf("from node: %s", node_to_str(&sheep->node));
		sd_eprintf("from node (sockaddr): %s",
			sockaddr_in_to_str(&sheep->addr));
		sd_eprintf("read bytes: %d, body length: %d",
			ret, rcv.body_len);
		goto remove;
	}

	sd_dprintf("received op: %s", sph_cli_msg_to_str(rcv.type));

	return msg_handlers[rcv.type](&rcv, sheep);

remove:
	sd_eprintf("removing node: %s", node_to_str(&sheep->node));
	remove_sheep(sheep);
}

static void sheep_comm_handler(int fd, int events, void *data)
{
	if (events & EPOLLIN)
		read_msg_from_sheep(data);
	else if (events & EPOLLHUP || events & EPOLLERR) {
		sd_eprintf("epoll() error: %s",
			node_to_str(&((struct sheep *)data)->node));
		remove_sheep(data);
	}
}

static void sheep_accept_handler(int fd, int events, void *data)
{
	int ret;
	struct sheep *new_sheep;
	socklen_t len;

	new_sheep = xzalloc(sizeof(struct sheep));
	INIT_LIST_HEAD(&new_sheep->sheep_list);

	len = sizeof(struct sockaddr_in);
	new_sheep->fd = accept(fd, (struct sockaddr *)&new_sheep->addr, &len);
	if (new_sheep->fd < 0) {
		sd_eprintf("accept() failed: %m");
		goto clean;
	}

	if (-1 == set_keepalive(new_sheep->fd)) {
		sd_eprintf("set_keepalive() failed: %m");
		goto clean;
	}

	ret = register_event(new_sheep->fd, sheep_comm_handler, new_sheep);
	if (ret < 0) {
		sd_eprintf("register_event() failed: %m");
		goto clean;
	}

	list_add_tail(&new_sheep->sheep_list, &sheep_list_head);
	new_sheep->state = SHEEP_STATE_CONNECTED;

	INIT_LIST_HEAD(&new_sheep->join_wait_list);

	sd_iprintf("accepted new sheep connection");
	return;

clean:
	free(new_sheep);
}

static struct sd_option shepherd_options[] = {
	{ 'b', "bindaddr", true,
	  "specify IP address of interface to listen on" },
	{ 'd', "debug", false, "include debug messages in the log" },
	{ 'f', "foreground", false, "make the program run in the foreground" },
	{ 'F', "log-format", true, "specify log format" },
	{ 'h', "help", false, "display this help and exit" },
	{ 'l', "log-file", true,
	  "specify a log file for writing logs of shepherd" },
	{ 'p', "port", true, "specify TCP port on which to listen" },
	{ 0, NULL, false, NULL },
};

static void usage(void)
{
	struct sd_option *opt;

	printf("shepherd daemon:\n"
		"usage: %s <option>...\n"
		"options:\n", progname);

	sd_for_each_option(opt, shepherd_options) {
		printf("  -%c, --%-18s%s\n", opt->ch, opt->name,
			opt->desc);
	}
}

static void exit_handler(void)
{
	sd_printf(SDOG_INFO, "exiting...");
}

static int set_listen_fd_cb(int fd, void *data)
{
	int ret;

	ret = register_event(fd, sheep_accept_handler, NULL);
	if (ret)
		panic("register_event() failed: %m");

	return 0;
}

static void crash_handler(int signo)
{
	sd_printf(SDOG_EMERG, "shepherd exits unexpectedly (%s).",
		  strsignal(signo));

	sd_backtrace();

	reraise_crash_signal(signo, 1);
}

int main(int argc, char **argv)
{
	int ch, ret, longindex;
	char *p;
	bool daemonize = true;
	int log_level = SDOG_INFO;
	const char *log_file = "/var/log/shepherd.log";
	const char *log_format = "default";
	struct logger_user_info shepherd_info;

	int port = SHEPHERD_PORT;
	const char *bindaddr = NULL;

	struct option *long_options;
	const char *short_options;
	int log_size = LOG_SPACE_SIZE;

	printf(TEXT_BOLD_RED "** WARNING: shepherd is still only suitable for "
	       "testing and review **" TEXT_NORMAL "\n");

	progname = argv[0];

	install_crash_handler(crash_handler);

	long_options = build_long_options(shepherd_options);
	short_options = build_short_options(shepherd_options);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'b':
			bindaddr = optarg;
			break;
		case 'd':
			log_level = SDOG_DEBUG;
			log_size = LOG_SPACE_DEBUG_SIZE;
			break;
		case 'f':
			daemonize = false;
			break;
		case 'F':
			log_format = optarg;
			break;
		case 'h':
			usage();
			exit(0);
			break;
		case 'l':
			log_file = optarg;
			break;
		case 'p':
			port = strtol(optarg, &p, 10);
			if (p == optarg) {
				fprintf(stderr, "invalid port: %s\n", optarg);
				exit(1);
			}
			break;
		default:
			fprintf(stderr, "unknown option: %c\n", ch);
			usage();
			exit(1);
			break;
		}
	}

	if (daemonize) {
		ret = daemon(0, 0);

		if (-1 == ret) {
			fprintf(stderr, "daemon() failed: %m\n");
			exit(1);
		}
	}

	/*
	 * early_log_init() must be called before any calling of
	 * sd_printf() series
	 */
	shepherd_info.port = port;
	early_log_init(log_format, &shepherd_info);

	ret = log_init(progname, log_size, !daemonize, log_level,
		       (char *)log_file);
	if (ret)
		panic("initialize logger failed: %m");

	atexit(exit_handler);
	init_event(EPOLL_SIZE);

	remove_efd = eventfd(0, EFD_NONBLOCK);
	if (remove_efd < 0)
		panic("eventfd() failed: %m");

	ret = register_event_prio(remove_efd, remove_handler, NULL,
				EVENT_PRIO_MAX);
	if (ret)
		panic("register_event() failed: %m");

	/* setup inet socket for communication with sheeps */
	ret = create_listen_ports(bindaddr, port, set_listen_fd_cb, NULL);
	if (ret)
		panic("create_listen_ports() failed: %m");

	running = true;

	while (running)
		event_loop_prio(-1);

	return 0;
}
