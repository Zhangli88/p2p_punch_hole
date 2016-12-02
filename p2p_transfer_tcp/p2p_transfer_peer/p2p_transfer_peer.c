//#include "xl_common.h"
#include "log.h"
#include "p2p_transfer.h"
#include <unistd.h>
#include <event.h>
#include <event2/listener.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#define P2P_TRANSFER_LISTEN_MAX_NUM		(16)

#define P2P_TRANSFER_CLIENT_PORT	(5152)

struct p2p_transfer_client_t
{
	struct event_base		*base;
	uint64_t				device_sn;

	struct event			*puser_event;

	uint32_t				local_ip;

	int						conn_server_sock;
	struct event			*pping_event;
	struct bufferevent		*pping_bev;

	int						listen_lcoal_sock;
	struct evconnlistener	*listener;
};

static struct p2p_transfer_client_t *s_ppt_client = NULL;

static void listener_cb(UNUSED struct evconnlistener *listener, UNUSED evutil_socket_t conn_sock,
						UNUSED struct sockaddr *client_addr, UNUSED int socklen, UNUSED void *user_data)
{
	XL_DEBUG(EN_PRINT_DEBUG, "listener_cb ...");
}

void ping_cb(UNUSED evutil_socket_t sock, UNUSED short events, UNUSED void *user_data)
{
	XL_DEBUG(EN_PRINT_DEBUG, "ping...");

	struct p2p_msg_head_t *pmsg = NULL;
	struct p2p_msg_ping_t *pping = NULL;
	int total_len = sizeof(struct p2p_msg_head_t) + sizeof(struct p2p_msg_ping_t);

	SAFE_CALLOC(struct p2p_msg_head_t *, pmsg, total_len);
	pmsg->magic = P2P_TRANSFER_MAGIC;
	pmsg->cmd_len = sizeof(struct p2p_msg_ping_t);
	pmsg->src_device_sn = s_ppt_client->device_sn;
	pmsg->cmd = P2P_TRANSFER_PING;

	pping = (struct p2p_msg_ping_t *)(pmsg->cmd_data);
	pping->device_sn = s_ppt_client->device_sn;
	pping->network_type = NP_PORT_RESTRICTED_CONE_NAT;

	if (-1 == bufferevent_write(s_ppt_client->pping_bev, pmsg, total_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bufferevent_write() failed, send P2P_TRANSFER_PING failed");
		goto ERR;
	}
ERR:
	SAFE_FREE(pmsg);
}

static int connect_peer(struct p2p_msg_device_info_t *pdevice_info)
{
	assert(pdevice_info != NULL);

	int sock = -1;
	struct sockaddr_in peer_addr;
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(peer_addr);
	int retry = 10;

	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = s_ppt_client->local_ip;
	local_addr.sin_port = htons(P2P_TRANSFER_CLIENT_PORT);

	XL_DEBUG(EN_PRINT_DEBUG, "local_ip: %s", inet_ntoa(local_addr.sin_addr));

	memset(&peer_addr, 0, addr_len);
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr = pdevice_info->ip_addr;
	peer_addr.sin_port = pdevice_info->port;

	while (--retry)
	{
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0)
		{
			XL_DEBUG(EN_PRINT_ERROR, "call socket() failed, err: %s", strerror(errno));
			goto NEXT;
		}
		if (-1 == set_sock_opt(sock, SO_REUSEADDR|SO_REUSEPORT|SO_KEEPALIVE))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call set_sock_opt() failed");
			goto NEXT;
		}
		if (-1 == bind(sock, (const struct sockaddr *)&local_addr, addr_len))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call bind() failed, err: %s", strerror(errno));
			goto NEXT;
		}
		XL_DEBUG(EN_PRINT_DEBUG, "retry: %d, connect device_sn: %llu, ip: %s, port: %d", retry, pdevice_info->device_sn,
			inet_ntoa(peer_addr.sin_addr), htons(peer_addr.sin_port));
		if (-1 == connect(sock, (const struct sockaddr *)&peer_addr, addr_len))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call connect() failed, ip_addr: %s, port: %d, errno: %d, err: %s",
					inet_ntoa(peer_addr.sin_addr), htons(peer_addr.sin_port), errno, strerror(errno));
			if (errno != ETIMEDOUT)
			{
				sleep(20);
			}
			goto NEXT;
		}
		break;
NEXT:
		SAFE_CLOSE(sock);
	}
	if (retry == 0)
	{
		XL_DEBUG(EN_PRINT_ERROR, "punch hole failed");
		return -1;
	}
	else
	{
		XL_DEBUG(EN_PRINT_DEBUG, "punch hole success");
	}
	return sock;
}

void *process_punch_hole_cmd_cb(UNUSED void *arg)
{
	int sock = -1;

	struct p2p_msg_device_info_t *pdevice_info = (struct p2p_msg_device_info_t *)arg;

	sock = connect_peer(pdevice_info);
	if (-1 == sock)
	{
		XL_DEBUG(EN_PRINT_DEBUG, "call connect_peer() failed");
		goto ERR;
	}
	char buf[10] = { '\0' };
	if (-1 == recv(sock, buf, sizeof(buf), 0))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call recv() failed, err: %s", strerror(errno));
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_DEBUG, "recv buf: %s", buf);
ERR:
	SAFE_CLOSE(sock);
	return NULL;
}

static int process_punch_hole_cmd(struct p2p_msg_device_info_t *pdevice_info)
{
	assert(pdevice_info != NULL);

	pthread_t tid;
	if (0 != pthread_create(&tid, NULL, process_punch_hole_cmd_cb, pdevice_info))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call pthread_create() failed, err: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static void conn_read_cb(struct bufferevent *pbev, UNUSED void *user_data)
{
	struct p2p_msg_head_t *prequest = NULL;
	struct p2p_msg_device_info_t *pdevice_info = NULL;
	int msg_head_len = sizeof(struct p2p_msg_head_t);
	int device_info_len = sizeof(struct p2p_msg_device_info_t);

	SAFE_CALLOC(struct p2p_msg_head_t *, prequest, msg_head_len);

	bufferevent_read(pbev, prequest, msg_head_len);
	XL_DEBUG(EN_PRINT_DEBUG, "cmd: %d", prequest->cmd);
	switch (prequest->cmd)
	{
	case P2P_TRANSFER_PUNCH_HOLE:
		SAFE_CALLOC(struct p2p_msg_device_info_t *, pdevice_info, device_info_len);
		bufferevent_read(pbev, pdevice_info, device_info_len);
		process_punch_hole_cmd(pdevice_info);
		break;
	default:
		break;
	}
ERR:
	SAFE_FREE(prequest);
}


static void conn_event_cb(struct bufferevent *bev, short events, UNUSED void *user_data)
{
	int conn_sock = bufferevent_getfd(bev);
	if (events & BEV_EVENT_EOF)
	{
		XL_DEBUG(EN_PRINT_DEBUG, "connection closed");
	}
	else if (events & BEV_EVENT_ERROR) 
	{
		XL_DEBUG(EN_PRINT_DEBUG, "got an error on the connection, err: %s", strerror(errno));
	}
	bufferevent_free(bev);
	SAFE_CLOSE(conn_sock);
}

static int connect_server(struct p2p_transfer_client_t *ppt_client)
{
	assert(ppt_client != NULL);

	int sock = -1;
	struct bufferevent *pping_bev = NULL;
	struct sockaddr_in server_addr;
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(server_addr);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sock)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call socket() failed, err: %s", strerror(errno));
		goto ERR;
	}
	if (-1 == set_sock_opt(sock, SO_REUSEADDR|SO_REUSEPORT|SO_KEEPALIVE))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call set_sock_opt() failed");
		goto ERR;
	}
	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = ppt_client->local_ip;
	local_addr.sin_port = htons(P2P_TRANSFER_CLIENT_PORT);

	if (-1 == bind(sock, (const struct sockaddr *)&local_addr, addr_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bind() failed, err: %s", strerror(errno));
		goto ERR;
	}

	memset(&server_addr, 0, addr_len);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(P2P_TRANSFER_SERVER_IP);
	server_addr.sin_port = htons(P2P_TRANSFER_SERVER_PORT);

	if (-1 == connect(sock, (const struct sockaddr *)&server_addr, addr_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call connect() failed, server ip: %s, err: %s", inet_ntoa(server_addr.sin_addr),
			strerror(errno));
		goto ERR;
	}

	pping_bev = bufferevent_socket_new(ppt_client->base, sock, BEV_OPT_CLOSE_ON_FREE);
	if (NULL == pping_bev)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bufferevent_socket_new() failed, sock: %d", sock);
		goto ERR;
	}
	bufferevent_setcb(pping_bev, conn_read_cb, NULL, conn_event_cb, NULL);
	bufferevent_enable(pping_bev, EV_READ);

	ppt_client->conn_server_sock = sock;
	ppt_client->pping_bev = pping_bev;
	return 0;
ERR:
	if (NULL != pping_bev)
	{
		bufferevent_free(pping_bev);
	}
	SAFE_CLOSE(sock);
	return -1;
}

static int listen_local(struct p2p_transfer_client_t *ppt_client)
{
	assert(ppt_client != NULL);
	
	int sock = -1;
	struct evconnlistener	*listener = NULL;
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(local_addr);

	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = ppt_client->local_ip;
	local_addr.sin_port = htons(P2P_TRANSFER_CLIENT_PORT);
	
	listener = evconnlistener_new_bind(ppt_client->base, listener_cb, NULL, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
		(struct sockaddr*)&local_addr, addr_len);
	if (NULL == listener)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call evconnlistener_new_bind() failed");
		goto ERR;
	}
	sock = evconnlistener_get_fd(listener);
	if (-1 == set_sock_opt(sock, SO_REUSEADDR|SO_REUSEPORT|SO_KEEPALIVE))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call set_sock_opt() failed");
		goto ERR;
	}
	ppt_client->listen_lcoal_sock = sock;
	ppt_client->listener = listener;
	return 0;
ERR:
	if (listener != NULL)
	{
		evconnlistener_free(listener);
	}
	return -1;
}

static int add_ping_timer(struct p2p_transfer_client_t *ppt_client)
{
	assert(ppt_client != NULL);

	struct event *ping_event = NULL;
	struct timeval ping_timeout = {5, 0};

	ping_event = event_new(ppt_client->base, -1, EV_TIMEOUT, ping_cb, NULL);
	if (NULL == ping_event)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call evtimer_new() failed");
		goto ERR;
	}
	event_add(ping_event, &ping_timeout);
	event_active(ping_event, EV_TIMEOUT, 0);
	ppt_client->pping_event = ping_event;
	return 0;
ERR:
	if (NULL != ping_event)
	{
		event_free(ping_event);
	}
	return -1;
}
void exit_cb(UNUSED evutil_socket_t sock, UNUSED short events, UNUSED void *user_data)
{
	XL_DEBUG(EN_PRINT_NOTICE, "exit loop...");
	event_loopbreak();
}

struct p2p_transfer_client_t *init(int argc, char **argv)
{
	struct p2p_transfer_client_t *ppt_client = NULL;

	if (-1 == configure_log(EN_PRINT_DEBUG, "/var/log/p2p_transfer_peer.log", 1))
	{
		printf("call configure_log() failed");
		return NULL;
	}

	ppt_client = (struct p2p_transfer_client_t *)calloc(1, sizeof(struct p2p_transfer_client_t));
	if (NULL == ppt_client)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call calloc() failed, err: %s", strerror(errno));
		return NULL;
	}

	if (argc > 1)
	{
		ppt_client->device_sn = atoi(argv[1]);
	}
	else
	{
		ppt_client->device_sn = 1111;
	}
	if (argc > 2)
	{
		ppt_client->local_ip = inet_addr(argv[2]);
	}

	ppt_client->listen_lcoal_sock = ppt_client->conn_server_sock = -1;

	ppt_client->base = event_base_new();
	if (NULL == ppt_client->base)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_new() failed");
		return NULL;
	}
	return ppt_client;
}

static void uninit(struct p2p_transfer_client_t *ppt_client)
{
	if (ppt_client == NULL)
	{
		return ;
	}
	if (NULL != ppt_client->puser_event)
	{
		event_free(ppt_client->puser_event);
		ppt_client->puser_event = NULL;
	}
	if (NULL != ppt_client->pping_event)
	{
		event_free(ppt_client->pping_event);
		ppt_client->pping_event = NULL;
	}
	if (ppt_client->listener != NULL)
	{
		evconnlistener_free(ppt_client->listener);
		ppt_client->listener = NULL;
	}
	if (ppt_client->conn_server_sock > 0)
	{
		close(ppt_client->conn_server_sock);
		ppt_client->conn_server_sock = -1;
	}
	if (ppt_client->listen_lcoal_sock > 0)
	{
		close(ppt_client->listen_lcoal_sock);
		ppt_client->listen_lcoal_sock = -1;
	}
	if (ppt_client->base != NULL)
	{
		event_base_free(ppt_client->base);
		ppt_client->base = NULL;
	}
	destroy_log();
}

static int punch_hole(struct p2p_msg_device_info_t *pdevice_info)
{
	assert(pdevice_info != NULL);

	XL_DEBUG(EN_PRINT_ERROR, "be called");

	int sock = -1;
	
	sock = connect_peer(pdevice_info);
	if (-1 == sock)
	{
		XL_DEBUG(EN_PRINT_DEBUG, "call connect_peer() failed");
		goto ERR;
	}	
	if (-1 == send(sock, "abc", strlen("abc"), 0))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call send() failed, err: %s", strerror(errno));
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_DEBUG, "p2p send success");
	SAFE_CLOSE(sock);
	return 0;
ERR:
	SAFE_CLOSE(sock);
	return -1;
}

void user_cb(UNUSED evutil_socket_t tmp_sock, UNUSED short events, UNUSED void *user_data)
{
	XL_DEBUG(EN_PRINT_ERROR, "be called");

	struct p2p_msg_head_t *prequest = NULL, *presponse = NULL;
	struct p2p_msg_device_info_t *pquery_device_info = NULL;
	int total_len = sizeof(struct p2p_msg_head_t) + sizeof(struct p2p_msg_device_info_t);
	int sock = s_ppt_client->conn_server_sock;
	uint64_t test_peer_device_sn = 2222;

	SAFE_CALLOC(struct p2p_msg_head_t *, prequest, total_len);
	SAFE_CALLOC(struct p2p_msg_head_t *, presponse, total_len);

	prequest->magic = P2P_TRANSFER_MAGIC;
	prequest->src_device_sn = s_ppt_client->device_sn;
	prequest->cmd_len = sizeof(struct p2p_msg_device_info_t);
	prequest->cmd = P2P_TRANSFER_QUERY_DEVICE_INFO_REQUEST;
	
	pquery_device_info = (struct p2p_msg_device_info_t *)(prequest->cmd_data);
	pquery_device_info->device_sn = test_peer_device_sn;

	if (-1 == send(sock, prequest, total_len, 0))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call send() failed, total_len: %d, err: %s", total_len, strerror(errno));
		goto ERR;
	}

	XL_DEBUG(EN_PRINT_DEBUG, "recv...");
	if (-1 == recv(sock, presponse, total_len, 0))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call recv() failed, total_len: %d, err: %s", total_len, strerror(errno));
		goto ERR;
	}
	if (presponse->cmd == P2P_TRANSFER_UNKNOWN_CMD)
	{
		XL_DEBUG(EN_PRINT_ERROR, "query device info failed, device_sn: %llu", pquery_device_info->device_sn);
		goto ERR;
	}

	pquery_device_info = (struct p2p_msg_device_info_t *)(presponse->cmd_data);
	XL_DEBUG(EN_PRINT_DEBUG, "peer: %llu, ip: %s, port: %d", test_peer_device_sn, inet_ntoa(pquery_device_info->ip_addr), htons(pquery_device_info->port));

	(void)punch_hole(pquery_device_info);
ERR:
	SAFE_FREE(prequest);
	SAFE_FREE(presponse);
}

static int add_user_timer(struct p2p_transfer_client_t *ppt_client)
{
	struct event *puser_event = NULL;
	struct timeval user_timeout = { 10, 0 };

	puser_event = event_new(ppt_client->base, -1, EV_TIMEOUT, user_cb, NULL);
	if (NULL == puser_event)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_new() failed");
		goto ERR;
	}
	event_add(puser_event, &user_timeout);
	ppt_client->puser_event = puser_event;
	return 0;
ERR:
	if (NULL != puser_event)
	{
		event_free(puser_event);
	}
	return -1;
}

int main(int argc, char **argv)
{
	s_ppt_client = init(argc, argv);
	if (NULL == s_ppt_client)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call init() failed");
		goto ERR;
	}

	if (-1 == listen_local(s_ppt_client))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call listen_local() failed");
		goto ERR;
	}
	if (-1 == connect_server(s_ppt_client))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call connect_server() failed");
		goto ERR;
	}	
	if (-1 == add_ping_timer(s_ppt_client))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call add_ping_timer() failed");
		goto ERR;
	}
	

	XL_DEBUG(EN_PRINT_NOTICE, "device_sn: %llu, listen_local_sock: %d, conn_server_sock: %d",
		s_ppt_client->device_sn, s_ppt_client->listen_lcoal_sock, s_ppt_client->conn_server_sock);

	if (s_ppt_client->device_sn != 2222)
	{
		if (-1 == add_user_timer(s_ppt_client))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call add_user_timer() failed");
			goto ERR;
		}
	}

	XL_DEBUG(EN_PRINT_NOTICE, "enter event_base_dispatch()...");
	if (-1 == event_base_dispatch(s_ppt_client->base))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_dispatch() failed");
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_NOTICE, "exit");
	uninit(s_ppt_client);
	return 0;
ERR:
	uninit(s_ppt_client);
	return -1;
}