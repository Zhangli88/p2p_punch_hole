#include "log.h"
#include "p2p_transfer.h"
#include "list.h"
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
#include <assert.h>

#define P2P_TRANSFER_LISTEN_MAX_NUM		(16)

struct p2p_server_device_info_t
{
	struct list_head	list;
	struct bufferevent	*pbev;
	uint64_t            device_sn;       
	struct in_addr		ip_addr;		/**< nat之后的ip地址，网络序. >*/
	uint16_t            port;			/**< nat之后的端口，网络序. >*/
	int                 network_type;
};

struct p2p_server_device_info_t *s_pall_device_info = NULL;

static void print_all_device_info()
{
	struct p2p_server_device_info_t *pindex = NULL;
	list_for_each_entry(pindex, &(s_pall_device_info->list), list)
	{
		XL_DEBUG(EN_PRINT_DEBUG, "device_sn: %llu, ip: %s, port: %d, network_type: %s", pindex->device_sn,
			inet_ntoa(pindex->ip_addr), htons(pindex->port), get_string_network_type(pindex->network_type));
	}
}

#if 0
static int connect_client(const struct p2p_msg_device_info_t *pdevice_info)
{
	XL_DEBUG(EN_PRINT_DEBUG, "be called");
	assert(pdevice_info != NULL);

	int sock = -1;
	struct sockaddr_in peer_addr;
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(peer_addr);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call socket() failed, err: %s", strerror(errno));
		goto ERR;
	}
	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = inet_addr(P2P_TRANSFER_SERVER_IP);
	local_addr.sin_port = htons(P2P_TRANSFER_SERVER_PORT+1);
	XL_DEBUG(EN_PRINT_DEBUG, "local ip: %s, port: %d", inet_ntoa(local_addr.sin_addr), ntohs(local_addr.sin_port));

	if (-1 == bind(sock, (const struct sockaddr *)&local_addr, addr_len))
	{
		XL_DEBUG(EN_PRINT_DEBUG, "call bind() failed, local ip: %s, port: %d, err: %s", inet_ntoa(local_addr.sin_addr),
			ntohs(local_addr.sin_port), strerror(errno));
		goto ERR;
	}

	memset(&peer_addr, 0, addr_len);
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr = pdevice_info->ip_addr;
	peer_addr.sin_port = pdevice_info->port;
	XL_DEBUG(EN_PRINT_DEBUG, "connect device_sn: %lu, ip: %s, port: %d", pdevice_info->device_sn,
		inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));

	if (-1 == connect(sock, (const struct sockaddr *)&peer_addr, addr_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call connect() failed, ip_addr: %s, port: %d, err: %s",
			inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port), strerror(errno));
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_NOTICE, "punch hole success");
	SAFE_CLOSE(sock);
	return 0;
ERR:
	SAFE_CLOSE(sock);
	return -1;
}
#endif

static int process_ping_cmd(struct bufferevent *pbev, const struct p2p_msg_ping_t *pping, const struct sockaddr_in *pclient_addr)
{
	assert(pping != NULL);
	assert(pclient_addr != NULL);
	assert(pbev != NULL);

	struct p2p_server_device_info_t *pdevice_info = NULL;
	SAFE_CALLOC(struct p2p_server_device_info_t *, pdevice_info, sizeof(struct p2p_server_device_info_t));

	XL_DEBUG(EN_PRINT_DEBUG, "device_sn: %d, network_type: %d", pping->device_sn, pping->network_type);

	/// TODO:先判断是否存在
	INIT_LIST_HEAD(&(pdevice_info->list));
	pdevice_info->pbev = pbev;
	pdevice_info->device_sn = pping->device_sn;
	pdevice_info->network_type = pping->network_type;
	pdevice_info->ip_addr = pclient_addr->sin_addr;
	pdevice_info->port = pclient_addr->sin_port;
	list_add(&(pdevice_info->list), &(s_pall_device_info->list));

	print_all_device_info();

#if 0
	struct p2p_msg_device_info_t device_info;
	memset(&device_info, 0, sizeof(device_info));
	device_info.device_sn = pping->device_sn;
	device_info.network_type = pping->network_type;
	device_info.ip_addr = pclient_addr->sin_addr;
	device_info.port = pclient_addr->sin_port;
	int retry = 3;
	sleep(10);
	while (retry)
	{
		retry--;
		sleep(1);
		if (0 == connect_client(&device_info))
		{
			break;
		}
	}
#endif
	return 0;
ERR:
	SAFE_FREE(pdevice_info);
	return -1;
}

static int send_punch_hole_cmd_to_peer(struct bufferevent *pdst_peer_bev, const struct p2p_msg_device_info_t *psrc_peer)
{
	assert(pdst_peer_bev != NULL);
	assert(psrc_peer != NULL);

	struct p2p_msg_head_t *pmsg = NULL;
	struct p2p_msg_device_info_t *pdevice_info = NULL;
	int total_len = sizeof(struct p2p_msg_head_t) + sizeof(struct p2p_msg_device_info_t);

	SAFE_CALLOC(struct p2p_msg_head_t *, pmsg, total_len);

	pmsg->magic = P2P_TRANSFER_MAGIC;
	pmsg->cmd = P2P_TRANSFER_PUNCH_HOLE;
	pmsg->cmd_len = sizeof(struct p2p_msg_device_info_t);
	pdevice_info = (struct p2p_msg_device_info_t *)(pmsg->cmd_data);

	pdevice_info->device_sn = psrc_peer->device_sn;
	pdevice_info->ip_addr = psrc_peer->ip_addr;
	pdevice_info->port = psrc_peer->port;
	pdevice_info->network_type = psrc_peer->network_type;
	
	if (-1 == bufferevent_write(pdst_peer_bev, pmsg, total_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bufferevent_write() failed, send P2P_TRANSFER_PUNCH_HOLE failed");
		goto ERR;
	}
	SAFE_FREE(pmsg);
	return 0;
ERR:
	SAFE_FREE(pmsg);
	return -1;
}

static int process_query_device_info_cmd(struct bufferevent *pquery_bev, uint64_t src_devcie_sn, uint64_t query_device_sn)
{
	assert(pquery_bev != NULL);

	struct p2p_msg_head_t *presponse = NULL;
	struct p2p_msg_device_info_t *psrc_device_info = NULL;
	struct p2p_msg_device_info_t *pquery_device_info = NULL;
	int total_len = sizeof(struct p2p_msg_head_t) + sizeof(struct p2p_msg_device_info_t);
	struct p2p_server_device_info_t *pindex = NULL;
	int num = 0;

	SAFE_CALLOC(struct p2p_msg_head_t *, presponse, total_len);
	SAFE_CALLOC(struct p2p_msg_device_info_t *, psrc_device_info, sizeof(struct p2p_msg_device_info_t));
	
	presponse->magic = P2P_TRANSFER_MAGIC;
	presponse->cmd = P2P_TRANSFER_UNKNOWN_CMD;
	presponse->cmd_len = sizeof(struct p2p_msg_device_info_t);
	pquery_device_info = (struct p2p_msg_device_info_t *)(presponse->cmd_data);
	struct bufferevent	*pdst_peer_bev = NULL;

	list_for_each_entry(pindex, &(s_pall_device_info->list), list)
	{
		if (pindex->device_sn == query_device_sn)
		{
			presponse->cmd = P2P_TRANSFER_QUERY_DEVICE_INFO_RESPONSE;

			pquery_device_info->device_sn = pindex->device_sn;
			pquery_device_info->ip_addr = pindex->ip_addr;
			pquery_device_info->port = pindex->port;
			pquery_device_info->network_type = pindex->network_type;

			pdst_peer_bev = pindex->pbev;
			num += 1;
		}
		if (pindex->device_sn == src_devcie_sn)
		{
			psrc_device_info->device_sn = pindex->device_sn;
			psrc_device_info->device_sn = pindex->device_sn;
			psrc_device_info->ip_addr = pindex->ip_addr;
			psrc_device_info->port = pindex->port;
			psrc_device_info->network_type = pindex->network_type;
			num += 1;
		}
		if (num == 2)
		{
			break;
		}
	}
	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_PUNCH_HOLE to device %llu", query_device_sn);
	// 发送消息给目的peer
	if (-1 == send_punch_hole_cmd_to_peer(pdst_peer_bev, psrc_device_info))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call send_punch_hole_cmd_to_peer() failed");
		goto ERR;
	}

	// 回复请求者
	if (-1 == bufferevent_write(pquery_bev, presponse, total_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bufferevent_write() failed, send P2P_TRANSFER_QUERY_DEVICE_INFO_RESPONSE failed");
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_DEBUG, "response query success, src_device_sn: %llu, query_device_sn: %llu",
		src_devcie_sn, query_device_sn);
	if (NULL == pdst_peer_bev)
	{
		XL_DEBUG(EN_PRINT_ERROR, "no peer is found, query_device_sn: %llu", query_device_sn);
		goto ERR;
	}
	SAFE_FREE(psrc_device_info);
	SAFE_FREE(presponse);
	return 0;
ERR:
	SAFE_FREE(psrc_device_info);
	SAFE_FREE(presponse);
	return -1;
}

static void conn_read_cb(struct bufferevent *pbev, UNUSED void *user_data)
{
	struct p2p_msg_head_t *prequest = NULL;
	struct p2p_msg_ping_t *pping = NULL;
	struct p2p_msg_device_info_t *pquery_device_info = NULL;
	int msg_head_len = sizeof(struct p2p_msg_head_t);
	int msg_ping_len = sizeof(struct p2p_msg_ping_t);
	int device_info_len = sizeof(struct p2p_msg_device_info_t);
	
	SAFE_CALLOC(struct p2p_msg_head_t *, prequest, msg_head_len);

	bufferevent_read(pbev, prequest, msg_head_len);
	XL_DEBUG(EN_PRINT_DEBUG, "cmd: %d", prequest->cmd);
	switch (prequest->cmd)
	{
	case P2P_TRANSFER_PING:
		SAFE_CALLOC(struct p2p_msg_ping_t *, pping, msg_ping_len);
		bufferevent_read(pbev, pping, msg_ping_len);
		process_ping_cmd(pbev, pping, (struct sockaddr_in *)user_data);
		break;
	case P2P_TRANSFER_QUERY_DEVICE_INFO_REQUEST:
		SAFE_CALLOC(struct p2p_msg_device_info_t *, pquery_device_info, device_info_len);
		bufferevent_read(pbev, pquery_device_info, device_info_len);
		process_query_device_info_cmd(pbev, prequest->src_device_sn, pquery_device_info->device_sn);
		break;
	default:
		break;
	}
ERR:
	SAFE_FREE(prequest);
}

static void conn_event_cb(struct bufferevent *bev, short events, UNUSED void *user_data)
{
	struct sockaddr_in *pclient_addr = (struct sockaddr_in *)user_data;
	int conn_sock = bufferevent_getfd(bev);

	if (events & BEV_EVENT_EOF)
	{
		XL_DEBUG(EN_PRINT_DEBUG, "connection closed");
	}
	else if (events & BEV_EVENT_ERROR) 
	{
		XL_DEBUG(EN_PRINT_DEBUG, "got an error on the connection, err: %s", strerror(errno));
	}
	SAFE_FREE(pclient_addr);
	bufferevent_free(bev);
	SAFE_CLOSE(conn_sock);
}

static void listener_cb(struct evconnlistener *listener, evutil_socket_t conn_sock, struct sockaddr *addr,
						UNUSED int socklen, UNUSED void *user_data)
{
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = NULL;
	struct sockaddr_in *pclient_addr = NULL;
	int addr_len = sizeof(struct sockaddr_in);

	// XXX:最终在conn_event_cb中释放
	SAFE_CALLOC(struct sockaddr_in *, pclient_addr, addr_len);
	memcpy(pclient_addr, addr, addr_len);

	XL_DEBUG(EN_PRINT_DEBUG, "client ip: %s, port: %d, sock: %d", inet_ntoa(pclient_addr->sin_addr),
		ntohs(pclient_addr->sin_port), conn_sock);

	bev = bufferevent_socket_new(base, conn_sock, BEV_OPT_CLOSE_ON_FREE);
	if (NULL == bev)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bufferevent_socket_new() failed, conn_sock: %d", conn_sock);
		goto ERR;
	}
	bufferevent_setcb(bev, conn_read_cb, NULL, conn_event_cb, pclient_addr);
	bufferevent_enable(bev, EV_READ);
	return ;
ERR:
	if (NULL != bev)
	{
		bufferevent_free(bev);
	}
	SAFE_FREE(pclient_addr);
}


int main()
{
	struct event_base *base = NULL;
	struct evconnlistener *listener = NULL;
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(local_addr);

	SAFE_CALLOC(struct p2p_server_device_info_t *, s_pall_device_info, sizeof(struct p2p_server_device_info_t));
	INIT_LIST_HEAD(&(s_pall_device_info->list));

	if (-1 == configure_log(EN_PRINT_DEBUG, "/var/log/p2p_transfer_server.log", 1))
	{
		printf("call configure_log() failed");
		goto ERR;
	}
	
	base = event_base_new();
	if (NULL == base)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_new() failed");
		goto ERR;
	}

	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = inet_addr(P2P_TRANSFER_SERVER_IP);
	local_addr.sin_port = htons(P2P_TRANSFER_SERVER_PORT);

	listener = evconnlistener_new_bind(base, listener_cb, NULL, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, P2P_TRANSFER_LISTEN_MAX_NUM,
		(const struct sockaddr*)&local_addr, addr_len);
	if (NULL == listener)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call evconnlistener_new_bind() failed, err: %s", strerror(errno));
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_NOTICE, "enter event_base_dispatch()...");
	if (-1 == event_base_dispatch(base))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_dispatch() failed");
		goto ERR;
	}
	evconnlistener_free(listener);
	event_base_free(base);
	destroy_log();
	return 0;
ERR:
	if (NULL != listener)
	{
		evconnlistener_free(listener);
	}
	if (NULL != base)
	{
		event_base_free(base);
	}
	SAFE_FREE(s_pall_device_info);
	destroy_log();
	return -1;
}
