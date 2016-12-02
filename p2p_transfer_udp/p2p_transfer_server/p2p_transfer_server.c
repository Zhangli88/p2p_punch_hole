#include "log.h"
#include "p2p_transfer.h"
#include "list.h"
#include <unistd.h>
#include <event.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

struct p2p_server_device_info_t
{
	struct list_head	list;
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

static int process_ping_cmd(const struct p2p_msg_ping_t *pping, const struct sockaddr_in *ppeer_addr)
{
	assert(pping != NULL);
	assert(ppeer_addr != NULL);

	struct p2p_server_device_info_t *pdevice_info = NULL;
	SAFE_CALLOC(struct p2p_server_device_info_t *, pdevice_info, sizeof(struct p2p_server_device_info_t));

	XL_DEBUG(EN_PRINT_DEBUG, "device_sn: %d, network_type: %d", pping->device_sn, pping->network_type);

	/// TODO:先判断是否存在
	INIT_LIST_HEAD(&(pdevice_info->list));
	pdevice_info->device_sn = pping->device_sn;
	pdevice_info->network_type = pping->network_type;
	pdevice_info->ip_addr = ppeer_addr->sin_addr;
	pdevice_info->port = ppeer_addr->sin_port;
	list_add(&(pdevice_info->list), &(s_pall_device_info->list));

	print_all_device_info();
	return 0;
ERR:
	SAFE_FREE(pdevice_info);
	return -1;
}

int send_punch_hole_cmd_to_peer(int sock, const struct p2p_msg_device_info_t *psrc_device_info,
								const struct p2p_msg_device_info_t *pquery_device_info)
{
	assert(psrc_device_info != NULL);
	assert(pquery_device_info != NULL);

	struct sockaddr_in peer_addr;
	struct p2p_msg_head_t *pmsg = NULL;
	struct p2p_msg_device_info_t *pdevice_info = NULL;
	int total_len = sizeof(*pmsg) + sizeof(*pdevice_info);

	SAFE_CALLOC(struct p2p_msg_head_t *, pmsg, total_len);
	pmsg->magic = P2P_TRANSFER_MAGIC;
	pmsg->cmd_len = 0;
	pmsg->cmd = P2P_TRANSFER_PUNCH_HOLE;
	pdevice_info = (struct p2p_msg_device_info_t *)pmsg->cmd_data;

	pdevice_info->device_sn = psrc_device_info->device_sn;
	pdevice_info->ip_addr = psrc_device_info->ip_addr;
	pdevice_info->port = psrc_device_info->port;
	pdevice_info->network_type = psrc_device_info->network_type;

	generate_peer_addr(&peer_addr, pquery_device_info);
	SAFE_SENDTO(sock, pmsg, total_len, &peer_addr);
	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_PUNCH_HOLE to device(%d) success", pquery_device_info->device_sn);
	SAFE_FREE(pmsg);
	return 0;
ERR:
	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_PUNCH_HOLE to device(%d) failed", pquery_device_info->device_sn);
	SAFE_FREE(pmsg);
	return -1;

}

static int process_query_device_info_cmd(int sock, uint64_t src_device_sn, uint64_t query_device_sn, const struct sockaddr_in *psrc_peer_addr)
{
	assert(psrc_peer_addr != NULL);

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

	list_for_each_entry(pindex, &(s_pall_device_info->list), list)
	{
		if (pindex->device_sn == query_device_sn)
		{
			presponse->cmd = P2P_TRANSFER_QUERY_DEVICE_INFO_RESPONSE;

			pquery_device_info->device_sn = pindex->device_sn;
			pquery_device_info->ip_addr = pindex->ip_addr;
			pquery_device_info->port = pindex->port;
			pquery_device_info->network_type = pindex->network_type;
			num += 1;
		}
		if (pindex->device_sn == src_device_sn)
		{
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
	if (presponse->cmd == P2P_TRANSFER_QUERY_DEVICE_INFO_RESPONSE)
	{
		// 先给查询的peer发送打洞命令
		if (-1 == send_punch_hole_cmd_to_peer(sock, psrc_device_info, pquery_device_info))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call send_punch_hole_cmd_to_peer failed");
			goto ERR;
		}
	}
	SAFE_SENDTO(sock, presponse, total_len, psrc_peer_addr);
	XL_DEBUG(EN_PRINT_DEBUG, "response query success, src_device_sn: %llu, query_device_sn: %llu", src_device_sn, query_device_sn);

	SAFE_FREE(psrc_device_info);
	SAFE_FREE(presponse);
	return 0;
ERR:
	SAFE_FREE(psrc_device_info);
	SAFE_FREE(presponse);
	return -1;
}

void read_cb(evutil_socket_t sock, UNUSED short events, UNUSED void *user_data)
{
	struct sockaddr_in peer_addr;
	struct p2p_msg_head_t *prequest = NULL;
	struct p2p_msg_ping_t *pping = NULL;
	struct p2p_msg_device_info_t *pquery_device_info = NULL;
	
	SAFE_CALLOC(struct p2p_msg_head_t *, prequest, P2P_TRANSFER_MAX_MSG_LENGTH);
	SAFE_RECVFROM(sock, prequest, P2P_TRANSFER_MAX_MSG_LENGTH, &peer_addr);
	XL_DEBUG(EN_PRINT_DEBUG, "cmd: %s", get_string_cmd(prequest->cmd));
	switch (prequest->cmd)
	{
	case P2P_TRANSFER_PING:
		pping = (struct p2p_msg_ping_t *)(prequest->cmd_data);
		process_ping_cmd(pping, &peer_addr);
		break;
	case P2P_TRANSFER_QUERY_DEVICE_INFO_REQUEST:
		pquery_device_info = (struct p2p_msg_device_info_t *)(prequest->cmd_data);
		process_query_device_info_cmd(sock, prequest->src_device_sn, pquery_device_info->device_sn, &peer_addr);
		break;
	default:
		break;
	}
ERR:
	SAFE_FREE(prequest);
}

int main()
{
	int sock = -1;
	struct event *pread_event = NULL;
	struct event_base *base = NULL;
	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(local_addr);

	SAFE_CALLOC(struct p2p_server_device_info_t *, s_pall_device_info, sizeof(struct p2p_server_device_info_t));
	INIT_LIST_HEAD(&(s_pall_device_info->list));

	if (-1 == configure_log(EN_PRINT_DEBUG, "/var/log/p2p_transfer_server.log", 1))
	{
		printf("call configure_log() failed");
		goto ERR;
	}
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
	{
		XL_DEBUG(EN_PRINT_DEBUG, "call socket() failed, err: %s", strerror(errno));
		goto ERR;
	}
	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = inet_addr(P2P_TRANSFER_SERVER_IP);
	local_addr.sin_port = htons(P2P_TRANSFER_SERVER_PORT);

	if (-1 == bind(sock, (const struct sockaddr *)&local_addr, addr_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bind() failed, err: %s", strerror(errno));
		goto ERR;
	}

	base = event_base_new();
	if (NULL == base)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_new() failed");
		goto ERR;
	}

	pread_event = event_new(base, sock, EV_READ|EV_PERSIST, read_cb, NULL);
	if (NULL == pread_event)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_new() failed");
		goto ERR;
	}
	event_add(pread_event, NULL);

	XL_DEBUG(EN_PRINT_NOTICE, "enter event_base_dispatch()...");
	if (-1 == event_base_dispatch(base))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_dispatch() failed");
		goto ERR;
	}
	event_base_free(base);
	destroy_log();
	return 0;
ERR:
	if (NULL != base)
	{
		event_base_free(base);
	}
	SAFE_FREE(s_pall_device_info);
	destroy_log();
	return -1;
}
