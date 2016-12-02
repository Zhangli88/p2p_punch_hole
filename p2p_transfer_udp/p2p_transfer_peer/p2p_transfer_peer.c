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
#include <stdio.h>


#define P2P_TRANSFER_CLIENT_PORT	(5152)
static int s_my_device_sn;
static int s_sock = -1;

int process_punch_hole_cmd(struct p2p_msg_device_info_t *pdevice_info)
{
	struct sockaddr_in peer_addr;
	struct p2p_msg_head_t *pmsg = NULL;
	int total_len = sizeof(struct p2p_msg_head_t);

	SAFE_CALLOC(struct p2p_msg_head_t *, pmsg, total_len);
	pmsg->magic = P2P_TRANSFER_MAGIC;
	pmsg->cmd_len = 0;
	pmsg->src_device_sn = s_my_device_sn;
	pmsg->cmd = P2P_TRANSFER_PUNCH_HOLE_TO_PEER;

	generate_peer_addr(&peer_addr, pdevice_info);
	SAFE_SENDTO(s_sock, pmsg, total_len, &peer_addr);
	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_PUNCH_HOLE_TO_PEER success");
	SAFE_FREE(pmsg);
	return 0;
ERR:
	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_PUNCH_HOLE_TO_PEER failed");
	SAFE_FREE(pmsg);
	return -1;
}

int punch_hole(const struct p2p_msg_device_info_t *pdevice_info)
{
	assert(pdevice_info != NULL);

	XL_DEBUG(EN_PRINT_DEBUG, "be called");

	sleep(5);

	struct sockaddr_in peer_addr;	
	struct p2p_msg_head_t *pmsg = NULL;
	char *user_data = "abc";
	int data_len = strlen(user_data) + 1;
	int total_len = sizeof(*pmsg) + data_len;

	SAFE_CALLOC(struct p2p_msg_head_t *, pmsg, total_len);

	pmsg->magic = P2P_TRANSFER_MAGIC;
	pmsg->src_device_sn = s_my_device_sn;	
	pmsg->cmd = P2P_TRANSFER_USER_DATA;
	pmsg->cmd_len = data_len;
	memcpy(pmsg->cmd_data, user_data, data_len);

	generate_peer_addr(&peer_addr, pdevice_info);
	SAFE_SENDTO(s_sock, pmsg, total_len, &peer_addr);

	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_USER_DATA success");
	SAFE_FREE(pmsg);
	return 0;
ERR:
	XL_DEBUG(EN_PRINT_DEBUG, "send P2P_TRANSFER_USER_DATA failed");
	SAFE_FREE(pmsg);
	return -1;
}

void read_cb(UNUSED evutil_socket_t sock, UNUSED short events, UNUSED void *user_data)
{
	struct p2p_msg_head_t *prequest = NULL;
	struct p2p_msg_device_info_t *pdevice_info = NULL;

	SAFE_CALLOC(struct p2p_msg_head_t *, prequest, P2P_TRANSFER_MAX_MSG_LENGTH);

	SAFE_RECVFROM(s_sock, prequest, P2P_TRANSFER_MAX_MSG_LENGTH, NULL);
	XL_DEBUG(EN_PRINT_DEBUG, "cmd: %s", get_string_cmd(prequest->cmd));
	switch (prequest->cmd)
	{
	case P2P_TRANSFER_PUNCH_HOLE:
		pdevice_info = (struct p2p_msg_device_info_t *)(prequest->cmd_data);
		(void)process_punch_hole_cmd(pdevice_info);
		break;
	case P2P_TRANSFER_QUERY_DEVICE_INFO_RESPONSE:
		pdevice_info = (struct p2p_msg_device_info_t *)(prequest->cmd_data);
		(void)punch_hole(pdevice_info);
	case P2P_TRANSFER_PUNCH_HOLE_TO_PEER:
		// nothing
		break;
	case P2P_TRANSFER_USER_DATA:
		XL_DEBUG(EN_PRINT_DEBUG, "punch hole success, user_data: %s", (char*)(prequest->cmd_data));
	default:
		break;
	}
ERR:
	SAFE_FREE(prequest);
}

void ping_cb(UNUSED evutil_socket_t sock, UNUSED short events, UNUSED void *user_data)
{
	XL_DEBUG(EN_PRINT_DEBUG, "ping...");
	
	struct p2p_msg_head_t *pmsg = NULL;
	struct p2p_msg_ping_t *pping = NULL;
	int total_len = sizeof(struct p2p_msg_head_t) + sizeof(struct p2p_msg_ping_t);
	struct sockaddr_in server_addr;

	SAFE_CALLOC(struct p2p_msg_head_t *, pmsg, total_len);
	pmsg->magic = P2P_TRANSFER_MAGIC;
	pmsg->cmd_len = sizeof(struct p2p_msg_ping_t);
	pmsg->src_device_sn = s_my_device_sn;
	pmsg->cmd = P2P_TRANSFER_PING;

	pping = (struct p2p_msg_ping_t *)(pmsg->cmd_data);
	pping->device_sn = s_my_device_sn;
	pping->network_type = NP_PORT_RESTRICTED_CONE_NAT;

	generate_server_addr(&server_addr);
	SAFE_SENDTO(s_sock, pmsg, total_len, &server_addr);
ERR:
	SAFE_FREE(pmsg);
}

void user_cb(UNUSED evutil_socket_t sock, UNUSED short events, UNUSED void *user_data)
{
	struct p2p_msg_head_t *prequest = NULL, *presponse = NULL;
	struct p2p_msg_device_info_t *pquery_device_info = NULL;
	int total_len = sizeof(struct p2p_msg_head_t) + sizeof(struct p2p_msg_device_info_t);
	struct sockaddr_in server_addr;

	SAFE_CALLOC(struct p2p_msg_head_t *, prequest, total_len);
	SAFE_CALLOC(struct p2p_msg_head_t *, presponse, total_len);

	prequest->magic = P2P_TRANSFER_MAGIC;
	prequest->src_device_sn = s_my_device_sn;
	prequest->cmd_len = sizeof(struct p2p_msg_device_info_t);
	prequest->cmd = P2P_TRANSFER_QUERY_DEVICE_INFO_REQUEST;

	pquery_device_info = (struct p2p_msg_device_info_t *)(prequest->cmd_data);
	pquery_device_info->device_sn = 2222;

	generate_server_addr(&server_addr);
	SAFE_SENDTO(s_sock, prequest, total_len, &server_addr);
ERR:
	SAFE_FREE(prequest);
	SAFE_FREE(presponse);
}

int main(int argc, char **argv)
{

	struct event_base *pbase = NULL;
	int sock = -1;
	struct event *pread_event = NULL;
	struct event *pping_event = NULL;
	struct timeval ping_timeout = {5, 0};
	struct event *puser_event = NULL;
	struct timeval user_timeout = {10, 0};

	struct sockaddr_in local_addr;
	socklen_t addr_len = sizeof(local_addr);

	if (-1 == configure_log(EN_PRINT_DEBUG, "/var/log/p2p_transfer_peer.log", 1))
	{
		printf("call configure_log() failed");
		goto ERR;
	}

	if (argc < 2)
	{
		printf("./p2p_transfer_peer my_device_sn\n");
		goto ERR;
	}
	s_my_device_sn = atoi(argv[1]);
	XL_DEBUG(EN_PRINT_DEBUG, "my_device_sn: %d", s_my_device_sn);
	
	memset(&local_addr, 0, addr_len);
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(P2P_TRANSFER_CLIENT_PORT);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call socket() failed, err: %s", strerror(errno));
		goto ERR;
	}
	if (-1 == bind(sock, (const struct sockaddr *)&local_addr, addr_len))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call bind() failed, err: %s", strerror(errno));
		goto ERR;
	}
	s_sock = sock;

	pbase = event_base_new();
	if (NULL == pbase)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_new() failed");
		goto ERR;
	}
	pread_event = event_new(pbase, sock, EV_READ|EV_PERSIST, read_cb, NULL);
	if (NULL == pread_event)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_new() failed");
		goto ERR;
	}
	event_add(pread_event, NULL);

	pping_event = event_new(pbase, -1, EV_TIMEOUT, ping_cb, NULL);
	if (NULL == pping_event)
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_new() failed");
		goto ERR;
	}
	event_add(pping_event, &ping_timeout);
	event_active(pping_event, EV_TIMEOUT, 0);

	if(s_my_device_sn != 2222)
	{
		puser_event = event_new(pbase, -1, EV_TIMEOUT, user_cb, NULL);
		if (NULL == puser_event)
		{
			XL_DEBUG(EN_PRINT_ERROR, "call event_new() failed");
			goto ERR;
		}
		event_add(puser_event, &user_timeout);
	}

	XL_DEBUG(EN_PRINT_NOTICE, "sock: %d, enter event_base_dispatch()...", sock);
	if (-1 == event_base_dispatch(pbase))
	{
		XL_DEBUG(EN_PRINT_ERROR, "call event_base_dispatch() failed");
		goto ERR;
	}
	XL_DEBUG(EN_PRINT_NOTICE, "exit");
	return 0;
ERR:
	return -1;
}