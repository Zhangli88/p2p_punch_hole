#include "p2p_transfer.h"
#include "log.h"
#include <string.h>
#include <errno.h>
#include <assert.h>

const char *get_string_network_type(int network_type)
{
	static char *s_network_type[] = {
		"UNKNOWN",
		"PUBLIC_NETWORK",
		"FULL_CONE_NAT",
		"RESTRICTED_CONE_NAT",
		"PORT_RESTRICTED_CONE_NAT",
		"SYMMETRIC_NAT",
	};
	if (network_type < NP_UNKNOWN || network_type > NP_SYMMETRIC_NAT)
	{
		network_type = NP_UNKNOWN;
	}
	return s_network_type[network_type];
}

int set_sock_opt(int sock, int flag)
{
	int enable = 1;

	if (flag & SO_REUSEADDR)
	{
		if (-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call setsockopt() failed, set SO_REUSEPORT failed, err: %s", strerror(errno));
			return -1;
		}
		else
		{
			XL_DEBUG(EN_PRINT_ERROR, "set SO_REUSEPORT success");
		}
	}
#ifndef NO_SUPPORT_REUSEPORT
	if (flag & SO_REUSEPORT)
	{
		if (-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call setsockopt() failed, set SO_REUSEPORT failed, err: %s", strerror(errno));
			return -1;
		}
	}
#endif
	if (flag & SO_KEEPALIVE)
	{
		if (-1 == setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call setsockopt() failed, set SO_KEEPALIVE failed, err: %s", strerror(errno));
			return -1;
		}
	}
	return 0;
}

void generate_server_addr(struct sockaddr_in *paddr)
{
	assert(paddr != NULL);

	memset(paddr, 0, sizeof(*paddr));
	paddr->sin_family = AF_INET;
	paddr->sin_addr.s_addr = inet_addr(P2P_TRANSFER_SERVER_IP);
	paddr->sin_port = htons(P2P_TRANSFER_SERVER_PORT);
}

void generate_peer_addr(struct sockaddr_in *paddr, const struct p2p_msg_device_info_t *pdevice_info)
{
	assert(paddr != NULL);
	assert(pdevice_info != NULL);

	memset(paddr, 0, sizeof(*paddr));
	paddr->sin_family = AF_INET;
	paddr->sin_addr = pdevice_info->ip_addr;
	paddr->sin_port = pdevice_info->port;
	XL_DEBUG(EN_PRINT_DEBUG, "ip: %s, port: %d", inet_ntoa(paddr->sin_addr), ntohs(paddr->sin_port));
}

const char *get_string_cmd(int cmd)
{
	static char *s_cmd[] = {
		"P2P_TRANSFER_UNKNOWN_CMD",
		"P2P_TRANSFER_PING",
		"P2P_TRANSFER_QUERY_DEVICE_INFO_REQUEST",
		"P2P_TRANSFER_QUERY_DEVICE_INFO_RESPONSE",
		"P2P_TRANSFER_PUNCH_HOLE",
		"P2P_TRANSFER_PUNCH_HOLE_TO_PEER",
		"P2P_TRANSFER_USER_DATA",
	};
	if (cmd < P2P_TRANSFER_UNKNOWN_CMD || cmd > P2P_TRANSFER_USER_DATA)
	{
		cmd = P2P_TRANSFER_UNKNOWN_CMD;
	}
	return s_cmd[cmd];
}