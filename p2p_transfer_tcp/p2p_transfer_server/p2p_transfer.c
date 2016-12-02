#include "p2p_transfer.h"
#include "log.h"
#include <string.h>
#include <errno.h>

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
	if (flag & SO_REUSEPORT)
	{
		if (-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)))
		{
			XL_DEBUG(EN_PRINT_ERROR, "call setsockopt() failed, set SO_REUSEPORT failed, err: %s", strerror(errno));
			return -1;
		}
	}
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