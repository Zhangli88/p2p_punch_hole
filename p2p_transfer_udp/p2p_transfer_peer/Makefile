all:p2p_transfer_udp_peer

p2p_transfer_udp_peer:clean
	gcc -o p2p_transfer_udp_peer -g3 -gdwarf-2 -g -O0 -W -Wall -Werror p2p_transfer_peer.c p2p_transfer.c log.c -levent -lm -lpthread
clean : 
	-rm -f p2p_transfer_udp_peer
