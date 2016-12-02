all:p2p_transfer_peer

p2p_transfer_peer:clean
	gcc -o p2p_transfer_peer -g -O0 -W -Wall -Werror p2p_transfer_peer.c p2p_transfer.c log.c -levent -lm -lpthread
clean : 
	-rm -f p2p_transfer_peer
