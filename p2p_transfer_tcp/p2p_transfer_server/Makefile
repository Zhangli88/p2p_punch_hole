all:p2p_transfer_server

p2p_transfer_server:clean
	gcc -o p2p_transfer_server -g -O0 -W -Wall -Werror p2p_transfer_server.c p2p_transfer.c log.c -levent -lm
clean : 
	-rm -f p2p_transfer_server
