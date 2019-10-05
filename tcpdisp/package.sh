
rm -f out/*
cp tcp_server/tcp_server out/
cp tcp_client/tcp_client out/
cp tcp_client/client.config out/
cp tcp_server/server.config out/

tar -cvf tcpdisp.tar out/* tcp_* common/* Makefile

chmod 777 tcpdisp.tar
