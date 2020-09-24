OBJC=mysql_protocol.o Hash.o
cc=gcc
mysql:$(OBJC)
	$(cc) -o $@ $^ -lpcap -g -Wall
mysql_protocol.o:mysql_protocol.c mysql_protocol.h Hash.h
	$(cc) -c $< -g -Wall
Hash.o:Hash.c Hash.h
	$(cc) -c $< -g -Wall
clean:
	rm -rf *.o
