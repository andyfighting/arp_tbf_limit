CFLAGS 	= -Wall -g 
DLFLAGS=-fPIC -shared

LIBCFUTIL = libcfutil

OBJS = main.o
TARGET=arp_defense_client

exec:$(TARGET) 

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) -o $@  $(OBJS) $(LDFLAGS)

lib:

%.o:%.c
	$(CC) $(CFLAGS) -c $< $(INCLUDE)

install:
	mkdir -p /usr/bin
	${CP} $(TARGET) /usr/bin
clean:
	rm -rf core* *.o *.a
	rm -rf $(TARGET)
	rm -rf /usr/bin/$(TARGET)
