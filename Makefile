CC=gcc
CFLAGS=-fPIC -fno-stack-protector -lcurl -c

all: compile

compile:
	$(CC) $(CFLAGS) junglecloud-pam.c

install:
	ld -lcurl -x --shared -o /lib/security/junglecloud-pam.so junglecloud-pam.o

clean:
	rm -rf *.o *.so