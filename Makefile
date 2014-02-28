CC=gcc
CFLAGS=-fPIC -fno-stack-protector -lcurl -c

all: requisites compile install

requisites:
	apt-get -y -q install build-essential libpam0g-dev libcurl4-openssl-dev

compile:
	$(CC) $(CFLAGS) junglecloud-pam.c

install:
	ld -lcurl -x --shared -o /lib/security/junglecloud-pam.so junglecloud-pam.o

clean:
	rm -rf *.o *.so