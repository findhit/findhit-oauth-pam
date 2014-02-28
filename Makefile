CCO=junglecloud-pam.o

CC=gcc
CFLAGS=-fPIC -fno-stack-protector -o $(CCO) -lcurl -c 

PAMDIR=/lib/security
PAM=pam_junglecloud.so
PAMPATH=$(PAMDIR)/$(PAM)

all: requisites compile install

requisites:
	apt-get -y -q install build-essential libpam0g-dev libcurl4-openssl-dev

compile:
	$(CC) $(CFLAGS) junglecloud-pam.c

install:
	ld -lcurl -x --shared -o $(PAMPATH) $(CCO)

clean:
	rm -rf *.o *.so
