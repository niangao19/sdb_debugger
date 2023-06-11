CC = gcc
CXX = g++
CFLAGS	= -Wall -g
LDFLAGS = -lcapstone

PROGS = sdb

all: $(PROGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDFLAGS)

.PHONY: clean all

clean:
	rm -f -r $(PROGS) *.dSYM
