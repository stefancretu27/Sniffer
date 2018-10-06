CC := g++
CFLAGS := -std=c++11 -g -Wall
LIBS := -lpcap -ljsoncpp

all:
	$(CC) $(CFLAGS) sniffer.cpp -o sniffer.o $(LIBS)
	
clean:
	rm *.o
