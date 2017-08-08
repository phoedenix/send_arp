

send_arp: main.c
	gcc -lpcap -o send_arp main.c

pcap.o : main.c
	gcc -lpcap -o send_arp main.o 

clear:
	rm *.o pcap
