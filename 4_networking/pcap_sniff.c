#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "hacking.h"

void pcap_fatal(const char *failed_in, const char *errbuf) {
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}

int main() {
	struct pcap_pkthdr header;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_if_t *interfaces;
	pcap_t *pcap_handle;
	int i;

	if (pcap_findalldevs(&interfaces, errbuf) == -1)
		pcap_fatal("pcap_findalldevs", errbuf);

	// device = interfaces->name;

	device = "lo";

	printf("Sniffing on device %s\n", device);

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if (pcap_handle == NULL)
		pcap_fatal("pcap_open_live", errbuf);

	for (i = 0; i < 3; i++) {
		packet = pcap_next(pcap_handle, &header);
		printf("Got a %d byte packet\n", header.len);
		dump(packet, header.len);
	}
	pcap_close(pcap_handle);
}
