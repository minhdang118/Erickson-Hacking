#include <libnet.h>
#include <pcap.h>
#include "hacking.h"

#define MAX_EXISTING_PORTS 30

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *, u_short *);

int main(int argc, char *argv[])
{
    struct pcap_pkthdr cap_header;
    const u_char *packet, *pkt_data;
    pcap_if_t *alldevs;
    pcap_t *pcap_handle;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    char *device;
    u_long target_ip;
    libnet_t *l;
    int i;
    u_short existing_ports[MAX_EXISTING_PORTS];


    if((argc < 2) || (argc > MAX_EXISTING_PORTS+2)) {
        if(argc > 2)
            printf("Limited to tracking %d existing ports.\n", MAX_EXISTING_PORTS);
        else
            printf("Usage: %s <IP to shroud> [existing ports...]\n", argv[0]);
        exit(0);
    }

    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_RAW4,                            /* injection type */
            NULL,                                   /* network interface */
            libnet_errbuf);                         /* error buffer */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", libnet_errbuf);
        exit(EXIT_FAILURE); 
    }

    target_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);

    if (target_ip == -1)
    {
        fatal("Invalid target address");
    }

    for(i=2; i < argc; i++)
        existing_ports[i-2] = (u_short) atoi(argv[i]); 

    existing_ports[argc-2] = 0;

    if ((pcap_findalldevs(&alldevs, pcap_errbuf)) == -1)
    {
        fatal(pcap_errbuf);
    }

    device = alldevs->name;
    if (device == NULL)
    {
        fatal(pcap_errbuf);
    }

    pcap_handle = pcap_open_live(device, 128, 1, 0, pcap_errbuf);
    if (pcap_handle == NULL)
    {
        fatal(pcap_errbuf);
    }

    libnet_seed_prand(l);

    set_packet_filter(pcap_handle, (struct in_addr *) &target_ip, existing_ports);

    printf("Resetting all TCP connections to %s on %s\n", argv[1], device);
    pcap_loop(pcap_handle, -1, caught_packet, (u_char *) &l);

    pcap_close(pcap_handle);
    libnet_destroy(l);

    return 0;
}
