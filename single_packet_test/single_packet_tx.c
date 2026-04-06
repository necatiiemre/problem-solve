/*
 * Single Packet TX - Raw socket ile periyodik VLAN paket gonderici
 *
 * VMC_1 TX ile ayni formatta paket gonderir:
 *   ETH(14) + VLAN(4) + IP(20) + UDP(8) + Payload(SEQ(8) + PRBS(1451) + DTN(1))
 *
 * Kullanim:
 *   sudo ./single_packet_tx
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>

// ==========================================
// YAPILANDIRMA MAKROLARI
// ==========================================

// Ag arayuzu
#define INTERFACE       "ens1f0np0"

// VLAN ve VL-ID
#define VLAN_ID         97
#define VLAN_PRIORITY   0
#define VL_ID           161     // DST MAC son 2 byte + DST IP son 2 byte

// Gonderim araligi (saniye)
#define TX_INTERVAL_SEC 10

// MAC adresleri
#define SRC_MAC         { 0x02, 0x00, 0x00, 0x00, 0x00, 0x40 }
// DST MAC: 03:00:00:00:XX:XX (son 2 byte = VL-ID big-endian)
#define DST_MAC_PREFIX  { 0x03, 0x00, 0x00, 0x00 }

// IP adresleri
#define SRC_IP          "10.0.0.0"
// DST IP: 224.224.X.X (son 2 byte = VL-ID big-endian, multicast)
#define DST_IP_PREFIX   0xE0E00000  // 224.224.0.0

// UDP portlari
#define UDP_SRC_PORT    100
#define UDP_DST_PORT    100

// IP
#define PKT_TTL         1

// Paket boyutlari (VMC_1 ile ayni)
#define ETH_HDR_LEN     14
#define VLAN_HDR_LEN    4
#define IP_HDR_LEN      20
#define UDP_HDR_LEN     8
#define SEQ_BYTES       8
#define PAYLOAD_SIZE    1467    // SEQ(8) + PRBS_DATA(1458) + DTN_SEQ(1)
#define PACKET_SIZE     (ETH_HDR_LEN + VLAN_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + PAYLOAD_SIZE)

// PRBS-31
#define PRBS31_POLY     0x80000001  // x^31 + x^28 + 1
#define PRBS31_SEED     0x7F3A2B01  // Port 2 icin seed (degistirilebilir)

// ==========================================
// PRBS-31 GENERATOR
// ==========================================
static uint32_t prbs31_state;

static void prbs31_init(uint32_t seed)
{
    prbs31_state = seed & 0x7FFFFFFF;
    if (prbs31_state == 0) prbs31_state = 1;
}

static uint8_t prbs31_next_byte(void)
{
    uint8_t byte = 0;
    for (int bit = 0; bit < 8; bit++) {
        int feedback = ((prbs31_state >> 30) ^ (prbs31_state >> 27)) & 1;
        prbs31_state = ((prbs31_state << 1) | feedback) & 0x7FFFFFFF;
        byte = (byte << 1) | (prbs31_state & 1);
    }
    return byte;
}

// ==========================================
// DTN SEQUENCE (VMC_1 ile ayni)
// 0, 1, 2, ..., 255, 1, 2, ..., 255, ...
// ==========================================
static inline uint8_t calc_dtn_seq(uint64_t seq)
{
    if (seq == 0) return 0;
    return (uint8_t)(((seq - 1) % 255) + 1);
}

// ==========================================
// IP CHECKSUM
// ==========================================
static uint16_t ip_checksum(const void *data, int len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++)
        sum += ntohs(p[i]);
    if (len & 1)
        sum += ((const uint8_t *)data)[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(~sum & 0xFFFF);
}

// ==========================================
// PAKET OLUSTURMA
// ==========================================
static void build_packet(uint8_t *pkt, uint64_t seq)
{
    memset(pkt, 0, PACKET_SIZE);
    uint16_t offset = 0;

    // --- Ethernet Header (14 bytes) ---
    // DST MAC: 03:00:00:00:VL_HI:VL_LO
    uint8_t dst_mac[] = DST_MAC_PREFIX;
    pkt[0] = dst_mac[0]; pkt[1] = dst_mac[1];
    pkt[2] = dst_mac[2]; pkt[3] = dst_mac[3];
    pkt[4] = (VL_ID >> 8) & 0xFF;
    pkt[5] = VL_ID & 0xFF;

    // SRC MAC
    uint8_t src_mac[] = SRC_MAC;
    memcpy(pkt + 6, src_mac, 6);

    // EtherType = 0x8100 (VLAN)
    pkt[12] = 0x81;
    pkt[13] = 0x00;
    offset = ETH_HDR_LEN;  // 14

    // --- VLAN Header (4 bytes) ---
    uint16_t tci = ((VLAN_PRIORITY & 0x7) << 13) | (VLAN_ID & 0x0FFF);
    pkt[offset + 0] = (tci >> 8) & 0xFF;
    pkt[offset + 1] = tci & 0xFF;
    // Inner EtherType = 0x0800 (IPv4)
    pkt[offset + 2] = 0x08;
    pkt[offset + 3] = 0x00;
    offset += VLAN_HDR_LEN;  // 18

    // --- IPv4 Header (20 bytes) ---
    uint8_t *ip = pkt + offset;
    ip[0] = 0x45;              // ver=4, ihl=5
    ip[1] = 0x00;              // TOS
    uint16_t ip_total = IP_HDR_LEN + UDP_HDR_LEN + PAYLOAD_SIZE;
    ip[2] = (ip_total >> 8) & 0xFF;
    ip[3] = ip_total & 0xFF;
    ip[4] = 0x00; ip[5] = 0x00;  // identification
    ip[6] = 0x00; ip[7] = 0x00;  // flags + fragment
    ip[8] = PKT_TTL;
    ip[9] = 17;                // protocol = UDP

    // SRC IP
    inet_pton(AF_INET, SRC_IP, ip + 12);

    // DST IP: 224.224.VL_HI.VL_LO
    uint32_t dst_ip = htonl(DST_IP_PREFIX | (VL_ID & 0xFFFF));
    memcpy(ip + 16, &dst_ip, 4);

    // IP checksum
    ip[10] = 0; ip[11] = 0;
    uint16_t cksum = ip_checksum(ip, IP_HDR_LEN);
    ip[10] = (cksum >> 8) & 0xFF;
    ip[11] = cksum & 0xFF;
    offset += IP_HDR_LEN;  // 38

    // --- UDP Header (8 bytes) ---
    uint8_t *udp = pkt + offset;
    uint16_t sp = htons(UDP_SRC_PORT);
    uint16_t dp = htons(UDP_DST_PORT);
    uint16_t udp_len = htons(UDP_HDR_LEN + PAYLOAD_SIZE);
    memcpy(udp + 0, &sp, 2);
    memcpy(udp + 2, &dp, 2);
    memcpy(udp + 4, &udp_len, 2);
    udp[6] = 0; udp[7] = 0;  // checksum = 0 (opsiyonel UDP)
    offset += UDP_HDR_LEN;  // 46

    // --- Payload ---
    uint8_t *payload = pkt + offset;

    // SEQ (8 bytes, little-endian)
    memcpy(payload, &seq, sizeof(seq));

    // PRBS-31 data (PAYLOAD_SIZE - SEQ_BYTES - 1 bytes)
    // Her sequence icin PRBS state'i resetle (tekrarlanabilir olsun)
    prbs31_init(PRBS31_SEED + (uint32_t)(seq & 0xFFFFFFFF));
    uint16_t prbs_len = PAYLOAD_SIZE - SEQ_BYTES - 1;  // son byte DTN
    for (uint16_t i = 0; i < prbs_len; i++)
        payload[SEQ_BYTES + i] = prbs31_next_byte();

    // DTN sequence (son byte)
    payload[PAYLOAD_SIZE - 1] = calc_dtn_seq(seq);
}

// ==========================================
// PAKET TRACE (gondermeden once ekrana bas)
// ==========================================
static void trace_packet(const uint8_t *pkt, uint16_t len, uint64_t seq)
{
    uint16_t payload_off = ETH_HDR_LEN + VLAN_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║ [TX] SEQ=%-6lu  PktLen=%u  VLAN=%u  VL-ID=%u\n", seq, len, VLAN_ID, VL_ID);
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("  DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
    printf("  SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);

    uint16_t tci = ((uint16_t)pkt[14] << 8) | pkt[15];
    printf("  VLAN:    ID=%u  Priority=%u  TCI=0x%04X\n",
           tci & 0x0FFF, (tci >> 13) & 0x7, tci);

    uint16_t ip_off = ETH_HDR_LEN + VLAN_HDR_LEN;
    uint16_t ip_total = ((uint16_t)pkt[ip_off + 2] << 8) | pkt[ip_off + 3];
    printf("  IP:      total_len=%u  ttl=%u  proto=%u\n",
           ip_total, pkt[ip_off + 8], pkt[ip_off + 9]);
    printf("  SRC IP:  %u.%u.%u.%u\n",
           pkt[ip_off + 12], pkt[ip_off + 13], pkt[ip_off + 14], pkt[ip_off + 15]);
    printf("  DST IP:  %u.%u.%u.%u\n",
           pkt[ip_off + 16], pkt[ip_off + 17], pkt[ip_off + 18], pkt[ip_off + 19]);

    uint16_t udp_off = ip_off + IP_HDR_LEN;
    uint16_t usrc = ((uint16_t)pkt[udp_off] << 8) | pkt[udp_off + 1];
    uint16_t udst = ((uint16_t)pkt[udp_off + 2] << 8) | pkt[udp_off + 3];
    uint16_t ulen = ((uint16_t)pkt[udp_off + 4] << 8) | pkt[udp_off + 5];
    printf("  UDP:     src=%u  dst=%u  len=%u\n", usrc, udst, ulen);

    printf("  Payload: SEQ=%" PRIu64 "  DTN_SEQ=%u\n",
           seq, pkt[payload_off + PAYLOAD_SIZE - 1]);

    // Ilk 32 byte payload
    printf("  Payload[32B]: ");
    for (int i = 0; i < 32 && i < PAYLOAD_SIZE; i++)
        printf("%02x ", pkt[payload_off + i]);
    printf("\n");

    printf("╚══════════════════════════════════════════════════╝\n\n");
}

// ==========================================
// MAIN
// ==========================================
int main(void)
{
    printf("=== Single Packet TX ===\n");
    printf("Interface: %s\n", INTERFACE);
    printf("VLAN: %u, VL-ID: %u\n", VLAN_ID, VL_ID);
    printf("Interval: %u sec\n", TX_INTERVAL_SEC);
    printf("Packet size: %u bytes\n", PACKET_SIZE);
    printf("========================\n\n");

    // Raw socket olustur (ETH_P_ALL ile tum protokoller)
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Interface index bul
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    // Hedef adres (sockaddr_ll)
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = 6;

    uint8_t dst_mac_prefix[] = DST_MAC_PREFIX;
    memcpy(saddr.sll_addr, dst_mac_prefix, 4);
    saddr.sll_addr[4] = (VL_ID >> 8) & 0xFF;
    saddr.sll_addr[5] = VL_ID & 0xFF;

    uint8_t pkt[PACKET_SIZE];
    uint64_t seq = 0;

    printf("Gonderim basliyor... (Ctrl+C ile durdur)\n\n");

    while (1) {
        build_packet(pkt, seq);
        trace_packet(pkt, PACKET_SIZE, seq);

        ssize_t sent = sendto(sock, pkt, PACKET_SIZE, 0,
                              (struct sockaddr *)&saddr, sizeof(saddr));
        if (sent < 0) {
            perror("sendto");
        } else {
            printf("  -> %zd bytes gonderildi\n\n", sent);
        }

        seq++;
        sleep(TX_INTERVAL_SEC);
    }

    close(sock);
    return 0;
}
