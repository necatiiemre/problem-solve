#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include "config.h"  // IMIX configuration

/*
 *  Paket yapısı:
 *  ┌──────────────────────────────────────────┐
 *  │ Ethernet Header (14 B)                  │
 *  │ VLAN Header (4 B, opsiyonel)            │
 *  │ IPv4 Header (20 B)                      │
 *  │ UDP Header (8 B)                        │
 *  │ Payload (Seq + PRBS Data)               │
 *  └──────────────────────────────────────────┘
 *
 *  DST MAC ve DST IP son 2 byte = VL-ID
 *  VLAN ID = IEEE 802.1Q tag (802.1Q TCI içinde taşınır)
 */

#ifdef USE_VLAN
# define VLAN_ENABLED 1
#else
# define VLAN_ENABLED 0
#endif

// ==========================================
// PRBS-31 CONFIGURATION
// ==========================================
#define PRBS31_PERIOD     0x7FFFFFFF
#define PRBS_CACHE_SIZE   ((PRBS31_PERIOD / 8) + 1)  // ~268 MB
#define PRBS_CACHE_MASK   (PRBS_CACHE_SIZE - 1)
#define SEQ_BYTES         8

// ==========================================
// LATENCY TEST PAYLOAD FORMAT
// ==========================================
// Normal mod:
//   [Sequence 8B][PRBS Data 1459B]
//
// Latency test modu:
//   [Sequence 8B][TX Timestamp 8B][PRBS Data 1451B]
//
// TX Timestamp = rte_rdtsc() (CPU cycle counter)

#define TX_TIMESTAMP_BYTES      8
#define LATENCY_PAYLOAD_OFFSET  (SEQ_BYTES + TX_TIMESTAMP_BYTES)  // 16 bytes header

// Latency test modunda PRBS boyutu (1518 - 18 - 20 - 8 - 16 = 1456)
#if VLAN_ENABLED
#define LATENCY_PRBS_BYTES  (LATENCY_TEST_PACKET_SIZE - ETH_HDR_SIZE - VLAN_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE - SEQ_BYTES - TX_TIMESTAMP_BYTES)
#else
#define LATENCY_PRBS_BYTES  (LATENCY_TEST_PACKET_SIZE - ETH_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE - SEQ_BYTES - TX_TIMESTAMP_BYTES)
#endif

// ==========================================
// PAYLOAD & PACKET SIZES
// ==========================================
#define PAYLOAD_SIZE_NO_VLAN 1471  // 8 seq + 1463 prbs
#define PAYLOAD_SIZE_VLAN    1467  // 8 seq + 1460 prbs (1518 - 14 - 4 - 20 - 8 - 5 = 1467)
#define VLAN_TAG_SIZE        4

#define ETH_HDR_SIZE  14
#define VLAN_HDR_SIZE 4
#define IP_HDR_SIZE   20
#define UDP_HDR_SIZE  8

#define PACKET_SIZE_NO_VLAN (ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + PAYLOAD_SIZE_NO_VLAN)
#define PACKET_SIZE_VLAN    (ETH_HDR_SIZE + VLAN_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + PAYLOAD_SIZE_VLAN)

#if VLAN_ENABLED
# define PACKET_SIZE   PACKET_SIZE_VLAN
# define PAYLOAD_SIZE  PAYLOAD_SIZE_VLAN
# define NUM_PRBS_BYTES (PAYLOAD_SIZE_VLAN - SEQ_BYTES)
# define L2_HEADER_SIZE (ETH_HDR_SIZE + VLAN_HDR_SIZE)
#else
# define PACKET_SIZE   PACKET_SIZE_NO_VLAN
# define PAYLOAD_SIZE  PAYLOAD_SIZE_NO_VLAN
# define NUM_PRBS_BYTES (PAYLOAD_SIZE_NO_VLAN - SEQ_BYTES)
# define L2_HEADER_SIZE ETH_HDR_SIZE
#endif

// ==========================================
// IMIX SUPPORT - DYNAMIC PACKET SIZES
// ==========================================
// IMIX modunda paket boyutları değişken olur.
// MAX_PRBS_BYTES: PRBS offset hesabı için sabit (en büyük PRBS boyutu)
// Bu değer tüm boyutlar için aynı formülle kullanılır:
//   offset = (sequence × MAX_PRBS_BYTES) % PRBS_CACHE_SIZE
// Böylece RX tarafı sequence'dan offset'i hesaplayabilir.

#define MAX_PRBS_BYTES NUM_PRBS_BYTES  // 1459 (VLAN) veya 1463 (non-VLAN)

// IMIX için minimum payload boyutu
// 100 byte paket: 100 - L2(18) - IP(20) - UDP(8) = 54 byte payload
// Payload = SEQ(8) + PRBS(46) minimum
#define MIN_IMIX_PAYLOAD_VLAN    (100 - ETH_HDR_SIZE - VLAN_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE)
#define MIN_IMIX_PAYLOAD_NO_VLAN (100 - ETH_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE)
#define MIN_IMIX_PRBS_BYTES      (MIN_IMIX_PAYLOAD_VLAN - SEQ_BYTES)  // 46 bytes

// Paket boyutundan PRBS boyutunu hesapla
#if VLAN_ENABLED
# define CALC_PRBS_LEN(pkt_size) ((pkt_size) - ETH_HDR_SIZE - VLAN_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE - SEQ_BYTES)
# define CALC_PAYLOAD_LEN(pkt_size) ((pkt_size) - ETH_HDR_SIZE - VLAN_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE)
#else
# define CALC_PRBS_LEN(pkt_size) ((pkt_size) - ETH_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE - SEQ_BYTES)
# define CALC_PAYLOAD_LEN(pkt_size) ((pkt_size) - ETH_HDR_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE)
#endif

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_VLAN 0x8100
#define MAX_PRBS_CACHE_PORTS 12

struct ports_config; 

// ==========================================
// VLAN HEADER
// ==========================================
struct vlan_hdr {
    uint16_t tci;        // Priority (3b) + CFI (1b) + VLAN ID (12b)
    uint16_t eth_proto;  // Next protocol (e.g. 0x0800 for IPv4)
} __rte_packed;

// ==========================================
// PACKET TEMPLATE (in-memory layout)
// ==========================================
#if VLAN_ENABLED
struct packet_template {
    struct rte_ether_hdr eth;
    struct vlan_hdr vlan;
    struct rte_ipv4_hdr ip;
    struct rte_udp_hdr udp;
    uint8_t payload[PAYLOAD_SIZE_VLAN];
} __rte_packed __rte_aligned(2);
#else
struct packet_template {
    struct rte_ether_hdr eth;
    struct rte_ipv4_hdr ip;
    struct rte_udp_hdr udp;
    uint8_t payload[PAYLOAD_SIZE_NO_VLAN];
} __rte_packed __rte_aligned(2);
#endif

// ==========================================
// PACKET CONFIGURATION STRUCT
// ==========================================
//
// VLAN ID   → 802.1Q header tag
// VL ID     → paket içinde MAC/IP eşlemesi için kullanılır
//
struct packet_config {
#if VLAN_ENABLED
    uint16_t vlan_id;          // VLAN header tag (802.1Q)
    uint8_t  vlan_priority;
#endif
    uint16_t vl_id;            // VL ID (MAC/IP için)
    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  ttl;
    uint8_t  tos;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t *payload_data;
    uint16_t payload_size;
};

// ==========================================
// PRBS-31 CACHE STRUCTURE (per-port)
// ==========================================
struct prbs_cache {
    uint8_t  *cache;         // Main PRBS cache
    uint8_t  *cache_ext;     // Extended cache (wraparound)
    uint32_t  initial_state; // Initial PRBS-31 state
    bool      initialized;
    int       socket_id;
};

// global PRBS cache
extern struct prbs_cache port_prbs_cache[MAX_PRBS_CACHE_PORTS];

// ==========================================
// FUNCTION PROTOTYPES
// ==========================================

// PRBS utilities
void init_prbs_cache_for_all_ports(uint16_t nb_ports, const struct ports_config *ports);
void cleanup_prbs_cache(void);
uint8_t* get_prbs_cache_for_port(uint16_t port_id);
uint8_t* get_prbs_cache_ext_for_port(uint16_t port_id);

// Packet building utilities
void init_packet_config(struct packet_config *config);
int  build_packet(struct packet_template *template, const struct packet_config *config);
int  build_packet_mbuf(struct rte_mbuf *mbuf, const struct packet_config *config);
uint16_t calculate_ip_checksum(struct rte_ipv4_hdr *ip);
uint16_t calculate_udp_checksum(const struct rte_ipv4_hdr *ip, const struct rte_udp_hdr *udp,
                                const uint8_t *payload, uint16_t payload_len);
int  set_mac_from_string(struct rte_ether_addr *mac, const char *mac_str);
int  set_ip_from_string(uint32_t *ip, const char *ip_str);
void print_packet_info(const struct packet_config *config);

// Fill PRBS payload for TX (dinamik boyut destekli)
// prbs_len: Yazılacak PRBS byte sayısı (IMIX için değişken)
void fill_payload_with_prbs31_dynamic(struct rte_mbuf *mbuf, uint16_t port_id,
                                       uint64_t sequence_number, uint16_t l2_len,
                                       uint16_t prbs_len);

// Legacy wrapper (sabit boyut için geriye uyumluluk)
static inline void fill_payload_with_prbs31(struct rte_mbuf *mbuf, uint16_t port_id,
                                             uint64_t sequence_number, uint16_t l2_len)
{
    fill_payload_with_prbs31_dynamic(mbuf, port_id, sequence_number, l2_len, NUM_PRBS_BYTES);
}

// ==========================================
// DTN PACKET SEQUENCE NUMBER
// ==========================================
// Payload'ın son byte'ı artık PRBS değil, DTN paket sequence number'dır.
// Her VL-IDX için bağımsız: 0'dan başlar, 255'e kadar artar,
// sonra 1'e döner ve 1-255 arasında döngü yapar.
// Döngü: 0, 1, 2, ..., 255, 1, 2, ..., 255, 1, 2, ...

static inline uint8_t calc_dtn_seq(uint64_t seq)
{
    if (seq == 0) return 0;
    return (uint8_t)(((seq - 1) % 255) + 1);
}

// ==========================================
// IMIX HELPER FUNCTIONS
// ==========================================

// IMIX pattern'den paket boyutu al (worker'ın offset + counter'ına göre)
static inline uint16_t get_imix_packet_size(uint64_t pkt_counter, uint8_t worker_offset)
{
    static const uint16_t imix_pattern[IMIX_PATTERN_SIZE] = IMIX_PATTERN_INIT;
    return imix_pattern[(pkt_counter + worker_offset) % IMIX_PATTERN_SIZE];
}

// Paket boyutundan payload boyutunu hesapla
static inline uint16_t calc_payload_size(uint16_t pkt_size)
{
    return CALC_PAYLOAD_LEN(pkt_size);
}

// Paket boyutundan PRBS boyutunu hesapla
static inline uint16_t calc_prbs_size(uint16_t pkt_size)
{
    return CALC_PRBS_LEN(pkt_size);
}

// Dinamik boyutlu paket oluştur
int build_packet_dynamic(struct rte_mbuf *mbuf, const struct packet_config *config,
                          uint16_t packet_size);

// ==========================================
// PACKET TRACE UTILITY
// ==========================================
#if PACKET_TRACE_ENABLED

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

static uint64_t _trace_count = 0;

// ---- Trace-local splitmix64 & CRC32C (header-only, matches tx_rx_manager.c) ----
#define TRACE_SPLITMIX_XOR_BYTES   64
#define TRACE_SPLITMIX_CRC_BYTES   4
#define TRACE_SPLITMIX_TOTAL_OVERHEAD (TRACE_SPLITMIX_XOR_BYTES + TRACE_SPLITMIX_CRC_BYTES)

static inline uint64_t trace_splitmix64(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

static const uint32_t trace_crc32c_table[256] = {
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A, 0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x5228EE48, 0x86E28AA3, 0x748909A0, 0x67D9FA54, 0x95B27957,
    0xCBA14573, 0x39CAC670, 0x2A9A3584, 0xD8F1B687, 0x0C3BD26C, 0xFE50516F, 0xED00A29B, 0x1F6B2198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9, 0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x56385F93,
    0x082B63B7, 0xFA40E0B4, 0xE9101340, 0x1B7B9043, 0xCFB1F4A8, 0x3DDA77AB, 0x2E8A845F, 0xDCE1075C,
    0x92A6FC17, 0x60CD7F14, 0x739D8CE0, 0x81F60FE3, 0x553C6B08, 0xA757E80B, 0xB4071BFF, 0x461C98FC,
    0x180FA4D8, 0xEA6427DB, 0xF934D42F, 0x0B5F572C, 0xDF9533C7, 0x2DFEB0C4, 0x3EAE4330, 0xCCC5C033,
    0xA23551A6, 0x505ED2A5, 0x430E2151, 0xB165A252, 0x65AFC6B9, 0x97C445BA, 0x8494B64E, 0x76FF354D,
    0x28EC0969, 0xDAD78A6A, 0xC987799E, 0x3BECFA9D, 0xEF269E76, 0x1D4D1D75, 0x0E1DEE81, 0xFC766D82,
    0xB23B96C9, 0x405015CA, 0x5300E63E, 0xA16B653D, 0x75A101D6, 0x87CA82D5, 0x949A7121, 0x66F1F222,
    0x38E2CE06, 0xCA894D05, 0xD9D9BEF1, 0x2BB23DF2, 0xFF785919, 0x0D13DA1A, 0x1E4329EE, 0xEC28AAED,
    0xC5A92679, 0x37C2A57A, 0x2492568E, 0xD6F9D58D, 0x0233B166, 0xF0583265, 0xE308C191, 0x11634292,
    0x4F707EB6, 0xBD1BFDB5, 0xAE4B0E41, 0x5C208D42, 0x88EAE9A9, 0x7A816AAA, 0x69D1995E, 0x9BBA1A5D,
    0xD5F7E116, 0x279C6215, 0x34CC91E1, 0xC6A712E2, 0x126D7609, 0xE006F50A, 0xF35606FE, 0x013D85FD,
    0x5F2EB9D9, 0xAD453ADA, 0xBE15C92E, 0x4C7E4A2D, 0x985E2EC6, 0x6A35ADC5, 0x79655E31, 0x8B0EDD32,
    0xE5FEA876, 0x17952B75, 0x04C5D881, 0xF6AE5B82, 0x22643F69, 0xD00FBC6A, 0xC35F4F9E, 0x3134CC9D,
    0x6F27F0B9, 0x9D4C73BA, 0x8E1C804E, 0x7C77034D, 0xA8BD67A6, 0x5AD6E4A5, 0x49861751, 0xBBED9452,
    0xF5A06F19, 0x07CBEC1A, 0x149B1FEE, 0xE6F09CED, 0x323AF806, 0xC0517B05, 0xD30188F1, 0x216A0BF2,
    0x7F7937D6, 0x8D12B4D5, 0x9E424721, 0x6C29C422, 0xB8E3A0C9, 0x4A8823CA, 0x59D8D03E, 0xABB3533D
};

static inline uint32_t trace_sw_crc32c(const void *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *p = (const uint8_t *)data;
    for (uint32_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ trace_crc32c_table[(crc ^ p[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

// Verify splitmix64 XOR: decode XOR'd bytes and compare with original PRBS
static inline bool trace_verify_splitmix64(const uint8_t *payload_base,
                                            uint64_t seq, uint16_t port_id)
{
    if (port_id >= MAX_PRBS_CACHE_PORTS || !port_prbs_cache[port_id].cache_ext)
        return false;

    const uint8_t *xored = payload_base + SEQ_BYTES;  // [8..71]
    uint64_t prbs_off = (seq * (uint64_t)MAX_PRBS_BYTES) % (uint64_t)PRBS_CACHE_SIZE;
    const uint8_t *orig_prbs = port_prbs_cache[port_id].cache_ext + prbs_off;

    // Decode: XOR gelen veriyi splitmix64 stream ile cikar, orijinal PRBS ile karsilastir
    for (int i = 0; i < TRACE_SPLITMIX_XOR_BYTES; i += 8) {
        uint64_t sm = trace_splitmix64(seq + (uint64_t)(i / 8));
        uint64_t xored_val, orig_val;
        memcpy(&xored_val, xored + i, sizeof(uint64_t));
        memcpy(&orig_val, orig_prbs + i, sizeof(uint64_t));
        uint64_t decoded = xored_val ^ sm;
        if (decoded != orig_val)
            return false;
    }
    return true;
}

// Verify PRBS on payload after splitmix+CRC overhead
static inline bool trace_verify_prbs(const uint8_t *payload_base,
                                      uint64_t seq, uint16_t port_id,
                                      uint16_t total_prbs_len)
{
    if (port_id >= MAX_PRBS_CACHE_PORTS || !port_prbs_cache[port_id].cache_ext)
        return false;

    uint64_t off = (seq * (uint64_t)MAX_PRBS_BYTES) % (uint64_t)PRBS_CACHE_SIZE;
    const uint8_t *recv = payload_base + SEQ_BYTES + TRACE_SPLITMIX_TOTAL_OVERHEAD;
    const uint8_t *exp = port_prbs_cache[port_id].cache_ext + off + TRACE_SPLITMIX_TOTAL_OVERHEAD;

    uint16_t check_len = (total_prbs_len > TRACE_SPLITMIX_TOTAL_OVERHEAD + 1)
        ? total_prbs_len - TRACE_SPLITMIX_TOTAL_OVERHEAD - 1 : 0;

    return (check_len == 0) || (memcmp(recv, exp, check_len) == 0);
}

// Helper: hex dump with offset labels, 16 bytes per line
static inline void trace_hexdump(const char *label, const uint8_t *data,
                                  uint16_t len, uint16_t max_bytes)
{
    uint16_t dump_len = (len < max_bytes) ? len : max_bytes;
    printf("  %s (%u bytes, showing %u):\n", label, len, dump_len);
    for (uint16_t i = 0; i < dump_len; i += 16) {
        printf("    [%04u] ", i);
        for (uint16_t j = i; j < i + 16 && j < dump_len; j++)
            printf("%02x ", data[j]);
        printf("\n");
    }
    if (dump_len < len)
        printf("    ... (%u bytes truncated)\n", len - dump_len);
}

// Helper: side-by-side comparison of received vs expected, show first N mismatches
static inline void trace_compare(const char *label, const uint8_t *recv,
                                  const uint8_t *exp, uint16_t len,
                                  uint16_t max_mismatches)
{
    uint16_t mismatch_count = 0;
    int first_mismatch = -1;
    for (uint16_t i = 0; i < len; i++) {
        if (recv[i] != exp[i]) {
            if (first_mismatch < 0) first_mismatch = i;
            mismatch_count++;
        }
    }
    printf("  %s: %u/%u bytes match", label, len - mismatch_count, len);
    if (mismatch_count == 0) {
        printf(" -> ALL OK\n");
        return;
    }
    printf(" -> %u MISMATCHES (first at offset %d)\n", mismatch_count, first_mismatch);

    // Show mismatches around first_mismatch
    uint16_t shown = 0;
    for (uint16_t i = 0; i < len && shown < max_mismatches; i++) {
        if (recv[i] != exp[i]) {
            printf("    [%04u] recv=0x%02x  exp=0x%02x  XOR=0x%02x\n",
                   i, recv[i], exp[i], recv[i] ^ exp[i]);
            shown++;
        }
    }
    if (mismatch_count > max_mismatches)
        printf("    ... (%u more mismatches)\n", mismatch_count - max_mismatches);
}

static inline void trace_print_packet(const char *stage, const uint8_t *pkt,
                                       uint16_t pkt_len, uint16_t port_id)
{
    uint16_t ether_type = ((uint16_t)pkt[12] << 8) | pkt[13];
    int has_vlan = (ether_type == 0x8100);

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ [TRACE][%s] Port=%u  PktLen=%u  EtherType=0x%04X (%s)\n",
           stage, port_id, pkt_len, ether_type, has_vlan ? "VLAN" : "IPv4");
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    // --- L2 Header ---
    printf("║ L2 HEADER:\n");
    printf("  DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
    printf("  SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);
    uint16_t vl_idx = ((uint16_t)pkt[4] << 8) | pkt[5];
    printf("  VL-IDX:  %u (0x%04X) [from DST MAC bytes 4-5]\n", vl_idx, vl_idx);

    // Compute offsets based on VLAN presence
    uint16_t l3_off, payload_off;
    if (has_vlan) {
        uint16_t tci = ((uint16_t)pkt[14] << 8) | pkt[15];
        uint16_t vlan_id = tci & 0x0FFF;
        uint16_t vlan_prio = (tci >> 13) & 0x7;
        uint16_t inner_type = ((uint16_t)pkt[16] << 8) | pkt[17];
        printf("  VLAN:    ID=%u  Priority=%u  TCI=0x%04X  InnerType=0x%04X\n",
               vlan_id, vlan_prio, tci, inner_type);
        l3_off = 18;  // ETH(14) + VLAN(4)
    } else {
        l3_off = 14;  // ETH(14)
    }
    payload_off = l3_off + 20 + 8;  // +IP(20) +UDP(8)

    // --- L3/L4 Header ---
    printf("║ L3/L4 HEADER (offset %u):\n", l3_off);
    // IP
    uint8_t ip_ver_ihl = pkt[l3_off];
    uint16_t ip_total_len = ((uint16_t)pkt[l3_off + 2] << 8) | pkt[l3_off + 3];
    uint8_t ip_ttl = pkt[l3_off + 8];
    uint8_t ip_proto = pkt[l3_off + 9];
    printf("  IP:  ver=%u ihl=%u total_len=%u ttl=%u proto=%u\n",
           ip_ver_ihl >> 4, ip_ver_ihl & 0xF, ip_total_len, ip_ttl, ip_proto);
    printf("  SRC IP:  %u.%u.%u.%u\n",
           pkt[l3_off + 12], pkt[l3_off + 13], pkt[l3_off + 14], pkt[l3_off + 15]);
    printf("  DST IP:  %u.%u.%u.%u\n",
           pkt[l3_off + 16], pkt[l3_off + 17], pkt[l3_off + 18], pkt[l3_off + 19]);
    // UDP
    uint16_t udp_off = l3_off + 20;
    uint16_t udp_src = ((uint16_t)pkt[udp_off] << 8) | pkt[udp_off + 1];
    uint16_t udp_dst = ((uint16_t)pkt[udp_off + 2] << 8) | pkt[udp_off + 3];
    uint16_t udp_len = ((uint16_t)pkt[udp_off + 4] << 8) | pkt[udp_off + 5];
    printf("  UDP: src=%u dst=%u len=%u\n", udp_src, udp_dst, udp_len);

    // --- Boyut analizi ---
    uint16_t ip_total_len_val = ((uint16_t)pkt[l3_off + 2] << 8) | pkt[l3_off + 3];
    uint16_t payload_from_ip = (ip_total_len_val > 28) ? (ip_total_len_val - 28) : 0;
    uint16_t payload_from_pktlen = pkt_len - payload_off;
    uint16_t nic_padding = (payload_from_pktlen > payload_from_ip) ?
                            (payload_from_pktlen - payload_from_ip) : 0;
    // VMC_1 TX beklenen boyutlar
    uint16_t tx_expected_pktlen = has_vlan ? PACKET_SIZE_VLAN : PACKET_SIZE_NO_VLAN;
    uint16_t tx_expected_payload = has_vlan ? PAYLOAD_SIZE_VLAN : PAYLOAD_SIZE_NO_VLAN;
    uint16_t tx_expected_iptotal = tx_expected_payload + 20 + 8;
    uint16_t device_added = (ip_total_len_val > tx_expected_iptotal) ?
                             (ip_total_len_val - tx_expected_iptotal) : 0;
    uint16_t total_extra = payload_from_pktlen - tx_expected_payload;

    // --- Payload ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ PAYLOAD BOYUT ANALIZI:\n");
    printf("  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │ VMC_1 TX beklenen:                                     │\n");
    printf("  │   pkt_len      = %u bytes                             │\n", tx_expected_pktlen);
    printf("  │   ip_total_len = %u                                  │\n", tx_expected_iptotal);
    printf("  │   payload      = %u bytes (SEQ:8 + PRBS:%u)       │\n",
           tx_expected_payload, tx_expected_payload - SEQ_BYTES);
    printf("  │                                                         │\n");
    printf("  │ Gelen paket (RX):                                      │\n");
    printf("  │   pkt_len      = %u bytes                             │\n", pkt_len);
    printf("  │   ip_total_len = %u                                  │\n", ip_total_len_val);
    printf("  │   payload      = %u bytes (pkt_len'den)              │\n", payload_from_pktlen);
    printf("  │                                                         │\n");
    printf("  │ FARK ANALIZI:  (toplam %u byte fazla)                  │\n", total_extra);
    if (device_added > 0)
    printf("  │   Cihaz ekledi:     +%u bytes (ip_total: %u -> %u)  │\n",
           device_added, tx_expected_iptotal, ip_total_len_val);
    if (nic_padding > 0)
    printf("  │   NIC/Switch pad:   +%u byte  (pkt_len vs ip_total)    │\n", nic_padding);
    if (total_extra == 0)
    printf("  │   Fark yok - boyutlar esit                             │\n");
    printf("  └─────────────────────────────────────────────────────────┘\n");

    if (total_extra > 0) {
        printf("  *** SONUC: Gelen paket TX'ten %u byte buyuk! ***\n", total_extra);
        printf("  ***   %u byte cihaz buyuttugu + %u byte NIC padding  ***\n", device_added, nic_padding);
        printf("  ***   Bu ekstra byte'lar 0x00 olarak gelir ve PRBS    ***\n");
        printf("  ***   kontrolunde FAIL'e neden olur (bizim hatamiz    ***\n");
        printf("  ***   degil, karsi taraf paketi buyutuyor).           ***\n");
    }

    // Payload tail: son byte'lar
    if (total_extra > 0) {
        const uint8_t *pb = pkt + payload_off;
        // TX payload sinirini goster
        printf("  PAYLOAD TAIL (TX siniri=%u, gelen=%u):\n", tx_expected_payload, payload_from_pktlen);
        uint16_t tail_start = (tx_expected_payload > 16) ? (tx_expected_payload - 16) : 0;
        uint16_t tail_end = payload_from_pktlen;
        printf("    offset: ");
        for (uint16_t i = tail_start; i < tail_end; i++) {
            if (i == tx_expected_payload) printf("│ ");
            if (i == payload_from_ip)     printf("│ ");
            printf("%4u ", i);
        }
        printf("\n    data:   ");
        for (uint16_t i = tail_start; i < tail_end; i++) {
            if (i == tx_expected_payload) printf("│ ");
            if (i == payload_from_ip)     printf("│ ");
            printf("  %02x ", pb[i]);
        }
        printf("\n    kaynak: ");
        for (uint16_t i = tail_start; i < tail_end; i++) {
            if (i == tx_expected_payload) printf("│ ");
            if (i == payload_from_ip)     printf("│ ");
            if (i < tx_expected_payload)
                printf(" VMC ");
            else if (i < payload_from_ip)
                printf(" CHz ");
            else
                printf(" PAD ");
        }
        printf("\n");
        printf("    (VMC = bizim veri, CHz = cihaz ekledi, PAD = NIC padding)\n");
        printf("    (│ = sinir isaretleri: ilk=TX payload sonu, ikinci=IP total_len sonu)\n");
    }

    const uint8_t *payload_base = pkt + payload_off;
    uint16_t payload_len = payload_from_pktlen;  // pkt_len tabanli

    // Sequence number
    uint64_t seq;
    memcpy(&seq, payload_base, sizeof(seq));
    printf("  SEQ:     %" PRIu64 " (0x%016" PRIX64 ")\n", seq, seq);

    uint16_t total_prbs_len = (payload_len > SEQ_BYTES) ? payload_len - SEQ_BYTES : 0;
    uint16_t tx_prbs_len = tx_expected_payload - SEQ_BYTES;  // VMC_1'in gonderdigi PRBS
    printf("  PRBS alani:  %u bytes (pkt_len'den)\n", total_prbs_len);
    printf("  PRBS (TX):   %u bytes (VMC_1'in gonderdigi gercek PRBS)\n", tx_prbs_len);
    if (total_prbs_len != tx_prbs_len)
        printf("  *** PRBS alani TX'ten %u byte buyuk! ***\n", total_prbs_len - tx_prbs_len);

    // Memory layout
    printf("║ PAYLOAD MEMORY MAP:\n");
    printf("  [%u..%u]     SEQ            (8 bytes)\n", 0, 7);
    printf("  [%u..%u]    XOR zone       (64 bytes) - splitmix64 XOR alani\n", 8, 71);
    printf("  [%u..%u]    CRC32C         (4 bytes)\n", 72, 75);
    uint16_t saf_prbs_from_tx = tx_prbs_len - TRACE_SPLITMIX_TOTAL_OVERHEAD - 1;
    uint16_t saf_prbs_from_pkt = (total_prbs_len > TRACE_SPLITMIX_TOTAL_OVERHEAD + 1) ?
        total_prbs_len - TRACE_SPLITMIX_TOTAL_OVERHEAD - 1 : 0;
    printf("  [%u..%u]  Saf PRBS       (%u bytes - VMC_1 gercek veri)\n",
           76, 76 + saf_prbs_from_tx - 1, saf_prbs_from_tx);
    if (saf_prbs_from_pkt > saf_prbs_from_tx)
        printf("  [%u..%u]  *** EKSTRA ***  (%u bytes - cihaz+NIC ekledi, 0x00 olur)\n",
               76 + saf_prbs_from_tx, 76 + saf_prbs_from_pkt - 1,
               saf_prbs_from_pkt - saf_prbs_from_tx);
    printf("  [%u]          DTN SEQ        (1 byte) - pkt_len'e gore\n", payload_len - 1);
    if (total_extra > 0)
        printf("  *** NOT: DTN byte gercekte [%u] offset'inde (TX payload siniri) ***\n",
               tx_expected_payload - 1);

    // Full payload hex dump (first 256 bytes for readability)
    trace_hexdump("RAW PAYLOAD", payload_base, payload_len, 256);

    // --- PRBS Cache Info ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ PRBS CACHE INFO:\n");
    printf("  Verification port_id: %u\n", port_id);
    uint64_t prbs_off = (seq * (uint64_t)MAX_PRBS_BYTES) % (uint64_t)PRBS_CACHE_SIZE;
    printf("  PRBS offset: seq(%" PRIu64 ") * MAX_PRBS_BYTES(%u) %% PRBS_CACHE_SIZE(%lu) = %" PRIu64 "\n",
           seq, MAX_PRBS_BYTES, (unsigned long)PRBS_CACHE_SIZE, prbs_off);

    bool cache_valid = (port_id < MAX_PRBS_CACHE_PORTS &&
                        port_prbs_cache[port_id].initialized &&
                        port_prbs_cache[port_id].cache_ext != NULL);
    printf("  Cache port %u: %s\n", port_id,
           cache_valid ? "VALID" : "*** INVALID/UNINITIALIZED ***");

    // --- CRC32C Verification ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ CRC32C VERIFICATION:\n");
    printf("  Input: payload_base[0..71] = SEQ(8B) + XOR_ZONE(64B) = 72 bytes\n");
    uint32_t calc_crc = trace_sw_crc32c(payload_base, SEQ_BYTES + TRACE_SPLITMIX_XOR_BYTES);
    uint32_t recv_crc;
    memcpy(&recv_crc, payload_base + SEQ_BYTES + TRACE_SPLITMIX_XOR_BYTES, sizeof(recv_crc));
    bool crc_ok = (calc_crc == recv_crc);
    // Endianness check: byte-swap recv_crc and compare
    uint32_t recv_crc_swapped = ((recv_crc >> 24) & 0xFF) |
                                 ((recv_crc >> 8) & 0xFF00) |
                                 ((recv_crc << 8) & 0xFF0000) |
                                 ((recv_crc << 24) & 0xFF000000);
    bool crc_ok_swapped = (calc_crc == recv_crc_swapped);
    printf("  Received CRC32C:  0x%08X (at payload offset 72)\n", recv_crc);
    printf("  Calculated CRC:   0x%08X (over bytes [0..71])\n", calc_crc);
    printf("  Byte-swapped CRC: 0x%08X (recv byte-reversed)\n", recv_crc_swapped);
    if (crc_ok)
        printf("  Result: OK\n");
    else if (crc_ok_swapped)
        printf("  Result: *** ENDIANNESS MISMATCH! ***\n"
               "    CRC32C DEGERI DOGRU ama byte sirasi TERS!\n"
               "    Cihaz BIG-ENDIAN yaziyor, biz LITTLE-ENDIAN okuyoruz.\n"
               "    byte-swap yapilinca: 0x%08X == 0x%08X ESLESIR!\n",
               recv_crc_swapped, calc_crc);
    else
        printf("  Result: *** FAIL (endian swap da eslesmedi) ***\n");

    // --- TX vs RX ilk 72 byte karsilastirmasi ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ PAYLOAD ILK 72 BYTE (SEQ + XOR ZONE) DETAY:\n");
    if (cache_valid) {
        const uint8_t *rx_data = payload_base;
        const uint8_t *tx_prbs_data = port_prbs_cache[port_id].cache_ext + prbs_off;
        // TX payload: [SEQ(8)] + [raw PRBS(64)] = 72 byte
        // RX payload: [SEQ(8)] + [XOR'd data(64)] = 72 byte
        printf("  offset  TX(PRBS)  RX(gelen)   XOR     Durum\n");
        printf("  ------  --------  ---------  ------   -----\n");
        // SEQ bytes (0-7): bunlar her iki tarafta da ayni olmali
        for (int i = 0; i < 8; i++) {
            uint8_t tx_byte = (i < (int)sizeof(seq)) ? ((uint8_t *)&seq)[i] : 0;
            uint8_t rx_byte = rx_data[i];
            printf("  [%4d]    0x%02x      0x%02x      0x%02x    %s  (SEQ)\n",
                   i, tx_byte, rx_byte, tx_byte ^ rx_byte,
                   (tx_byte == rx_byte) ? "OK" : "FARKLI");
        }
        printf("  ------  --------  ---------  ------   ----- (XOR zone baslangici)\n");
        // XOR zone bytes (8-71): TX'te raw PRBS, RX'te transform edilmis
        int diff_count = 0;
        for (int i = 0; i < 64; i++) {
            uint8_t tx_byte = tx_prbs_data[i];
            uint8_t rx_byte = rx_data[SEQ_BYTES + i];
            bool same = (tx_byte == rx_byte);
            if (!same) diff_count++;
            printf("  [%4d]    0x%02x      0x%02x      0x%02x    %s\n",
                   SEQ_BYTES + i, tx_byte, rx_byte, tx_byte ^ rx_byte,
                   same ? "AYNI" : "FARKLI");
        }
        printf("  ------  --------  ---------  ------   -----\n");
        if (diff_count == 0)
            printf("  XOR zone: TX ile RX AYNI -> cihaz transform YAPMAMIS\n");
        else if (diff_count == 64)
            printf("  XOR zone: 64/64 byte FARKLI -> cihaz transform UYGULADI!\n");
        else
            printf("  XOR zone: %d/64 byte farkli -> KISMI degisiklik\n", diff_count);
    }

    // --- Splitmix64 Verification ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ SPLITMIX64 VERIFICATION:\n");
    printf("  XOR'd zone: payload[8..71] (64 bytes)\n");
    printf("  Decode: decoded[i] = xored[i] ^ splitmix64(seq + i/8)\n");

    if (cache_valid) {
        const uint8_t *xored = payload_base + SEQ_BYTES;
        const uint8_t *orig_prbs = port_prbs_cache[port_id].cache_ext + prbs_off;
        bool sm_ok = true;

        printf("  Block-by-block (8 blocks x 8 bytes):\n");
        for (int blk = 0; blk < 8; blk++) {
            uint64_t sm_key = seq + (uint64_t)blk;
            uint64_t sm_val = trace_splitmix64(sm_key);
            uint64_t xored_val, orig_val;
            memcpy(&xored_val, xored + blk * 8, sizeof(uint64_t));
            memcpy(&orig_val, orig_prbs + blk * 8, sizeof(uint64_t));
            uint64_t decoded = xored_val ^ sm_val;
            bool blk_ok = (decoded == orig_val);
            if (!blk_ok) sm_ok = false;
            printf("    [blk %d] sm_key=seq+%d=%" PRIu64 "\n", blk, blk, sm_key);
            printf("            sm_val  = 0x%016" PRIX64 "\n", sm_val);
            printf("            xored   = 0x%016" PRIX64 "\n", xored_val);
            printf("            decoded = 0x%016" PRIX64 " (xored ^ sm_val)\n", decoded);
            printf("            exp_prbs= 0x%016" PRIX64 " %s\n", orig_val,
                   blk_ok ? "OK" : "*** MISMATCH ***");
        }
        printf("  SPLIT64 Result: %s\n", sm_ok ? "OK" : "*** FAIL ***");
    } else {
        printf("  *** SKIP: PRBS cache invalid for port %u ***\n", port_id);
    }

    // --- PRBS Verification ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ PRBS-31 VERIFICATION (saf PRBS bolumu):\n");

    if (cache_valid) {
        const uint8_t *recv_prbs = payload_base + SEQ_BYTES + TRACE_SPLITMIX_TOTAL_OVERHEAD;
        const uint8_t *exp_prbs = port_prbs_cache[port_id].cache_ext + prbs_off + TRACE_SPLITMIX_TOTAL_OVERHEAD;
        uint16_t prbs_check_len = (total_prbs_len > TRACE_SPLITMIX_TOTAL_OVERHEAD + 1)
            ? total_prbs_len - TRACE_SPLITMIX_TOTAL_OVERHEAD - 1 : 0;
        uint16_t tx_prbs_check = saf_prbs_from_tx;  // VMC_1'in gonderdigi saf PRBS
        printf("  Kontrol edilen:  %u bytes (pkt_len bazli)\n", prbs_check_len);
        printf("  TX gercek PRBS:  %u bytes (VMC_1'in gonderdigi)\n", tx_prbs_check);
        if (prbs_check_len > tx_prbs_check)
            printf("  *** SON %u BYTE TX SINIRININ OTESINDE (cihaz+NIC kaynaklı) ***\n",
                   prbs_check_len - tx_prbs_check);
        printf("  PRBS cache:  cache_ext[%" PRIu64 " + %u] = cache_ext[%" PRIu64 "]\n",
               prbs_off, TRACE_SPLITMIX_TOTAL_OVERHEAD,
               prbs_off + TRACE_SPLITMIX_TOTAL_OVERHEAD);

        if (prbs_check_len > 0) {
            // Show first 64 bytes of received vs expected
            uint16_t show_len = (prbs_check_len < 64) ? prbs_check_len : 64;
            printf("  RECV PRBS[0..%u]: ", show_len - 1);
            for (uint16_t i = 0; i < show_len; i++) printf("%02x ", recv_prbs[i]);
            printf("\n");
            printf("  EXPD PRBS[0..%u]: ", show_len - 1);
            for (uint16_t i = 0; i < show_len; i++) printf("%02x ", exp_prbs[i]);
            printf("\n");

            // TX siniri icindeki PRBS kontrolu
            uint16_t tx_match = 0;
            for (uint16_t i = 0; i < tx_prbs_check && i < prbs_check_len; i++)
                if (recv_prbs[i] == exp_prbs[i]) tx_match++;
            printf("  TX PRBS (%u byte): %u/%u match %s\n",
                   tx_prbs_check, tx_match, tx_prbs_check,
                   (tx_match == tx_prbs_check) ? "-> GERCEK VERI TAMAMEN DOGRU" :
                   "-> *** GERCEK VERIDE HATA VAR ***");

            // Ekstra byte'lar
            if (prbs_check_len > tx_prbs_check) {
                uint16_t extra_start = tx_prbs_check;
                uint16_t extra_count = prbs_check_len - tx_prbs_check;
                printf("  EKSTRA BYTE'LAR (offset %u..%u, %u byte, TX sinirinin OTESI):\n",
                       extra_start, prbs_check_len - 1, extra_count);
                printf("    ");
                for (uint16_t i = extra_start; i < prbs_check_len; i++)
                    printf("[%u] recv=0x%02x exp=0x%02x ", i, recv_prbs[i], exp_prbs[i]);
                printf("\n");
                printf("    *** Bunlar VMC_1'in GONDERMEDIGI byte'lar.          ***\n");
                printf("    *** Cihaz/NIC paketi buyuttugu icin burada 0x00 var. ***\n");
                printf("    *** Bu PRBS FAIL'in GERCEK SEBEBI budur.            ***\n");
            }

            // Detailed comparison with mismatch positions
            trace_compare("PRBS compare (tam)", recv_prbs, exp_prbs, prbs_check_len, 16);
        } else {
            printf("  *** PRBS check length is 0, nothing to verify ***\n");
        }
    } else {
        printf("  *** SKIP: PRBS cache invalid for port %u ***\n", port_id);
    }

    // --- XOR Zone vs Raw PRBS comparison (VMC_2 transform olmadiysa ayni olmali) ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ XOR ZONE vs EXPECTED RAW PRBS (transform yoksa ayni olmali):\n");
    if (cache_valid) {
        const uint8_t *xor_zone = payload_base + SEQ_BYTES;  // payload[8..71]
        const uint8_t *raw_prbs = port_prbs_cache[port_id].cache_ext + prbs_off;  // expected raw
        trace_compare("XOR_ZONE vs RAW_PRBS", xor_zone, raw_prbs, 64, 8);
    }

    // --- DTN Sequence ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ DTN SEQUENCE:\n");
    uint8_t dtn_actual = payload_base[payload_len - 1];
    uint8_t dtn_expected = calc_dtn_seq(seq);
    printf("  Actual:   %u (payload son byte, offset %u)\n", dtn_actual, payload_len - 1);
    printf("  Expected: %u (calc_dtn_seq(%" PRIu64 "))\n", dtn_expected, seq);
    printf("  Result:   %s\n", (dtn_actual == dtn_expected) ? "OK" : "*** MISMATCH ***");

    // --- Summary ---
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    bool sm_ok_final = cache_valid ? trace_verify_splitmix64(payload_base, seq, port_id) : false;
    bool prbs_ok_final = cache_valid ? trace_verify_prbs(payload_base, seq, port_id, total_prbs_len) : false;

    // TX siniri icinde PRBS kontrolu (ekstra byte'lar haric)
    bool prbs_tx_ok = false;
    if (cache_valid) {
        const uint8_t *r = payload_base + SEQ_BYTES + TRACE_SPLITMIX_TOTAL_OVERHEAD;
        const uint8_t *e = port_prbs_cache[port_id].cache_ext + prbs_off + TRACE_SPLITMIX_TOTAL_OVERHEAD;
        prbs_tx_ok = (saf_prbs_from_tx == 0) || (memcmp(r, e, saf_prbs_from_tx) == 0);
    }

    printf("║ SUMMARY:\n");
    printf("║   CRC32C  = %s", crc_ok ? "OK" : "FAIL");
    if (!crc_ok) printf("  (VMC_2 transform yok, beklenen)");
    printf("\n");
    printf("║   SPLIT64 = %s", sm_ok_final ? "OK" : "FAIL");
    if (!sm_ok_final) printf("  (VMC_2 transform yok, beklenen)");
    printf("\n");
    printf("║   PRBS    = %s", prbs_ok_final ? "OK" : "FAIL");
    if (!prbs_ok_final && prbs_tx_ok && total_extra > 0)
        printf("  (SADECE cihaz/NIC ekstra byte'lari yuzunden FAIL!)");
    else if (!prbs_ok_final && !prbs_tx_ok)
        printf("  (*** GERCEK PRBS HATASI - TX verisi bozuk ***)");
    printf("\n");
    if (prbs_tx_ok && !prbs_ok_final)
        printf("║   PRBS(TX siniri icinde) = OK  <-- VMC_1 verisi %u/%u byte dogru\n",
               saf_prbs_from_tx, saf_prbs_from_tx);
    printf("║   DTN_SEQ = %s\n", (dtn_actual == dtn_expected) ? "OK" : "FAIL");
    if (total_extra > 0) {
        printf("║\n");
        printf("║   *** SONUC: Paket %u byte buyutulmus (cihaz:%u + NIC:%u) ***\n",
               total_extra, device_added, nic_padding);
        printf("║   *** PRBS FAIL sadece bu ekstra byte'lardan kaynakli. ***\n");
        printf("║   *** VMC_1'in gonderdigi %u byte PRBS tamamen dogru. ***\n", saf_prbs_from_tx);
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

#define SHOULD_TRACE_PACKET(port_id, vl_idx, seq) \
    (PACKET_TRACE_ENABLED && \
     (((port_id) == PACKET_TRACE_PORT && \
       (vl_idx) == PACKET_TRACE_VL_IDX_TX && \
       ((PACKET_TRACE_SEQ == 0) || ((seq) % PACKET_TRACE_SEQ == 0))) || \
      ((port_id) == PACKET_TRACE2_PORT && \
       (vl_idx) == PACKET_TRACE2_VL_IDX_TX && \
       ((PACKET_TRACE2_SEQ == 0) || ((seq) % PACKET_TRACE2_SEQ == 0)))))

#define SHOULD_TRACE_PACKET_RX(port_id, vl_idx, seq) \
    (PACKET_TRACE_ENABLED && \
     (((port_id) == PACKET_TRACE_PORT && \
       (vl_idx) == PACKET_TRACE_VL_IDX_RX && \
       ((PACKET_TRACE_SEQ == 0) || ((seq) % PACKET_TRACE_SEQ == 0))) || \
      ((port_id) == PACKET_TRACE2_PORT && \
       (vl_idx) == PACKET_TRACE2_VL_IDX_RX && \
       ((PACKET_TRACE2_SEQ == 0) || ((seq) % PACKET_TRACE2_SEQ == 0)))))

#else
#define SHOULD_TRACE_PACKET(port_id, vl_idx, seq) (0)
#define SHOULD_TRACE_PACKET_RX(port_id, vl_idx, seq) (0)
#endif

#endif /* PACKET_H */
