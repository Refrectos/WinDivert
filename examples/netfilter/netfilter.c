/*
 * netfilter.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * PATCHED: UDP packets are silently dropped (no ICMP responses).
 *          All blocked packets are logged to a file specified via -l flag.
 *
 * usage: netfilter.exe windivert-filter [-v] [-l logfile]
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)
#define htons(x)            WinDivertHelperHtons(x)
#define htonl(x)            WinDivertHelperHtonl(x)

#define MAXBUF              WINDIVERT_MTU_MAX
#define INET6_ADDRSTRLEN    45
#define IPPROTO_ICMPV6      58

typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

typedef struct
{
    WINDIVERT_IPV6HDR ipv6;
    WINDIVERT_TCPHDR tcp;
} TCPV6PACKET, *PTCPV6PACKET;

typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_ICMPHDR icmp;
    UINT8 data[];
} ICMPPACKET, *PICMPPACKET;

typedef struct
{
    WINDIVERT_IPV6HDR ipv6;
    WINDIVERT_ICMPV6HDR icmpv6;
    UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;

static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);
static void PacketIpIcmpInit(PICMPPACKET packet);
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet);
static void PacketIpv6TcpInit(PTCPV6PACKET packet);
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet);

int __cdecl main(int argc, char **argv)
{
    HANDLE handle, console;
    INT16 priority = 0;
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS recv_addr, send_addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    UINT32 src_addr[4], dst_addr[4];
    char src_str[INET6_ADDRSTRLEN+1], dst_str[INET6_ADDRSTRLEN+1];
    UINT payload_len;
    const char *err_str;
    int verbose = 0;
    FILE *logfile = NULL;

    TCPPACKET reset0;
    PTCPPACKET reset = &reset0;
    TCPV6PACKET resetv6_0;
    PTCPV6PACKET resetv6 = &resetv6_0;

    // Parse arguments: filter [-v] [-l logfile]
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s windivert-filter [-v] [-l logfile]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-l") == 0 && i+1 < argc)
        {
            logfile = fopen(argv[++i], "a");
            if (!logfile)
                fprintf(stderr, "warning: cannot open log file\n");
        }
    }

    // Initialize TCP reset packets only (no ICMP needed for UDP)
    PacketIpTcpInit(reset);
    reset->tcp.Rst = 1;
    reset->tcp.Ack = 1;
    PacketIpv6TcpInit(resetv6);
    resetv6->tcp.Rst = 1;
    resetv6->tcp.Ack = 1;

    console = GetStdHandle(STD_OUTPUT_HANDLE);

    handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(argv[1], WINDIVERT_LAYER_NETWORK,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &recv_addr))
        {
            fprintf(stderr, "warning: failed to read packet\n");
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
            NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
            &payload_len, NULL, NULL);

        if (ip_header == NULL && ipv6_header == NULL)
            continue;

        // Format addresses
        if (ip_header != NULL)
        {
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), src_str, sizeof(src_str));
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr), dst_str, sizeof(dst_str));
        }
        if (ipv6_header != NULL)
        {
            WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, src_addr);
            WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dst_addr);
            WinDivertHelperFormatIPv6Address(src_addr, src_str, sizeof(src_str));
            WinDivertHelperFormatIPv6Address(dst_addr, dst_str, sizeof(dst_str));
        }

        // ── UDP: silent drop, no ICMP response ──────────────────────────
        if (udp_header != NULL)
        {
            UINT16 sport = ntohs(udp_header->SrcPort);
            UINT16 dport = ntohs(udp_header->DstPort);

            // Console output (only if -v flag)
            if (verbose)
            {
                SetConsoleTextAttribute(console, FOREGROUND_RED);
                fputs("BLOCK ", stdout);
                SetConsoleTextAttribute(console,
                    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                printf("ip.SrcAddr=%s ip.DstAddr=%s SrcPort=%u DstPort=%u\n",
                    src_str, dst_str, sport, dport);
            }

            // Log to file
            if (logfile)
            {
                fprintf(logfile, "ip.SrcAddr=%s ip.DstAddr=%s SrcPort=%u DstPort=%u\n",
                    src_str, dst_str, sport, dport);
                fflush(logfile);
            }

            // Packet is simply dropped — no WinDivertSend, no ICMP
            continue;
        }

        // ── TCP: send RST (original behaviour) ──────────────────────────
        if (tcp_header != NULL)
        {
            if (verbose)
            {
                SetConsoleTextAttribute(console, FOREGROUND_RED);
                fputs("BLOCK ", stdout);
                SetConsoleTextAttribute(console,
                    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                printf("ip.SrcAddr=%s ip.DstAddr=%s tcp.SrcPort=%u tcp.DstPort=%u\n",
                    src_str, dst_str,
                    ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));
            }

            if (ip_header != NULL && !tcp_header->Rst && !tcp_header->Fin)
            {
                reset->ip.SrcAddr = ip_header->DstAddr;
                reset->ip.DstAddr = ip_header->SrcAddr;
                reset->tcp.SrcPort = tcp_header->DstPort;
                reset->tcp.DstPort = tcp_header->SrcPort;
                reset->tcp.SeqNum = (tcp_header->Ack ? tcp_header->AckNum : 0);
                reset->tcp.AckNum = (tcp_header->Syn ?
                    htonl(ntohl(tcp_header->SeqNum) + 1) :
                    htonl(ntohl(tcp_header->SeqNum) + payload_len));
                memcpy(&send_addr, &recv_addr, sizeof(send_addr));
                send_addr.Outbound = !recv_addr.Outbound;
                WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET), &send_addr, 0);
                WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET), NULL, &send_addr);
            }

            if (ipv6_header != NULL && !tcp_header->Rst && !tcp_header->Fin)
            {
                memcpy(resetv6->ipv6.SrcAddr, ipv6_header->DstAddr, sizeof(resetv6->ipv6.SrcAddr));
                memcpy(resetv6->ipv6.DstAddr, ipv6_header->SrcAddr, sizeof(resetv6->ipv6.DstAddr));
                resetv6->tcp.SrcPort = tcp_header->DstPort;
                resetv6->tcp.DstPort = tcp_header->SrcPort;
                resetv6->tcp.SeqNum = (tcp_header->Ack ? tcp_header->AckNum : 0);
                resetv6->tcp.AckNum = (tcp_header->Syn ?
                    htonl(ntohl(tcp_header->SeqNum) + 1) :
                    htonl(ntohl(tcp_header->SeqNum) + payload_len));
                memcpy(&send_addr, &recv_addr, sizeof(send_addr));
                send_addr.Outbound = !recv_addr.Outbound;
                WinDivertHelperCalcChecksums((PVOID)resetv6, sizeof(TCPV6PACKET), &send_addr, 0);
                WinDivertSend(handle, (PVOID)resetv6, sizeof(TCPV6PACKET), NULL, &send_addr);
            }
            continue;
        }

        // ── ICMP: silent drop (original behaviour) ───────────────────────
    }

    if (logfile) fclose(logfile);
}

static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
    memset(packet, 0, sizeof(WINDIVERT_IPHDR));
    packet->Version = 4;
    packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
    packet->Id = ntohs(0xDEAD);
    packet->TTL = 64;
}

static void PacketIpTcpInit(PTCPPACKET packet)
{
    memset(packet, 0, sizeof(TCPPACKET));
    PacketIpInit(&packet->ip);
    packet->ip.Length = htons(sizeof(TCPPACKET));
    packet->ip.Protocol = IPPROTO_TCP;
    packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

static void PacketIpIcmpInit(PICMPPACKET packet)
{
    memset(packet, 0, sizeof(ICMPPACKET));
    PacketIpInit(&packet->ip);
    packet->ip.Protocol = IPPROTO_ICMP;
}

static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
    memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
    packet->Version = 6;
    packet->HopLimit = 64;
}

static void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
    memset(packet, 0, sizeof(TCPV6PACKET));
    PacketIpv6Init(&packet->ipv6);
    packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
    packet->ipv6.NextHdr = IPPROTO_TCP;
    packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
    memset(packet, 0, sizeof(ICMPV6PACKET));
    PacketIpv6Init(&packet->ipv6);
    packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}
