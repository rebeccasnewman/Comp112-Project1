#include "libpacketmod.h"

#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <arpa/inet.h>

//this function slightly modified from https://github.com/OISF/suricata
static uint16_t IPV4Checksum(uint16_t *pkt, uint16_t hlen)
{
    uint32_t csum = pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[6] + pkt[7] +
                    pkt[8] + pkt[9];

    hlen -= 20;
    pkt += 10;

    if (hlen == 0) {
        ;
    } else if (hlen == 4) {
        csum += pkt[0] + pkt[1];
    } else if (hlen == 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
    } else if (hlen == 12) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5];
    } else if (hlen == 16) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7];
    } else if (hlen == 20) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9];
    } else if (hlen == 24) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11];
    } else if (hlen == 28) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13];
    } else if (hlen == 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
                pkt[14] + pkt[15];
    } else if (hlen == 36) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
                pkt[14] + pkt[15] + pkt[16] + pkt[17];
    } else if (hlen == 40) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
                pkt[14] + pkt[15] + pkt[16] + pkt[17] + pkt[18] + pkt[19];
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t) ~csum;
}


//this function slightly modified from https://github.com/OISF/suricata
static uint16_t TCPChecksum(uint16_t *shdr, uint16_t *pkt, uint16_t tlen)
{
    uint16_t pad = 0;

    uint32_t csum = shdr[0] + shdr[1] + shdr[2] + shdr[3] + htons(6) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[9];

    tlen -= 20;
    pkt += 10;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] +
                pkt[8] +
                pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
                pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t)~csum;
}

void FixChecksums(char *ip_pkt, uint16_t ip_pkt_len){

    uint8_t ihl;
    memcpy(&ihl,&ip_pkt[0], sizeof(ihl));
    ihl = ihl & 0x0F; //bitwise to get the low four bits
    uint8_t hlen = ihl * 4;
    uint16_t tcp_len = ip_pkt_len - hlen;


    uint16_t ip_csum = IPV4Checksum((uint16_t  *) &ip_pkt[0], hlen);
    uint16_t tcp_csum = TCPChecksum((uint16_t  *) &ip_pkt[12],(uint16_t  *) &ip_pkt[hlen], tcp_len);

    memcpy(&ip_pkt[10],&ip_csum,sizeof(ip_csum));
    memcpy(&ip_pkt[hlen+16],&tcp_csum,sizeof(tcp_csum));

    uint16_t newcsum;
    memcpy(&newcsum,&ip_pkt[10],sizeof(ip_csum));
    printf("new csum %hx\n",newcsum);
}
