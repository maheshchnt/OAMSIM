/*
 * File: tx.c  Northforge OAMSIM
 *
 * tx.c transmits packets out of ethernet interface
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "oamsim.h"

pthread_t ccm_tx_thread;
int is_tx_running = FALSE;

int skt_fd = -1;

struct eth {
    uchar if_name[150];
    uint  if_number;
    uchar src_mac[6];
} driver_info;


void oam_ether_srcmac_get(uchar *src_mac)
{
    memcpy(src_mac, &driver_info.src_mac, 6);
}

int oamsim_network_interface_create(char *interface)
{
    struct sockaddr_ll skt;
    int tx_bytes = -1;
    struct ifreq intf;
    unsigned char *mac = NULL;

    strcpy(&driver_info.if_name, interface);
    driver_info.if_number = if_nametoindex(interface);

    /* Create a raw socket to transmit OAM packets */
    skt_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (skt_fd < 0) {
	printf("\n Socket creation failed: %d", skt_fd);
	return skt_fd;
    }
        

    memset(&skt, 0, sizeof(struct sockaddr));
    skt.sll_family   = AF_PACKET;
    skt.sll_protocol = htons(ETH_P_ALL);
    skt.sll_ifindex  = driver_info.if_number;
    /* Bind the socket to ethernet interface */
    if (bind(skt_fd, (struct sockaddr *)&skt, sizeof(skt)) < 0) {
	printf("\n Failed to bind the OAM socket with network interface");
	close(skt_fd);
	return FAIL;
    }

    /* now get the interface details */
    memset(&intf, 0, sizeof(intf));
    intf.ifr_addr.sa_family = AF_INET;
    strcpy(intf.ifr_name , &driver_info.if_name);
   
    if (ioctl(skt_fd, SIOCGIFHWADDR, &intf) != OK) {
        close(skt_fd);
	return FAIL;
    }

    memcpy(&driver_info.src_mac, intf.ifr_hwaddr.sa_data, 6);
    
    printf("\n Ethernet interface: '%s' created\n", interface);

    return skt_fd;
}

int oam_edm_pkt_tx(struct cfm_mep *mep)
{
    if (write(skt_fd, &mep->edm.pkt, mep->edm.pkt_length) != mep->edm.pkt_length)
	return FAIL;

    return OK;
}

void ccm_tx_thread_handler(void *ptr)
{
    struct timeval time, prev_time;
    uchar  *pkt;
    uchar  pkt_offset;
    int    tmp = 0;
    struct cfm_tx_mep *tx_mep;
    struct cfm_mep *mep;
    uint   cur_time_stamp = 0;
    int    sec_ctr, sec_diff;

    gettimeofday(&prev_time, NULL);

    while (is_tx_running) {
	LOCK(&cfm_info.mutex);
	tx_mep = cfm_info.mep_list;
	gettimeofday(&time, NULL);
  
	sec_diff = time.tv_sec - prev_time.tv_sec;
	if ((cur_time_stamp + (sec_diff << SEC_POS)) > 0x3ff00000)
            cur_time_stamp &= ~0xfff00000; /* counter overflow case*/
	else
            cur_time_stamp += sec_diff << SEC_POS;

	cur_time_stamp &= 0xfff00000; 
	cur_time_stamp |= time.tv_usec;
	prev_time.tv_sec = time.tv_sec;

	while (tx_mep != NULL) {
	    if ((tx_mep->mep->cc.timeval != 0) && 
		(tx_mep->mep->cc.timeval <= (cur_time_stamp - tx_mep->mep->cc.tx_time_stamp))) {
		pkt = &tx_mep->mep->cc.pkt;
		SET_SEQ_NUM_IN_FRAME(tx_mep->mep->cc.tx_count);
		if (write(skt_fd, &tx_mep->mep->cc.pkt, tx_mep->mep->cc.pkt_length) != tx_mep->mep->cc.pkt_length)
		    LOG("PKT_TX failed\n");

		tx_mep->mep->cc.tx_time_stamp = cur_time_stamp;
		tx_mep->mep->cc.tx_count++;
	    }

	    tx_mep = tx_mep->list.nxt;
	}
	UNLOCK(&cfm_info.mutex);
    }

    pthread_exit(NULL);
}

int oamsim_tx_init(void)
{
    is_tx_running = TRUE;
    return pthread_create(&ccm_tx_thread, NULL, ccm_tx_thread_handler, NULL);
}

int oamsim_tx_cleanup()
{
    is_tx_running = FALSE;
    return close(skt_fd);
}
