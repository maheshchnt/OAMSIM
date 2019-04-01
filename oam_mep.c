#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "oamsim.h"

#define GET_THE_LAST_NODE(dst, node) \
	for (node = &dst->list; node->nxt != NULL; node = node->nxt) {}
        
#define ADD_NODE(dst, src) if (dst == NULL) { \
	                       dst = src;     \
	                       dst->list.prv = dst->list.nxt = NULL; \
	                   } else { \
			       struct node *nd;\
			       GET_THE_LAST_NODE(dst, nd); \
			       nd->nxt = src;\
			       src->list.prv = nd; \
			   }

#define DEL_NODE(dst, src) if ((src == dst) && (src->list.nxt == NULL))\
			       dst = NULL;\
			   else if (src->list.nxt == NULL) { \
			       struct node *tmp;\
			       tmp = src->list.prv;\
			       tmp->nxt = NULL;\
			   } else if (src->list.prv == NULL) {\
			       dst = src->list.nxt;\ 
                           } else {\
			       struct node *tmp;\
			       tmp = src->list.prv;\
			       tmp->nxt = src->list.nxt;\
                               tmp = src->list.nxt;\
		     	       tmp->prv = src->list.prv;\
			   }

#if 0
#define ADD_NODE_WITH_LOCK(dst, src, lk)  if (dst == NULL) { \
	                                      dst = src;\
	                                  } else { \
					      struct node *nd;\
					      GET_THE_LAST_NODE(dst, nd); \
					      nd->nxt = src;\
					      src->list.prv = nd; \
					  }
#endif

#define ADD_NODE_WITH_LOCK(dst, src, lk)  if (dst == NULL) { \
                                              LOCK(lk);\
                                              dst = src;\
                                              UNLOCK(lk);\
                                          } else { \
                                              struct node *nd;\
                                              GET_THE_LAST_NODE(dst, nd); \
                                              LOCK(lk);\
                                              nd->nxt = src;\
                                              src->list.prv = nd; \
                                              UNLOCK(lk);\
                                          }

#if 0
#define DEL_NODE_WITH_LOCK(dst, src, lk) if ((src == dst) && (src->list.nxt == NULL)) {\
	                                     dst = NULL;\
                                         } else if (src->list.nxt == NULL) {\
				             struct node *tmp;\
				             tmp = src->list.prv;\
					     tmp->nxt = NULL;\
                       			 } else if (src->list.prv == NULL) {\
                                             dst = src->list.nxt;\ 
                                         } else {\
                                             struct node *tmp;\
                                             tmp = src->list.prv;\
                                             tmp->nxt = src->list.nxt;\
                                             tmp = src->list.nxt;\
                                             tmp->prv = src->list.prv;\
                                         } 
#endif					     

#define DEL_NODE_WITH_LOCK(dst, src, lk) if ((src == dst) && (src->list.nxt == NULL)) {\
                                             LOCK(lk);\
                                             dst = NULL;\
                                             UNLOCK(lk);\
                                         } else if (src->list.nxt == NULL) {\
                                             struct node *tmp;\
                                             LOCK(lk);\
                                             tmp = src->list.prv;\
                                             tmp->nxt = NULL;\
                                             UNLOCK(lk);\
                                         }  else if (src->list.prv == NULL) {\
                                             dst = src->list.nxt;\
                                         } else {\
                                             struct node *tmp;\
                                             LOCK(lk);\
                                             tmp = src->list.prv;\
                                             tmp->nxt = src->list.nxt;\
                                             tmp = src->list.nxt;\
                                             tmp->prv = src->list.prv;\
                                             UNLOCK(lk);\
                                         }

int oam_info_init()
{
    cfm_info.mep_intf_bitmap = malloc(MAX_MEP/8);
    if (cfm_info.mep_intf_bitmap == NULL)
	return MEM;

    if (pthread_mutex_init(&cfm_info.mutex, NULL) != 0) {
	free(cfm_info.mep_intf_bitmap);
	return FAIL;
    }

    return OK;
}

int oam_info_uninit()
{
    free(cfm_info.mep_intf_bitmap);
    pthread_mutex_destroy(&cfm_info.mutex);

    return OK;
}

int oam_get_mep_interface_index(void)
{
    int i, j, k;
    uint intf_chunk = -1;

    for (i = 0; i < MAX_MEP/32; i++) {
        if (cfm_info.mep_intf_bitmap[i] != 0xFFFFFFFF) {
	    for (j = 0; j < 4; j++) {
		if (((cfm_info.mep_intf_bitmap[i] >> (j * 8 )) & 0xFF) != 0xFF) {
		    for (k = 0; k < 8; k++) {
	                if ((((cfm_info.mep_intf_bitmap[i] >> (j * 8 )) >> k) & 0x1) != 0x1) {
			    cfm_info.mep_intf_bitmap[i] |= 1 << ((j * 8) + k);
			    return ((i * 32) + (j * 8) + k);
			}
		    }
		}
	    }
	}
    }

    return -1;
}

void oam_free_mep_interface_index(uint intf)
{
    cfm_info.mep_intf_bitmap[intf/32] &= ~(1 << (intf%32));
}


enum retcodes is_mep_intf_valid(uint intf)
{
    return (cfm_info.mep_intf_bitmap[intf/32] & (1 << (intf%32)));
}


struct cfm_md* oam_md_get(uchar *mdname, int mdlevel)
{
    struct cfm_md *md;

    for (md = cfm_info.md_list; md != NULL; md = md->list.nxt) {
	if ((strcmp(&md->md_name, mdname) == 0) && (md->md_level == mdlevel))
            return md;
    }

    return NULL;
}

struct cfm_ma* oam_ma_get(struct cfm_md *md, uchar *maname)
{
    struct cfm_ma *ma;

    for (ma = md->ma_list; ma != NULL; ma = ma->list.nxt) {
	if (strcmp(&ma->ma_name, maname) == 0)
            return ma;
    }

    return NULL;
}

struct cfm_mep* oam_mep_get(struct cfm_ma *ma, uint mep_id)
{ 
    struct cfm_mep *mep;

    for (mep = ma->mep_list; mep != NULL; mep = mep->list.nxt) {
        if (mep->mep_id == mep_id)
	    return mep;
    }

    return NULL;
}

int oam_build_tx_packet(struct cfm_mep *mep)
{
    int ccm_flags = (mep->cc.tx_interval) & 0x7;
    int maid_length = 0;
    int offset = 0;
    int tmp = 0;
    int byte_length = 0;
    uchar src_mac[6];
    uchar eth_header[ETH_HDR_LENGTH];
    uchar pkt[CFM_PKT_LENGTH];
    uchar level_and_version = mep->md->md_level << CFM_MD_LEVEL_SHIFT;
    uchar *cc_pkt;
    uchar *pkt_buf = &pkt;
    uchar *eth_buf = &eth_header;
    struct cfm_tlv *tlv;

    /* Build the ethernet header */
    oam_ether_srcmac_get(&src_mac);
    memcpy(&eth_header, &mep->dst_mac, 6);
    memcpy(eth_buf + 6, &src_mac, 6);
    eth_header[12] = 0x89;
    eth_header[13] = 0x02;

    /* CFM packet header parameters */
    FRAME_CCM_HEADER(level_and_version, 1);
    FRAME_CCM_HEADER(CFM_CC_MSG_OPCODE, 1);
    FRAME_CCM_HEADER(ccm_flags, 1);
    FRAME_CCM_HEADER(CFM_TLV_OFFSET, 1);
    FRAME_CCM_HEADER(mep->cc.tx_count, 4);
    FRAME_CCM_HEADER(mep->mep_id, 2);

    /* By default MD type is string*/
    if (mep->md->type == MD_CHAR_STRING) {
        maid_length = strlen(mep->md->md_name);
        FRAME_CCM_HEADER(MD_CHAR_STRING, 1);
        FRAME_CCM_HEADER(maid_length, 1);
        strcpy((pkt_buf + offset), &mep->md->md_name);
        offset += maid_length;
    }

    /* By default MA type is string*/
    if (mep->ma->type == MA_CHAR_STRING) {
	maid_length = strlen(mep->ma->ma_name);
	FRAME_CCM_HEADER(MA_CHAR_STRING, 1);
	FRAME_CCM_HEADER(maid_length, 1);
	strcpy((pkt_buf + offset), &mep->ma->ma_name);
        offset += maid_length;
    }

    /* write zeros into remaining header till the start of the TLV*/
    byte_length = CFM_TLV_OFFSET - (offset - CFM_HEADER_LENGTH);
    SET_CCM_HEADER(0, byte_length);

    for (tlv = mep->tlv_list; tlv != NULL; tlv = tlv->list.nxt) {
	tlv->offset = offset;
	FRAME_CCM_HEADER(tlv->tlv_type, 1);
	FRAME_CCM_HEADER(tlv->tlv_size, 2);
	strcpy((pkt_buf + offset), tlv->tlv_val);
	offset += tlv->tlv_size;
    }
    /* End of TLVs*/
    FRAME_CCM_HEADER(CFM_END_TLV, 1);

    /* Take the lock and copy the packet into mep.cc.pkt*/
    LOCK(&cfm_info.mutex);
    cc_pkt = &mep->cc.pkt;
    /* Finally, copy the packet into pkt buffer */
    memcpy(cc_pkt, eth_header, ETH_HDR_LENGTH);
    memcpy(cc_pkt + ETH_HDR_LENGTH, pkt, offset); 

    mep->cc.pkt_length = offset + ETH_HDR_LENGTH;
  
    UNLOCK(&cfm_info.mutex); 
    return OK;
}

int oam_send_edm_pkt(struct oamsim_cli_msg *msg)
{
    uint   edm_duration = msg->edm_duration;
    uint   mep_intf = msg->mepIntf; 
    uchar  eth_header[ETH_HDR_LENGTH];
    uchar  pkt[CFM_PKT_LENGTH];
    uchar  *edm_pkt;
    uchar  *eth_buf = &eth_header;
    uchar  src_mac[6];
    uint   level_and_version = 0;
    uint   oui_and_subopcode = 0x0019A701; /* ITU-T OUI*/
    int    offset = 0;
    int    tmp = 0;
    int    result = -1;
    int    ccm_flags = 0;
    struct cfm_tx_mep *mep_list = cfm_info.mep_list;
    struct cfm_mep *mep;

    if (is_mep_intf_valid(mep_intf) == FALSE)
        return -1;

    if (mep_list == NULL)
        return -1;

    mep = get_mep_by_intf(mep_intf);
    if (mep == NULL)
        return -1;

    level_and_version = mep->md->md_level << CFM_MD_LEVEL_SHIFT;   
     /* Build the ethernet header */
    oam_ether_srcmac_get(&src_mac);
    memcpy(&eth_header, &mep->dst_mac, 6);
    memcpy(eth_buf + 6, &src_mac, 6);
    eth_header[12] = 0x89;
    eth_header[13] = 0x02;

    /* CFM EDM PDU packet header parameters */
    FRAME_CCM_HEADER(level_and_version, 1);
    FRAME_CCM_HEADER(CFM_EDM_PDU_OPCODE, 1);
    FRAME_CCM_HEADER(ccm_flags, 1);
    FRAME_CCM_HEADER(CFM_EDM_TLV_OFFSET, 1);
    FRAME_CCM_HEADER(oui_and_subopcode, 4);
    FRAME_CCM_HEADER(mep->mep_id, 2);
    FRAME_CCM_HEADER(edm_duration, 4);

    /* End of TLVs*/
    FRAME_CCM_HEADER(CFM_END_TLV, 1);

    edm_pkt = &mep->edm.pkt;
    /* Finally, copy the packet into pkt buffer */
    memcpy(edm_pkt, eth_header, ETH_HDR_LENGTH);
    memcpy(edm_pkt + ETH_HDR_LENGTH, pkt, offset);
    memset(edm_pkt + offset + ETH_HDR_LENGTH, 0, 64 - (offset + ETH_HDR_LENGTH));

    mep->edm.pkt_length = 64;

    LOCK(&cfm_info.mutex);
    result = oam_edm_pkt_tx(mep);
    UNLOCK(&cfm_info.mutex);
    
    if (result != OK)
        return -1;

    return OK;
}

int oam_mep_create(struct oamsim_cli_msg *msg)
{
    struct  cfm_md *md = NULL;
    struct  cfm_ma *ma = NULL;
    struct  cfm_mep *mep = NULL;
    struct  cfm_tx_mep *tx_mep;
    int     new_md = FALSE;
    int     new_ma = FALSE;
    uchar   dst_mac[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};


    /* COMEBACK : Do other checks on parameters */
    if (cfm_info.mep_count >= MAX_MEP)
        return FULL; /* No more room from new MEP */

    if (msg->mepid > 8192 || msg->mepid < 1)
	return INVALID;

    if ((strlen(&msg->ma_name) + strlen(&msg->md_name)) > 48)
	return INVALID;

    if (msg->md_level > 7 || msg->md_level < 0)
	return INVALID;

    if (msg->mep_interval < 1 || msg->mep_interval > 7)
	return INVALID;

    /* Check if the MEP is already created */
    md = oam_md_get(&msg->md_name, msg->md_level);
    if (md != NULL) {
	ma = oam_ma_get(md, &msg->ma_name);
	if (ma != NULL) {
	    mep = oam_mep_get(ma, msg->mepid);
	    if (mep != NULL) {
		LOG("%u : MEP already created", msg->mepid);
		return INVALID;
	    }
	}
    }

    /* Create a Maintenance Domain */
    if (md == NULL) {
	md = malloc(sizeof(struct cfm_md));
	if (md == NULL)
	    return MEM;

	memset(md, 0, sizeof(struct cfm_md));
	md->md_level = msg->md_level;
	strcpy(&md->md_name, &msg->md_name);
	md->type = MD_CHAR_STRING;
	new_md = TRUE;
    }

    /* Create a MA */
    if (ma == NULL) {
	ma = malloc(sizeof(struct cfm_ma));
	if (ma == NULL)
	    goto NO_MEM;

	memset(ma, 0, sizeof(struct cfm_ma));
	ma->type = MA_CHAR_STRING; /* COMEBACK:assign it by default*/
	ma->md = md;
	strcpy(&ma->ma_name, &msg->ma_name);
	new_ma = TRUE;
    }

    /* Create a MEP*/
    mep = malloc(sizeof(struct cfm_mep));
    if (mep == NULL) 
	goto NO_MEM;

    memset(mep, 0, sizeof(struct cfm_mep));
    mep->mep_id         = msg->mepid;
    mep->assoc_id       = msg->assoc_id;
    mep->md             = md;
    mep->ma             = ma;
    oam_mep_interval_set(msg, mep);

    /* Encoding the assoc-id in the dst mac address */
    dst_mac[5]  = msg->assoc_id & 0xFF;
    dst_mac[4]  = (msg->assoc_id >> 8) & 0xFF;
    memcpy(&mep->dst_mac, &dst_mac, 6);

    if (oam_build_tx_packet(mep) != OK)
        goto NO_MEM;

    /* Create a tx mep node;this is used by ethernet driver to transmit CC*/
    tx_mep = malloc(sizeof(struct cfm_tx_mep));
    if (tx_mep == NULL) 
        goto NO_MEM;

    memset(tx_mep, 0, sizeof(struct cfm_tx_mep));
    /* get mep interface. Note that this interface
     * must be freed when MEP is deleted */
    tx_mep->mep = mep;
    mep->tx_mep = tx_mep;
    tx_mep->mep_if = oam_get_mep_interface_index();

    /* Add MEP to MA list */
    ADD_NODE(ma->mep_list, mep);
    ma->mep_count++;

    /* Add ma to md list */
    if (new_ma == TRUE) {
        ADD_NODE(md->ma_list, ma);
	md->ma_count++;
    }

    /* Add md to cfm_info list */
    if (new_md == TRUE) {
        ADD_NODE(cfm_info.md_list, md);
	cfm_info.md_count++;
    }

    /* Finally add the tx_mep to tx_cc list to transmit the packet */
    ADD_NODE_WITH_LOCK(cfm_info.mep_list, tx_mep, &cfm_info.mutex);
    cfm_info.mep_count++;

    return tx_mep->mep_if;

NO_MEM:
    if (tx_mep != NULL)
	free(tx_mep);

    if (mep != NULL)
	free(mep);

    if ((ma != NULL) && (ma->mep_count == 0))
	free(ma);

    if ((md != NULL) && (md->ma_count == 0))
	free(md);

    return MEM;

}

struct cfm_mep* get_mep_by_intf(uint intf)
{
    struct cfm_tx_mep *tx_mep;

    for (tx_mep = cfm_info.mep_list; tx_mep != NULL; tx_mep = tx_mep->list.nxt) {
        if (tx_mep->mep_if == intf)
	    return tx_mep->mep;	
    }
    
    return NULL;
}

/* THis function is called from two places: 1) from cli to set the period
 *  2) from oam_mep_create
 */
int oam_mep_interval_set(struct oamsim_cli_msg *msg, struct cfm_mep *mep_info)
{
    int    result;
    uint   mep_intf = msg->mepIntf;
    int    period = msg->mep_interval;
    struct cfm_tx_mep *mep_list = cfm_info.mep_list;
    struct cfm_mep *mep = mep_info;

    if (mep == NULL) {
        if (is_mep_intf_valid(mep_intf) == FALSE)
            return -1;

        if (mep_list == NULL)
   	    return -1;

        mep = get_mep_by_intf(mep_intf);
        if (mep == NULL)
	    result -1;
    } 

    mep->cc.tx_interval = period;

    switch (period) {
	case 1:
	    mep->cc.timeval = 3300;
	    break;
	case 2:
	    mep->cc.timeval = 10000;
	    break;
	case 3:
	    mep->cc.timeval = 100000;
	    break;
	case 4:
	    mep->cc.timeval = 1 << SEC_POS;
	    break;
	case 5:
	    mep->cc.timeval = 10 << SEC_POS;
	    break;
	case 6:
	    mep->cc.timeval = 60 << SEC_POS;
	    break;
	case 7:
	    mep->cc.timeval = 600 << SEC_POS;
	    break;
	default:
            return -1;
    }

    return 0;
}

int oam_mep_tlv_set(struct oamsim_cli_msg *msg)
{
    int    result;
    uint   mep_intf = msg->mepIntf;
    int    tlv_type = msg->tlv_type;
    int    tlv_size = msg->tlv_size;
    struct cfm_tx_mep *mep_list = cfm_info.mep_list;
    struct cfm_mep *mep;
    struct cfm_tlv *tlv;

    if (is_mep_intf_valid(mep_intf) == FALSE)
        return -1;
 
    if (mep_list == NULL)
        return -1;

    mep = get_mep_by_intf(mep_intf);
    if (mep == NULL)
        return -1;

    for (tlv = mep->tlv_list; tlv != NULL; tlv = tlv->list.nxt) {
	if (tlv->tlv_type == tlv_type) {
	    break;
	}
    }

    if (tlv != NULL) {
        tlv->tlv_type = tlv_type;
        tlv->tlv_size = tlv_size;
        strcpy(&tlv->tlv_val, &msg->tlv_val);
    } else {
        /* Create a new TLV and add it to the MEP */
        tlv = malloc(sizeof(struct cfm_tlv));
        memset(tlv, 0, sizeof(struct cfm_tlv));
        tlv->tlv_type = tlv_type;
        tlv->tlv_size = tlv_size;
        strcpy(&tlv->tlv_val, &msg->tlv_val);
        ADD_NODE(mep->tlv_list, tlv);
    }
    // update the cc packet of the MEP
    result = oam_build_tx_packet(mep);
    if (result != OK)
	return -1;
    
    return 0;
}

int oam_mep_tlv_delete(struct oamsim_cli_msg *msg)
{
    int    result;
    uint   mep_intf = msg->mepIntf;
    int    tlv_type = msg->tlv_type;
    struct cfm_tx_mep *mep_list = cfm_info.mep_list;
    struct cfm_mep *mep;
    struct cfm_tlv *tlv;

    if (is_mep_intf_valid(mep_intf) == FALSE)
        return -1;

    if (mep_list == NULL)
        return -1;

    mep = get_mep_by_intf(mep_intf);
    if (mep == NULL)
        return -1;

    for (tlv = mep->tlv_list; tlv != NULL; tlv = tlv->list.nxt) {
        if (tlv->tlv_type == tlv_type) {
	    DEL_NODE(mep->tlv_list, tlv);
            result = oam_build_tx_packet(mep);
            if (result == OK)
	        return OK;

            break;
        }
    }    

    LOG("%d - TLV not found\n", msg->tlv_type);
    return ERR;
}

int oam_mep_destroy(struct oamsim_cli_msg *msg)
{
    int    result;
    uint   mep_intf = msg->mepIntf;
    struct cfm_mep *mep;
    struct cfm_ma *ma;
    struct cfm_md *md;
    struct cfm_tlv *tlv, *nxt_tlv;

    /* Check whether or not MEP interface is valid*/
    if (is_mep_intf_valid(mep_intf) == FALSE)
        return -1;

    if (cfm_info.mep_list == NULL)
        return -1;

    /* get mep by mep interface */
    mep = get_mep_by_intf(mep_intf);
    if (mep == NULL)
        result -1;

    /* remove the tx_mep from cc_tx mep list;once this is done, 
     * ccm pkt belongining to this mep will not be transmitted*/
    DEL_NODE_WITH_LOCK(cfm_info.mep_list, mep->tx_mep, &cfm_info.mutex);
    free(mep->tx_mep);
    cfm_info.mep_count--;

    /* remove the mep from ma list, decrement the mep_count.
     * If mep count is zero, delete the ma and decrement the
     *  ma count in the md. If the ma count in md is also zero, 
     *  delete the md as well and decrement the md count in cfm_info */
    ma = mep->ma;
    DEL_NODE(ma->mep_list, mep);
    /* Free the TLVs before freeing the MEP*/
    tlv = mep->tlv_list;
    while (tlv != NULL) {
	nxt_tlv = tlv->list.nxt;
        free(tlv);
        tlv = nxt_tlv;	
    }

    free(mep);
    ma->mep_count--;
    oam_free_mep_interface_index(mep_intf);

    if (ma->mep_count == 0) {
	md = ma->md;
	DEL_NODE(md->ma_list, ma);
	free(ma);
	md->ma_count--;
	if (md->ma_count == 0) {
            DEL_NODE(cfm_info.md_list, md);
	    free(md);
	    cfm_info.md_count--;
	}
    }

    return OK;
}

int oam_print_all_meps(void)
{
    struct cfm_tx_mep *mep_list = cfm_info.mep_list;

    //COMEBACK: Print all the mep details
    return OK;
}
