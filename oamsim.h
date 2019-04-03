#include <pthread.h>

/* Maximum meps that are supported */
#define MAX_MEP (16 * 1024)

#define MAX_MD_NAME_SIZE 50
#define MAX_MA_NAME_SIZE  50

#define MA_CHAR_STRING 2 /* Change it to enum if required */
#define MD_CHAR_STRING 4

#define ETH_HDR_LENGTH 14
#define CFM_PKT_LENGTH 1500
#define CFM_HEADER_LENGTH 4

#define CFM_MSG_VERSION 0 
#define CFM_CC_MSG_OPCODE 1
#define CFM_EDM_PDU_OPCODE 41
#define CFM_TLV_OFFSET 70
#define CFM_EDM_TLV_OFFSET 10
#define CFM_SEQ_NUM_OFFSET 5

#define CFM_MD_LEVEL_SHIFT 5

#define BUILD_NEW_CCM_PKT (1 << 0)
#define SET_OR_CHANGE_TLV_IN_PKT (1 << 1)

#define TRUE  1
#define FALSE 0

#define LOG printf

typedef unsigned char uchar;
typedef unsigned int uint;

#define LOCK(lk) pthread_mutex_lock(lk)
#define UNLOCK(lk) pthread_mutex_unlock(lk)

/* Can copy upto 4 bytes*/
#define FRAME_CCM_HEADER(val, len) for (tmp = (len - 1); tmp >= 0; tmp--) { \
				       pkt[offset] = (val >> (tmp*8)) & 0xFF;\
				       offset++;\
				   }
    
#define SET_CCM_HEADER(val, len) memset((pkt + offset), val, len);\
	                         offset += len;

#define SET_SEQ_NUM_IN_FRAME(val) pkt_offset = (ETH_HDR_LENGTH + CFM_SEQ_NUM_OFFSET) - 1;\
                                  for (tmp = 3; tmp >= 0; tmp--) {\
	                              pkt[pkt_offset] = val >> ((tmp*8)) & 0xFF;\
				      pkt_offset++;\
				  }

#define SEC_POS 20

/* cli message structure */
struct oamsim_cli_msg
{
    uint  mepid;
    uint  mepIntf;
    uint  md_level;
    uchar md_name[MAX_MD_NAME_SIZE];
    uchar ma_name[MAX_MA_NAME_SIZE];
    uint  assoc_id;
    uint  tlv_type;
    uint  tlv_size;
    uint  credits;
    uchar tlv_val[100];
    uint  mep_interval;
    uint  edm_duration;
};

enum retcodes {
    OK        = 0,
    ERR       = -1,
    MEM       = -2,
    FULL      = -3,
    FAIL      = -4,
    INVALID   = -5,
    NOTFOUND  = -6,
};

struct node {
    void *prv;
    void *nxt;
};

/* list of meps that are configured*/
struct cfm_tx_mep {
    struct  node list;
    uint    mep_if;   /* mep interface */
    struct  cfm_mep *mep;
};

/* global cfm data structure */
struct cfm {
    uint            mep_count; /* Number of MEPs currently configured */
    uint            md_count;  /* Numbrer of MDs currently configured*/
    uint            *mep_intf_bitmap;
    struct          cfm_md *md_list;
    struct          cfm_tx_mep *mep_list;
    pthread_mutex_t mutex;
} cfm_info;

/* MD structure */
struct cfm_md {
    struct node list;
    int    md_level;
    uint   ma_count;    /* number of MAs configured in this md */
    int    type;
    char   md_name[MAX_MD_NAME_SIZE];
    struct cfm_ma *ma_list;
};

/* ma structure */
struct cfm_ma {
    struct  node list;
    uint    mep_count;
    int     type;
    char    ma_name[MAX_MA_NAME_SIZE];
    struct  cfm_mep *mep_list; /* MEPs that are configured in this ma*/
    struct  cfm_md *md;   /* back pointer to MD*/
};

/* Continuity check message structure*/
struct cfm_cc {
    int     tx_interval;
    uint    timeval; /* CC message interval (0-19 bits for usec, 20-31 bits for sec) */
    uint    tx_time_stamp; /* last transmitted packet's time stamp*/
    uint    credits; /* Number of packets to transmit: 0xffffffff means continues tx */
    uint    tx_count;
    uchar   pkt[CFM_PKT_LENGTH];
    int     pkt_length;
};

/* EDM PDU Clause 9.26.1 ITU-T_G8013_Y1731 */
struct cfm_edm {
    uint   duration;
    uint   pkt[CFM_PKT_LENGTH];
    uint   pkt_length;
};

/* TLV structure */
struct cfm_tlv {
    struct node list;
    uint   offset;
    uint   tlv_type;
    int    tlv_size;
    uchar  tlv_val[40];
};

/* mep structure */
struct cfm_mep {
    struct  node list;
    uint    mep_id;
    uint    assoc_id;  /* Specific to Broadcom chipset*/
    uchar   dst_mac[6];
    struct  cfm_tlv *tlv_list;
    struct  cfm_ma *ma; /* back pointer to ma*/
    struct  cfm_md *md; /* back pointer to md*/
    struct  cfm_tx_mep *tx_mep; /* bck pointer to tx_mep*/
    struct  cfm_cc cc; /* CC message structure*/
    struct  cfm_edm edm; /* edm pdui */
};

enum cfm_tlv_type {
     CFM_END_TLV                      = 0,
     CFM_SENDER_ID_TLV                = 1,
     CFM_PORT_STATUS_TLV              = 2,
     CFM_DATA_TLV                     = 3,
     CFM_INTERFACE_STATUS_TLV         = 4,
     CFM_TEST_TLV                     = 32,
};

extern struct cfm_mep* get_mep_by_intf(uint intf);
