
#ifndef SFA_H_ERIC
#define SFA_H_ERIC 1

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "util.h"
#include "openvswitch/hmap.h"
#include "openvswitch/ofp-msgs.h"
#include "connmgr.h"

int sfa_handle_pkt(struct ofconn *ofconn, const struct ofpbuf *msg);
//int sfa_handle_pkt(struct ofconn *ofconn, const struct ofpbuf *msg); //pjq


#define MAX_ENTRY 500

enum sfaerr{
	SFA_MSG_PROCESS_OK,
	SFA_MSG_PROCESS_ERROR,
};

/* SFA extension. */
enum sfatype{

	OFPTYPE_SFA_TABLE_CREATE = 50,	/* sfa_craete_table msg type*/
	OFPTYPE_SFA_ST_ENTRY_MOD = 51,	/* sfa_st_entry_mode msg type*/
	OFPTYPE_SFA_AT_ENTRY_MOD = 52,	/* sfa_at_entry_mode msg type*/

};


enum OPRATOR
{
	OPRATOR_NON = 0,
	OPRATOR_ISEQUAL,	/* = */
	OPRATOR_ADD,		/* + */
	OPRATOR_SUB, 		/* - */
	OPRATOR_BITAND,		/* & */
	OPRATOR_BITOR, 		/* | */
	OPRATOR_BITWISE,	/* ^ */
	OPRATOR_GREATER,    /* > */
	OPRATOR_LESS,		/* < */
	OPRATOR_EQUALGREATER,	/* >= */
	OPRATOR_EQUALLESS,		/* <= 8 */
};

struct sp_match_x {

    ovs_be16 field_id;  /*0xffff means metadata,
                          0x8XXX means from table parameter,
                          otherwise means from packet data. */
    ovs_be16 offset;  /*bit unit*/
    ovs_be16 len;    /*length in bit unit*/
};


struct STT_MATCH_ENTRY{
    struct ovs_list node;
    struct sp_match_x param_left_match;
    uint64_t param_left;
    enum OPRATOR oprator;
    struct sp_match_x param_right_match;
    uint64_t param_right;
    uint32_t last_status;
    uint32_t cur_status;
} ;

struct STATUS_TRANZ_TABLE
{
	struct ovs_list stt_entrys; //store STT_MATCH_ENTRYs
};
//******** STATUS TARANZ TABLE SET  END *********************



//********** ACTION TABLE SET ******************************/
//SFA_ACTION IS ENUM+PARAM
//AT_MATCH_ENTRY is like ST_MATCH_ENTRY
struct SFA_ACTION
{
	enum SFA_ACTION_TYPE
	{
        SAT_NON,
		SAT_OUTPUT,
		SAT_DROP,
		SAT_TOOPENFLOW,
		ACT_SETSRCFIELD,
		ACT_SETDSTFIELD,
	} actype;
	uint32_t acparam;
};
struct AT_MATCH_ENTRY{
	struct hmap_node node;
//    struct sp_match_x st_match;
	char* data;
	uint32_t last_status;
	struct SFA_ACTION act;
};


struct ACTION_TABLE
{
//    uint64_t bitmap;
	struct sp_match_x at_match;
	struct hmap at_entrys;  // store AT_MATCH_ENTRYS

};
//********** ACTION TABLE SET END **************************/



//*********** STATUS TABLE SET**************************/
//st table entry use hmap_node to store hash info
// hmap is stored in st, one st has one hmap



struct ST_MATCH_ENTRY{
	struct hmap_node node;
//    struct sp_match_x st_match;
	char* data;
	uint32_t last_status;
};


struct STATUS_TABLE{
    struct sp_match_x st_match;
    struct hmap st_entrys;	// store ST_MATCH_ENTRYs
};
//*********** STATUS TABLE SET END *********************/


//************ CONTROLLERAPP SET ***********************/
struct CONTROLLAPP
{
	struct ovs_list node;
	uint32_t appid;
	struct STATUS_TABLE* pst;
	struct STATUS_TRANZ_TABLE* pstt;
	struct ACTION_TABLE* pat;

};

//************* CONTROLLERAPP SET END ********************/


struct APPS
{
	//private vars
	bool islistinit;
	struct ovs_list appslist; //point to CONTROLLAPPs
}g_apps;


//************  MSG PROTOCOL *******************************



struct sfa_msg_init_st{
	uint32_t aid;
//	long bitmap;
    uint32_t counts;
//    uint32_t status;
	struct sp_match_x st_match;

	//uint32_t lenth;
	//byte[] data;

//	if counts is 0 means no st entry else the next ele is
//	#counts of struct data{
//		uint32_t lenth;
//		byte[] data}

}; //align to 8 BYTE


struct sfa_msg_init_stt
{
	struct sp_match_x param_left_match;
	uint16_t pad1;
	uint64_t param_left;
	uint64_t pad2;

	uint64_t mask1;
	uint64_t mask1_pad;

	struct sp_match_x param_right_match;
	uint16_t pad3;
	uint64_t param_right;
	uint64_t pad4;

    uint64_t mask2;
    uint64_t mask2_pad;

	enum OPRATOR oprator;
	uint32_t last_status;
	uint32_t cur_status;

	uint32_t pad5;
};


struct sfa_msg_init_at{
//    long bitmap;
	uint32_t counts;
    struct sp_match_x at_match;
};


struct sfa_msg_mod_st{
    uint32_t type;
    uint32_t status;
    uint32_t len;
    char* value;
};

struct sfa_msg_mod_at{
    uint32_t type;
    uint32_t act_type;
    uint32_t act_param;
    uint32_t status;
    uint32_t len;
	char* value;
};

//  mode type
enum MOD_TYPE
{
	ENTRY_ADD,
	ENTRY_UPDATE, //for action table update means update the action or status, for status table ,update means update status
	ENTRY_DEL,
};


struct sfa_msg_mod{
	uint32_t appid;
	uint32_t count;
	/*
		#counts of structure if is action table mod
		{
		enum TABLE_MOD_TYPE mod type;
		struct SFA_ACTION act;
		uint32_t last_status;
		uint32_t data_len;
		byte[] data;
		}
	*/
	/*
		#counts of structure if is status table mod
		{
		enum TABLE_MOD_TYPE mod type;
		uint32_t last_status;
		uint32_t data_len;
		byte[] data;
		}
		*/


};




/*	 sfa init msg pattern
 *
 *
 *  |--------------------------32bit ------------------------------|
 * 	+--------------------------------------------------------------+
 *  + version(8)   +   type(8)=90 +           length(16)           +
 *  + -------------------------------------------------------------+
 *  +						xid(32)								   +
 *  +--------------------------------------------------------------+
 *  +						appid(32)
 *  +--------------------------------------------------------------+
 *  +				status table.bitmap(32/64)
 *  +--------------------------------------------------------------+
 *  +				status table.bitmap(64/64)
 *  +--------------------------------------------------------------+
 *  + 				status table data.counts(32)
 *  +--------------------------------------------------------------+
 *  + 				if counts != 0 , see struct data{}
 *  +--------------------------------------------------------------+
 *  +            status transition table counter(32)               +
 *  +--------------------------------------------------------------+
 *  + 			    event  left param type (32)
 *  +--------------------------------------------------------------+
 *  +				event left param value(32/64)
 *  +--------------------------------------------------------------+
 *  +				event left param value(64/64)
 *  +--------------------------------------------------------------+
 *  + 			    event right param type (32)
 *  +--------------------------------------------------------------+
 *  +				event right param value(32/64)
 *  +--------------------------------------------------------------+
 *  +				event right param value(64/64)
 *  +--------------------------------------------------------------+
 *  +               event param operator(32)
 *  +---------------------------------------------------------------
 *  +				status transition table.laststatus(32)
 *  +--------------------------------------------------------------+
 *  +               status transition table.nextstatus(32)
 *  +---------------------------------------------------------------
 *  +          .... #(counter-1) of stt entrys.......
 *  +---------------------------------------------------------------
 *  +             action table bitmap(32/64)
 *  +----------------------------------------------------------------
 *  + 			  	action table bitmap(64/64)
 *  +--------------------------------------------------------------+
 *  +				action table.count(32)
 *  +--------------------------------------------------------------+
 *  +			...#(count-1) of at entrys ....
 *  +--------------------------------------------------------------+
 *  + 			    action table.type(32)
 *  +--------------------------------------------------------------+
 *  +             	action table.param(32)
 *  +-----------------------------------------------------------------
 *  +             	action table.laststatus(32)
 *  +-----------------------------------------------------------------
 *  +             	action table.data_len(32)
 *  +-----------------------------------------------------------------
 *  +             	action table.data
 *  +-----------------------------------------------------------------
 *  +             .........................
 *  +-----------------------------------------------------------------

 */
//
//enum sfaerr sfa_msg_init(struct ofconn *ofconn, const struct ofp_header *sfah );
//enum sfaerr sfa_msg_st_mod(struct ofconn *ofconn, const struct ofp_header *sfah);
//enum sfaerr sfa_msg_at_mod(struct ofconn *ofconn, const struct ofp_header *sfah);

//
//





void cnm();

#endif
