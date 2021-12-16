
#ifndef SP_H_PJQ
#define SP_H_PJQ 1

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

int sp_msg_decode(struct ofconn *ofconn, const struct ofpbuf *msg);

#define MAX_ENTRY 500

enum sperr{
	SP_MSG_PROCESS_OK,
	SP_MSG_PROCESS_ERROR,
};

/* sp msg type. */
enum sptype{
	OFPTYPE_SP_TABLE_CREATE = 50,	/* sp_create_table msg type*/
	OFPTYPE_SP_ST_ENTRY_MOD = 51,	/* sp_st_entry_mode msg type*/
	OFPTYPE_SP_AT_ENTRY_MOD = 52,	/* sp_at_entry_mode msg type*/
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
	OPRATOR_EQUALLESS,		/* <=  */
};

struct sp_match_x {

    ovs_be16 field_id;  /* Used to indicate what kind of field,
                         * it can be a constant or a data packet field or
                         * a parameter sent by the controller */
    ovs_be16 offset;  /* bit unit */
    ovs_be16 len;    /* length in bit unit */

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
//    uint32_t con_1;     //lty
//    uint32_t con_0;     //lty

} ;

struct STATUS_TRANZ_TABLE
{
	struct ovs_list stt_entrys; //store STT_MATCH_ENTRYs
};
//******** STATUS TARANZ TABLE SET  END *********************



//********** ACTION TABLE SET ******************************/
//SP_ACTION IS ENUM+PARAM
//AT_MATCH_ENTRY is like ST_MATCH_ENTRY
struct SP_ACTION
{
	enum SP_ACTION_TYPE
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
	struct SP_ACTION act;
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



struct sp_msg_init_st{
	uint32_t aid;
//	long bitmap;
    uint32_t counts;
//    uint32_t status;
	struct sp_match_x st_match;
    uint16_t pad; // test debug
}; //align to 8 BYTE


struct sp_msg_init_stt
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


struct sp_msg_init_at{
//    long bitmap;
	uint32_t counts;
    struct sp_match_x at_match;
};


struct sp_msg_mod_st{
    uint32_t type;
    uint32_t status;
    uint32_t len;
    char* value;
};

struct sp_msg_mod_at{
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


struct sp_msg_mod{
	uint32_t appid;
	uint32_t count;
	/*
		#counts of structure if is action table mod
		{
		enum TABLE_MOD_TYPE mod type;
		struct SP_ACTION act;
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







#endif
