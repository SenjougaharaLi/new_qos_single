/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 * Copyright (c) 2013 Simon Horman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "odp-execute.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include "dp-packet.h"
#include "dpif.h"
#include "netlink.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "packets.h"
#include "flow.h"
#include "unaligned.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "timeval.h"
#include "stdbool.h"

void pofbf_copy_bit(const uint8_t *data_ori, uint8_t *data_res, uint16_t offset_b, uint16_t len_b); /* pjq */
void pofbf_cover_bit(uint8_t *data_ori, const uint8_t *value, uint16_t pos_b, uint16_t len_b); /* pjq */

VLOG_DEFINE_THIS_MODULE(odp_execute);

/* tsf: to calculate bandwidth. should keep consistent with dpif-netdev.c */
struct bandwidth_info {
    bool comp_latch;     /* if true, don't compute bandwidth, use the former value. */
    uint64_t diff_time;  /* the time that comp_latch value changes. */
    uint64_t n_packets;
    uint64_t n_bytes;
    uint64_t sel_int_packets;
    float    bd;
};

/* Masked copy of an ethernet address. 'src' is already properly masked. */
static void
ether_addr_copy_masked(struct eth_addr *dst, const struct eth_addr src,
                       const struct eth_addr mask)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(dst->be16); i++) {
        dst->be16[i] = src.be16[i] | (dst->be16[i] & ~mask.be16[i]);
    }
}



/* tsf: convert uint64_t data into byte array. */
static uint8_t * uint64_to_arr(uint64_t uint64) {
    uint8_t arr[8];
    for (int i = 0; i < 8; i++) {
        arr[7-i] = (uint64 >> 8*i) & 0xff;
    }
    return arr;
}

/* tsf: store uint8_t data into byte array. */
static uint8_t * uint8_to_arr(uint8_t uint8) {
    uint8_t arr[8];
    arr[0] = uint8;
    return arr;
}

static uint8_t get_set_bits_of_bytes(uint16_t byte){
	uint8_t count = 0;
	while (byte) {
		count += byte & 1;
		byte >>= 1;
	}
	return count;
}

int counter = 0;          // used to limit log rate
uint8_t diff_time_sp=0;
uint8_t last_diff_time=0;
/* tsf: we define INT header in Byte: ETH + IP + INT (type_ttl_mapInfo_medata) + PAYLOAD. */
#define ETH_HEADER_LEN              14
#define ETH_TYPE_OFF                12
#define ETH_TYPE_LEN                 2
#define IPV4_HEADER_LEN             20
#define IPV4_SRC_BASE               26
#define INT_HEADER_BASE             34
#define INT_HEADER_LEN               5
#define INT_HEADER_TYPE_OFF         34
#define INT_HEADER_TYPE_LEN          2
#define INT_HEADER_TTL_OFF          36
#define INT_HEADER_TTL_LEN           1
#define INT_HEADER_MAPINFO_OFF      37
#define INT_HEADER_MAPINFO_LEN       2
#define INT_HEADER_DATA_OFF         39

/* tsf: src header: type=0x0908, ttl=0x01 */
#define INT_SRC_TYPE_TTL         0x090801
uint8_t int_src_type_ttl = 0x01;
uint16_t INT_TYPE_VAL_H       =      0x0908;
uint16_t SRINT_TYPE_VAL_H       =      0x0808;
uint16_t ETH_TYPE_VAL_H       =      0x0800;
uint16_t INT_TYPE_VAL_N       =      0x0809;
uint16_t ETH_TYPE_VAL_N       =      0x0008;   // network byte order

#define MAX_INT_BYTE_LEN           200

/* tsf: INT data byte len. */
#define INT_DATA_DPID_LEN            4   /* bit 0 */
#define INT_DATA_IN_PORT_LEN         4   /* bit 1 */
#define INT_DATA_OUT_PORT_LEN        4   /* bit 2 */
#define INT_DATA_INGRESS_TIME_LEN    8   /* bit 3 */
#define INT_DATA_HOP_LATENCY_LEN     4   /* bit 4 */
#define INT_DATA_BANDWIDTH_LEN       4   /* bit 5 */
#define INT_DATA_N_PACKETS_LEN       8   /* bit 6 */
#define INT_DATA_N_BYTES_LEN         8   /* bit 7 */
#define INT_DATA_QUEUE_LEN           4   /* bit 8, not supported by ovs-pof */
#define INT_DATA_FWD_ACTS_LEN        4   /* bit 9 */
#define INT_DATA_BER_LEN             8   /* bit 10, optical layer data. */

#define CPU_BASED_MAPINFO            0x06ff     /* the bitmap that ovs-pof supports */

/* tsf: invisible packet length. */
#define INTER_FRAME_GAP              12  /* in bytes */
#define PKT_PREAMBLE_SIZE             8  /* in bytes */
#define ETHER_CRC_LEN                 4  /* in bytes */
#define INVISIBLE_PKT_SIZE           24  /* in bytes, 12+8+4=24B */
#define RAND_MAX                     0x7fffffff     //lty

//#define FLOW_BW                       1 /* ifdef, flow bandwidth; else, fixed 50ms to calculate port bandwidth */

/* tsf: flag to determine whether to use 'key->offset' given by controller.
 *      used by odp_pof_add_field() and odp_pof_delete_field().
 * */
bool use_controller_offset = false;
uint64_t INT_HEADER_PKT_CNT = 0;       // count packets for N to insert INT header

double ber = 0;    /* optical layer data. global extern variable, called in ovs-vswitchd.c. */


static void
odp_pof_set_field(struct dp_packet *packet, const struct ovs_key_set_field *key,
                  const struct ovs_key_set_field *mask, long long ingress_time, struct bandwidth_info *bd_info)
{
    char * header;
//    VLOG_INFO("+++++++++++zqt odp_pof_set_field:key->offset = %d, len= %d, fieldid= %d", key->offset, key->len, key->field_id);
//    uint8_t *value = dp_packet_pof_set_field(packet, key->offset);
    if (key->field_id != 0xffff) {
        uint8_t *value = dp_packet_pof_set_field(packet, (key->offset));
        if (value) {
            if (!mask) {
                for (int i = 0; i < key->len; i++) {
                    *(value + i) = key->value[i];
//                    VLOG_INFO("+++++++++++zqt odp_pof_set_field:!mask");
                }
            } else {
                for (int i = 0; i < key->len; i++) {
//                    VLOG_INFO("+++++++++++sqy 11111 odp_pof_set_field before:key->value[i]= %d, %d, %d", key->value[i], *(value+i), mask->value[i] );
                    *(value + i) = key->value[i] | (*(value + i) & ~mask->value[i]);
//                    VLOG_INFO("+++++++++++sqy odp_pof_set_field after: %d, %d", key->value[i], *(value+i));
                }
                /*ether_addr_copy_masked(&eh->eth_src, key->eth_src, mask->eth_src);
                ether_addr_copy_masked(&eh->eth_dst, key->eth_dst, mask->eth_dst);*/
            }
        }
    } else {   // 'add_dynamic_field' or 'add_int_field' action, fields come from data plane

        /** @param key->value[0] controller mapInfo. if is 0xffff, then we read 'mapInfo' from packets
         * @param key->offset define where to insert INT data fields. determined by data plane or controller (see flag 'use_controller_offset').
         * @param key->len refers to N, which selects one every N packets.
         * */

        uint8_t device_id = (uint8_t) key->device_id;
//        uint8_t in_port = (uint8_t)key->in_port;
        uint8_t out_port = (uint8_t) key->out_port;

        device_id = device_id<<4;
        uint8_t dp = device_id + out_port;

        uint32_t ingress_time__ = (uint32_t) ingress_time;       // tsf: used to calculate delta_time
//        VLOG_INFO("+++++++zqt odp_pof_add_field, return: ingress_time__=%x", ingress_time__);
        float bandwidth = 0.0;    // initialized value, if change, else keep
        uint16_t int_len = 0;
        uint8_t int_value[MAX_INT_BYTE_LEN];           // should cover added fields.
        uint8_t controller_mapInfo = key->value[0];    // the mapInfo comes from controller, 2B
        uint8_t final_mapInfo = 0;                     // the final intent mapInfo

#ifdef FLOW_BW
        uint64_t start_times = 0, end_times = 0;
#endif

        final_mapInfo = controller_mapInfo;
//        VLOG_INFO("+++++++zqt odp_pof_add_field, return: final_mapInfo=%x", final_mapInfo);
        if (get_set_bits_of_bytes(final_mapInfo) == 0) {
//            VLOG_INFO("+++++++tsf odp_pof_add_field, return: int_type=%x", int_type);
            return;
        }

        if (final_mapInfo & (UINT8_C(1))) { // zqt: device_id, 1B
            memcpy(int_value + int_len, &dp, 1);
            int_len += 1;
            /*VLOG_INFO("++++++tsf odp_pof_add_field: device_id=0x%04llx", htonl(device_id));*/
        }

        if (final_mapInfo & (UINT8_C(1) << 2)) { // tsf: hop latency, 2B
            uint32_t egress_time = (uint32_t) time_wall_usec();        // current time
            uint8_t diff_time = ntohs(egress_time - ingress_time__)>>8;  // for packet level
//            VLOG_INFO("+++++++zqt odp_pof_add_field, return: 8diff_time=%u", diff_time);
            memcpy(int_value + int_len, &diff_time, 1);
            int_len += 1;
            /*VLOG_INFO("++++++tsf odp_pof_add_field: egress_time=0x%llx, diff_lantency= 0x%04lx / %d us", egress_time, diff_time, htonl(diff_time));*/
        }

        if (final_mapInfo & (UINT8_C(1) << 3)) { // tsf: bandwidth computation insert, 4B
            bandwidth = (bd_info->n_bytes + INVISIBLE_PKT_SIZE * bd_info->n_packets
                         + (int_len + INT_DATA_BANDWIDTH_LEN) * 1) / (bd_info->diff_time * 1.0) * 8;  // Mbps
            uint16_t bandwidth1 = (short) bandwidth;
            memcpy(int_value + int_len, &bandwidth1, 2);      // stored as float type
            int_len += 2;
            /*VLOG_INFO("++++++tsf odp_pof_add_field: bandwidth: 0x%04x / %f Mbps", bandwidth, bandwidth);*/
        }

        uint8_t *value_ = dp_packet_pof_set_field(packet, (key->offset));
        if (value_ ) {
            if (!mask) {
                for (int i = 0; i < int_len; i++) {
                    *(value_  + i) = int_value[i];
                }
            } else {
                for (int i = 0; i < int_len; i++) {
//                    VLOG_INFO("+++++++++++sqy 3333 odp_pof_set_field before:key->value[i]= %d, %d, %d", int_value[i], *(value_ +i));
//                    *(value_  + i) = int_value[i] | (*(value_  + i));
                    *(value_  + i) = int_value[i];
//                    *(value + i) = int_value[i] | (*(value + i) & ~mask->value[i]);
//                    VLOG_INFO("+++++++++++sqy odp_pof_set_field after: %d, %d", int_value[i], *(value_ +i));
                }
            }
        }

    }
}


static void
odp_pof_modify_field(struct dp_packet *packet, const struct ovs_key_modify_field *key,
                     const struct ovs_key_modify_field *mask)
{
    char * header;

    /*VLOG_INFO("++++++tsf odp_pof_modify_field: *lowest_byte=%d, value[0]=%d", *lowest_byte, key->value[0]);*/
    header = dp_packet_data(packet);
    uint8_t sg_ttl;
    uint8_t len;
    uint8_t mapinfo;
    uint8_t p_ttl;
//    VLOG_INFO("+++++++tsf odp_pof_add_field, return: int_type=%x", sr_ttl);
    if (key->field_id != 0xffff) {
        uint8_t *value = dp_packet_pof_modify_field(packet, key->offset);
        uint8_t *lowest_byte = value + (key->len - 1);

        if (value) {
            if (!mask) {
                *lowest_byte += key->value[0];
                /*VLOG_INFO("++++++tsf odp_pof_modify_field/wo mask: key->value[0]=%d, key->mask[0]=%d, *lowest_byte=%d",
                          key->value[0], mask->value[0], *lowest_byte);*/
            } else {   // run here
                /**lowest_byte += key->value[0];*/
                *lowest_byte += key->value[0];
                /*VLOG_INFO("++++++tsf odp_pof_modify_field/wt mask: key->value[0]=%d, key->mask[0]=%d, *lowest_byte=%d",
                          key->value[0], mask->value[0], *lowest_byte);*/
            }
        }
    }
    else {
//        memcpy(&sr_ttl, header + (key->offset), 1);
        memcpy(&sg_ttl, header + 14, 1);
        memcpy(&len, header + 15, 1);
        memcpy(&mapinfo, header + 16, 1);
        memcpy(&p_ttl, header + 17 + (len)*4, 1);

        if(sg_ttl!=0x00){
            if(p_ttl!=0x01){ //pTTL = pTTL - 1;
                uint8_t *value = dp_packet_pof_modify_field(packet, key->offset);
                uint8_t *lowest_byte = value + (key->len - 1);
                if (value) {
                    if (!mask) {
                        *lowest_byte += key->value[0];
                        /*VLOG_INFO("++++++tsf odp_pof_modify_field/wo mask: key->value[0]=%d, key->mask[0]=%d, *lowest_byte=%d",
                                  key->value[0], mask->value[0], *lowest_byte);*/
                    } else {   // run here
                        /**lowest_byte += key->value[0];*/
                        *lowest_byte += key->value[0];
                        /*VLOG_INFO("++++++tsf odp_pof_modify_field/wt mask: key->value[0]=%d, key->mask[0]=%d, *lowest_byte=%d",
                                  key->value[0], mask->value[0], *lowest_byte);*/
                    }
                }
            }else{    //sgTTL = sgTTL - 1;
                uint8_t *value = dp_packet_pof_modify_field(packet, 112); // offset is 14B
                uint8_t *lowest_byte = value + (key->len - 1);
                if (value) {
                    if (!mask) {
                        *lowest_byte += key->value[0];
                        /*VLOG_INFO("++++++tsf odp_pof_modify_field/wo mask: key->value[0]=%d, key->mask[0]=%d, *lowest_byte=%d",
                                  key->value[0], mask->value[0], *lowest_byte);*/
                    } else {   // run here
                        /**lowest_byte += key->value[0];*/
                        *lowest_byte += key->value[0];
                        /*VLOG_INFO("++++++tsf odp_pof_modify_field/wt mask: key->value[0]=%d, key->mask[0]=%d, *lowest_byte=%d",
                                  key->value[0], mask->value[0], *lowest_byte);*/
                    }
                }
                //delete pField
                memmove(header + 4, header, (key->offset));  // shift the packet's length=key->offset backward key->len bytes
                dp_packet_pof_resize_field(packet, -4);
            }
        }else{
            //delete sgField
            memmove(header + 3  + sg_ttl*4, header, 14 );  // shift the packet's length=key->offset backward key->len bytes   // offset is 14B
            dp_packet_pof_resize_field(packet, - (3 + sg_ttl*4) ); // len = 1 + (sgTTL)*4
            memcpy(header + ETH_TYPE_OFF, &ETH_TYPE_VAL_N, ETH_TYPE_LEN);
        }
    }
}




static void
odp_pof_add_field(struct dp_packet *packet, const struct ovs_key_add_field *key,
                  const struct ovs_key_add_field *mask, long long ingress_time,
                  struct bandwidth_info *bd_info)
{
    char * header;

    /** tsf: if field_id=0xffff, then to add INT field, the `value` store the adding intent.
     *       otherwise, then to add static fields that comes from controller.
     **/
    if (key->field_id != 0xffff) {   // 'add_static_field' action, fields come from controller
        header = dp_packet_pof_resize_field(packet, key->len);
        memmove(header, header + key->len, key->offset);
        memcpy(header + key->offset, key->value, key->len);
    } else {   // 'add_dynamic_field' or 'add_int_field' action, fields come from data plane

        /** @param key->value[0] controller mapInfo. if is 0xffff, then we read 'mapInfo' from packets
         * @param key->offset define where to insert INT data fields. determined by data plane or controller (see flag 'use_controller_offset').
         * @param key->len refers to N, which selects one every N packets.
         * */

        uint8_t device_id = (uint8_t) key->device_id;
        uint8_t out_port = (uint8_t) key->out_port;

        device_id = device_id<<4;
        uint8_t dp = device_id + out_port;
        uint32_t ingress_time__ = (uint32_t) ingress_time;       // tsf: used to calculate delta_time

        float bandwidth = 0.0;    // initialized value, if change, else keep

//        uint16_t int_offset = 14;
        uint16_t int_len = 0;                          // indicate how many available bytes in int_value[]
        uint8_t int_value[MAX_INT_BYTE_LEN];           // should cover added fields.

        uint8_t controller_mapInfo = key->value[0];    // the mapInfo comes from controller, 2B
        uint16_t final_mapInfo = 0;                     // the final intent mapInfo


        final_mapInfo = controller_mapInfo;
        if (get_set_bits_of_bytes(final_mapInfo) == 0) {
            /*VLOG_INFO("+++++++tsf odp_pof_add_field, return: int_type=%x", int_type);*/
            return;
        }

        if (final_mapInfo & (UINT8_C(1))) { // tsf: device_id, 4B
            memcpy(int_value + int_len, &dp, 1);
            int_len += 1;
            /*VLOG_INFO("++++++tsf odp_pof_add_field: device_id=0x%04llx", htonl(device_id));*/
        }

        if (final_mapInfo & (UINT8_C(1) << 2)) { // tsf: hop latency, 2B
            uint32_t egress_time = (uint32_t) time_wall_usec();        // current time
            uint8_t diff_time = ntohs(egress_time - ingress_time__)>>8;  // for packet level
//            VLOG_INFO("+++++++zqt odp_pof_add_field, return: 8diff_time=%u", diff_time);
            memcpy(int_value + int_len, &diff_time, 1);
            int_len += 1;
            /*VLOG_INFO("++++++tsf odp_pof_add_field: egress_time=0x%llx, diff_lantency= 0x%04lx / %d us", egress_time, diff_time, htonl(diff_time));*/
        }
//        VLOG_INFO("+++++++zqt odp_pof_add_field, return: int_len=%x", int_len);
        if (final_mapInfo & (UINT8_C(1) << 3)) { // tsf: bandwidth computation insert, 4B
            bandwidth = (bd_info->n_bytes + INVISIBLE_PKT_SIZE * bd_info->n_packets
                         + (int_len + 2) * 1) / (bd_info->diff_time * 1.0) * 8;  // Mbps
            uint16_t bandwidth1 = (short) bandwidth;
            memcpy(int_value + int_len, &bandwidth1, 2);      // stored as float type
            int_len += 2;
            /*VLOG_INFO("++++++tsf odp_pof_add_field: bandwidth: 0x%04x / %f Mbps", bandwidth, bandwidth);*/
        }

        header = dp_packet_pof_resize_field(packet, int_len);
        memmove(header, header + int_len, key->offset);
        memcpy(header + key->offset, int_value, int_len);

//        INT_TYPE_VAL = htons(INT_TYPE_VAL);
        memcpy(header + ETH_TYPE_OFF, &INT_TYPE_VAL_N, ETH_TYPE_LEN);
    }
}


/* tsf: I extend delete_field to support three different deleting operation, listed as follows.
 * act1: delete_truct_field, 'offset'==0xffff, and truncate packet to 'len' size from header.
 * act2: delete_int_field, 'len'==0xffff, and 'offset' is the start location of INT header, deleting len
 * calculated by mapInfo of INT frame, which is | type(2B) | TTL(1B) | mapInfo(2B)(lty) | INT_data([1, 8B].
 * act3: delete_field, original function, delete static field set by {'offset', 'len'}.
 * */
static void
odp_pof_delete_field(struct dp_packet *packet, const struct ovs_key_delete_field *key,
                    const struct ovs_key_delete_field *mask)
{
	/*VLOG_INFO("++++++tsf odp_pof_delete_field: offset=%d, len=%d, pkt_len=%d.", key->offset, key->len, dp_packet_size(packet));*/

	char * header;
	uint32_t offset = key->offset;
	uint32_t len = key->len;

	/*VLOG_INFO("++++++tsf odp_pof_delete_field: before delete field 1, pkt_len=%d.", dp_packet_size(packet));*/
	header = dp_packet_data(packet);  // tsf: start of the header

	/* tsf: act1: defined as delete_trunc_field action, truncate packets into key->len length from header. */
	if (key->offset == 0xffff / 8) {
		/* delete_field in act3. */
		int kept_offset = IPV4_SRC_BASE, kept_len = key->len;    // kept_offset defines the start location from header
		memcpy(header, header+kept_offset, kept_len);
		len = dp_packet_size(packet) - key->len;     // remained payload to be deleted
		offset = key->len;                           // keep key->len header
		goto act3;
	}

	/* tsf: act2: defined as delete_int_field action, calculate deleted length according to mapInfo, key->offset
	 * sets start location. INT format start from 272b: | type(2B) | TTL(1B) | mapInfo(2B) | INT_data([1, 8B]. */
	if (key->len == 0xffff / 8) {

	    /* del_int_field: data_1 refers to one set of metadata type.
	     * int_format: type + ttl + mapInfo + data_1 + data_1 + ... + data_1*/

		int int_data_len = 0;          // data field length to be deleted
		uint16_t int_map;
		uint8_t  int_ttl;              // read them from packets
		memcpy(&int_ttl, header + INT_HEADER_TTL_OFF, INT_HEADER_TTL_LEN);          // read INT.ttl from packet frame
		memcpy(&int_map, header + INT_HEADER_MAPINFO_OFF, INT_HEADER_MAPINFO_LEN);  // read INT.mapInfo from packet frame

        int_map = int_map & CPU_BASED_MAPINFO;

        if (int_map & (UINT16_C(1) << 0)) { // tsf: device_id, 4B
        	int_data_len += INT_DATA_DPID_LEN;
        }

        if (int_map & (UINT16_C(1) << 1)) { // tsf: in_port, 4B
        	int_data_len += INT_DATA_IN_PORT_LEN;
        }

        if (int_map & (UINT16_C(1) << 2)) { // tsf: out_port, 4B
        	int_data_len += INT_DATA_OUT_PORT_LEN;
        }

        if (int_map & (UINT16_C(1) << 3)) { // tsf: ingress_time, 8B
        	int_data_len += INT_DATA_INGRESS_TIME_LEN;
        }

        if (int_map & (UINT16_C(1) << 4)) { // tsf: hop latency, 4B
        	int_data_len += INT_DATA_HOP_LATENCY_LEN;
        }

        if (int_map & (UINT16_C(1) << 5)) { // tsf: bandwidth, 4B
            int_data_len += INT_DATA_BANDWIDTH_LEN;
        }

        if (int_map & (UINT16_C(1) << 6)) { // lty: n_packets, 8B
            int_data_len += INT_DATA_N_PACKETS_LEN;
        }

        if (int_map & (UINT16_C(1) << 7)) { // lty: n_bytes, 8B
            int_data_len += INT_DATA_N_BYTES_LEN;
        }

        if (int_map & (UINT16_C(1) << 8)) { // tsf: queue_len, 4B
            // not supported
        }

        if (int_map & (UINT16_C(1) << 9)) { // tsf: fwd_acts, 4B
            int_data_len += INT_DATA_FWD_ACTS_LEN;
        }

        if (int_map & (UINT16_C(1) << 10)) { // tsf: ber, 8B, double
            int_data_len += INT_DATA_BER_LEN;
        }

        /* delete_field in act3. */
        offset = use_controller_offset ? offset : INT_HEADER_BASE;
        len = INT_HEADER_LEN + int_data_len * int_ttl;
        /*VLOG_INFO("++++++tsf odp_pof_delete_field: act2, offset=%d, len=%d, ttl=%d, int_map=%x, int_data_len=%d, pkt_len=%d.",
        		offset, len, int_ttl, int_map, int_data_len, dp_packet_size(packet));*/
	}

	/* tsf: act3: original delete_field action, delete static {offset, length} field. */
act3:
	memmove(header + len, header, offset);  // shift the packet's length=key->offset backward key->len bytes
	dp_packet_pof_resize_field(packet, -len);

//	ETH_TYPE_VAL = htons(ETH_TYPE_VAL);
    memcpy(header + ETH_TYPE_OFF, &ETH_TYPE_VAL_N, ETH_TYPE_LEN);
	/*VLOG_INFO("++++++tsf odp_pof_delete_field: after delete field 2, pkt_len=%d.", dp_packet_size(packet));*/
}

static void
odp_eth_set_addrs(struct dp_packet *packet, const struct ovs_key_ethernet *key,
                  const struct ovs_key_ethernet *mask)
{
    struct eth_header *eh = dp_packet_l2(packet);

    if (eh) {
        if (!mask) {
            eh->eth_src = key->eth_src;
            eh->eth_dst = key->eth_dst;
        } else {
            ether_addr_copy_masked(&eh->eth_src, key->eth_src, mask->eth_src);
            ether_addr_copy_masked(&eh->eth_dst, key->eth_dst, mask->eth_dst);
        }
    }
}

static void
odp_set_ipv4(struct dp_packet *packet, const struct ovs_key_ipv4 *key,
             const struct ovs_key_ipv4 *mask)
{
    struct ip_header *nh = dp_packet_l3(packet);

    packet_set_ipv4(
        packet,
        key->ipv4_src | (get_16aligned_be32(&nh->ip_src) & ~mask->ipv4_src),
        key->ipv4_dst | (get_16aligned_be32(&nh->ip_dst) & ~mask->ipv4_dst),
        key->ipv4_tos | (nh->ip_tos & ~mask->ipv4_tos),
        key->ipv4_ttl | (nh->ip_ttl & ~mask->ipv4_ttl));
}

static const ovs_be32 *
mask_ipv6_addr(const ovs_16aligned_be32 *old, const ovs_be32 *addr,
               const ovs_be32 *mask, ovs_be32 *masked)
{
    for (int i = 0; i < 4; i++) {
        masked[i] = addr[i] | (get_16aligned_be32(&old[i]) & ~mask[i]);
    }

    return masked;
}

static void
odp_set_ipv6(struct dp_packet *packet, const struct ovs_key_ipv6 *key,
             const struct ovs_key_ipv6 *mask)
{
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);
    ovs_be32 sbuf[4], dbuf[4];
    uint8_t old_tc = ntohl(get_16aligned_be32(&nh->ip6_flow)) >> 20;
    ovs_be32 old_fl = get_16aligned_be32(&nh->ip6_flow) & htonl(0xfffff);

    packet_set_ipv6(
        packet,
        mask_ipv6_addr(nh->ip6_src.be32, key->ipv6_src, mask->ipv6_src, sbuf),
        mask_ipv6_addr(nh->ip6_dst.be32, key->ipv6_dst, mask->ipv6_dst, dbuf),
        key->ipv6_tclass | (old_tc & ~mask->ipv6_tclass),
        key->ipv6_label | (old_fl & ~mask->ipv6_label),
        key->ipv6_hlimit | (nh->ip6_hlim & ~mask->ipv6_hlimit));
}

static void
odp_set_tcp(struct dp_packet *packet, const struct ovs_key_tcp *key,
             const struct ovs_key_tcp *mask)
{
    struct tcp_header *th = dp_packet_l4(packet);

    if (OVS_LIKELY(th && dp_packet_get_tcp_payload(packet))) {
        packet_set_tcp_port(packet,
                            key->tcp_src | (th->tcp_src & ~mask->tcp_src),
                            key->tcp_dst | (th->tcp_dst & ~mask->tcp_dst));
    }
}

static void
odp_set_udp(struct dp_packet *packet, const struct ovs_key_udp *key,
             const struct ovs_key_udp *mask)
{
    struct udp_header *uh = dp_packet_l4(packet);

    if (OVS_LIKELY(uh && dp_packet_get_udp_payload(packet))) {
        packet_set_udp_port(packet,
                            key->udp_src | (uh->udp_src & ~mask->udp_src),
                            key->udp_dst | (uh->udp_dst & ~mask->udp_dst));
    }
}

static void
odp_set_sctp(struct dp_packet *packet, const struct ovs_key_sctp *key,
             const struct ovs_key_sctp *mask)
{
    struct sctp_header *sh = dp_packet_l4(packet);

    if (OVS_LIKELY(sh && dp_packet_get_sctp_payload(packet))) {
        packet_set_sctp_port(packet,
                             key->sctp_src | (sh->sctp_src & ~mask->sctp_src),
                             key->sctp_dst | (sh->sctp_dst & ~mask->sctp_dst));
    }
}

static void
odp_set_tunnel_action(const struct nlattr *a, struct flow_tnl *tun_key)
{
    enum odp_key_fitness fitness;

    fitness = odp_tun_key_from_attr(a, tun_key);
    ovs_assert(fitness != ODP_FIT_ERROR);
}

static void
set_arp(struct dp_packet *packet, const struct ovs_key_arp *key,
        const struct ovs_key_arp *mask)
{
    struct arp_eth_header *arp = dp_packet_l3(packet);

    if (!mask) {
        arp->ar_op = key->arp_op;
        arp->ar_sha = key->arp_sha;
        put_16aligned_be32(&arp->ar_spa, key->arp_sip);
        arp->ar_tha = key->arp_tha;
        put_16aligned_be32(&arp->ar_tpa, key->arp_tip);
    } else {
        ovs_be32 ar_spa = get_16aligned_be32(&arp->ar_spa);
        ovs_be32 ar_tpa = get_16aligned_be32(&arp->ar_tpa);

        arp->ar_op = key->arp_op | (arp->ar_op & ~mask->arp_op);
        ether_addr_copy_masked(&arp->ar_sha, key->arp_sha, mask->arp_sha);
        put_16aligned_be32(&arp->ar_spa,
                           key->arp_sip | (ar_spa & ~mask->arp_sip));
        ether_addr_copy_masked(&arp->ar_tha, key->arp_tha, mask->arp_tha);
        put_16aligned_be32(&arp->ar_tpa,
                           key->arp_tip | (ar_tpa & ~mask->arp_tip));
    }
}

static void
odp_set_nd(struct dp_packet *packet, const struct ovs_key_nd *key,
           const struct ovs_key_nd *mask)
{
    const struct ovs_nd_msg *ns = dp_packet_l4(packet);
    const struct ovs_nd_opt *nd_opt = dp_packet_get_nd_payload(packet);

    if (OVS_LIKELY(ns && nd_opt)) {
        int bytes_remain = dp_packet_l4_size(packet) - sizeof(*ns);
        ovs_be32 tgt_buf[4];
        struct eth_addr sll_buf = eth_addr_zero;
        struct eth_addr tll_buf = eth_addr_zero;

        while (bytes_remain >= ND_OPT_LEN && nd_opt->nd_opt_len != 0) {
            if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
                && nd_opt->nd_opt_len == 1) {
                sll_buf = nd_opt->nd_opt_mac;
                ether_addr_copy_masked(&sll_buf, key->nd_sll, mask->nd_sll);

                /* A packet can only contain one SLL or TLL option */
                break;
            } else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                       && nd_opt->nd_opt_len == 1) {
                tll_buf = nd_opt->nd_opt_mac;
                ether_addr_copy_masked(&tll_buf, key->nd_tll, mask->nd_tll);

                /* A packet can only contain one SLL or TLL option */
                break;
            }

            nd_opt += nd_opt->nd_opt_len;
            bytes_remain -= nd_opt->nd_opt_len * ND_OPT_LEN;
        }

        packet_set_nd(packet,
                      mask_ipv6_addr(ns->target.be32,
                                     key->nd_target, mask->nd_target, tgt_buf),
                      sll_buf,
                      tll_buf);
    }
}

static char* parse_match(struct dp_packet *packet, struct sp_match_x st_match)
{

//    struct xlate_in *xin = ctx->xin;
//    struct dp_packet *packet = ctx->xin->packet;
    char* match = malloc(st_match.len / 8 + 2);

//    if(st_match.field_id == 0xfff0)
//    {match=1;}

    int len = st_match.len / 8;
//    VLOG_INFO("++++lty len in bytes: %d", len);
//    memset(match, 0, 8);
    pofbf_copy_bit((uint8_t *)(packet->mbuf.data_off + packet->mbuf.buf_addr),
                   match, st_match.offset, st_match.len);

    match[len] = '\0';
    match[len + 1] = '\0';
//    VLOG_INFO("++++++pjq in parse match, field id: %d, offset: %d, len: %d \n", st_match.field_id,
   //           st_match.offset, st_match.len);

//    VLOG_INFO("++++++ pjq in parse match, match: %s \n", match);

    struct ds s;
    ds_init(&s);
    ds_put_hex_dump(&s, match, st_match.len / 8, 0, false);
//    VLOG_INFO("++++++ pjq in handle_openflow__,  the ofpbuf msg size: %d, msg: \n%s", st_match.len, ds_cstr(&s));
    ds_destroy(&s);

    char* data = (uint8_t *)(packet->mbuf.data_off + packet->mbuf.buf_addr);
    ds_init(&s);
    ds_put_hex_dump(&s, data, 64, 0, false);
//    VLOG_INFO("++++++ packet size: %d, msg: \n%s", st_match.len, ds_cstr(&s));
    ds_destroy(&s);

    return match;
}

static char* parse_match_at(struct dp_packet *packet, struct sp_match_x st_match, uint32_t state)
{

//    struct xlate_in *xin = ctx->xin;
//    struct dp_packet *packet = ctx->xin->packet;
    char* match = malloc(st_match.len / 8 + 2 + 4);

//    if(st_match.field_id == 0xfff0)
//    {match=1;}

    int len = st_match.len / 8;
//    VLOG_INFO("++++lty len in bytes: %d", len);
//    VLOG_INFO("+++++lty state: %d", state);
//    memset(match, 0, 8);
    pofbf_copy_bit((uint8_t *)(packet->mbuf.data_off + packet->mbuf.buf_addr),
                   match, st_match.offset, st_match.len);

    match[len + 4] = '\0';
    match[len + 5] = '\0';



    match[len + 3] = state & 0xFF;
    match[len + 2] = (state >> 8) & 0xFF;
    match[len + 1] = (state >> 16) & 0xFF;
    match[len] = (state >> 24) & 0xFF;
//    VLOG_INFO("++++++pjq in parse match, field id: %d, offset: %d, len: %d \n", st_match.field_id,
    //          st_match.offset, st_match.len);

//    VLOG_INFO("++++++ pjq in parse match, match: %s \n", match);

    struct ds s;
    ds_init(&s);
    ds_put_hex_dump(&s, match, st_match.len / 8 + 4, 0, false);
//    VLOG_INFO("++++++ pjq in handle_openflow__,  the ofpbuf msg size: %d, msg: \n%s", st_match.len, ds_cstr(&s));
    ds_destroy(&s);

    char* data = (uint8_t *)(packet->mbuf.data_off + packet->mbuf.buf_addr);
    ds_init(&s);
    ds_put_hex_dump(&s, data, 64, 0, false);
//    VLOG_INFO("++++++ packet size: %d, msg: \n%s", st_match.len, ds_cstr(&s));
    ds_destroy(&s);

    return match;
}

static uint64_t get_event_param(struct dp_packet *ctx, struct sp_match_x match)
{
    return 1;
}



// calculate event according to two params and the operator
static bool get_event(uint64_t param1, uint64_t param2, enum OPRATOR op)
{
    bool event;
    switch(op)
    {
        case OPRATOR_NON:
        {
            event = true;
            break;
        }
        case OPRATOR_ADD:
        {
            event = param1 + param2;
            break;
        }
        case OPRATOR_BITAND:
        {
            event = param1 & param2;
            break;
        }
        case OPRATOR_BITOR:
        {
            event = param1 | param2;
            break;
        }
        case OPRATOR_ISEQUAL:
        {
            event = (param1 == param2);
            break;
        }
        case OPRATOR_GREATER:
        {
            event = (param1 > param2);
            break;
        }
        case OPRATOR_LESS:
        {
            event = (param1 < param2);
            break;
        }
        case OPRATOR_EQUALGREATER:
        {
            event = (param1 >= param2);
            break;
        }
        case OPRATOR_EQUALLESS:
        {
            event = (param1 <= param2);
            break;
        }
        default:
        {
            printf("**Event operator not found!\n");
            event = false;
            break;
        }
    }
    return event;
}

static void sp_setsrcfield_action(struct dp_packet *packet, ovs_be32 src_ip, uint16_t max_len, bool may_packet_in)
{
//    ctx->xin->flow.nw_src = src_ip;
    //st_entry->last_status = 1;
//	xlate_output_action(ctx, 2, 0, false);
}
static void sp_setdstfield_action(struct dp_packet *packet, ovs_be32 dst_ip, uint16_t max_len, bool may_packet_in)
{
//    ctx->xin->flow.nw_dst = dst_ip;

//    struct dp_packet *packet = ctx->xin->packet;
    char* match = xmalloc(6);
    match[0] = '1';
    match[1] = '2';
    match[2] = '3';
    match[3] = '4';
//    memset(match, 0, 8);
    pofbf_cover_bit((uint8_t *)(packet->mbuf.data_off + packet->mbuf.buf_addr),
                    match, 240, 32);

    struct ds s;
    char* data = (uint8_t *)(packet->mbuf.data_off + packet->mbuf.buf_addr);
    ds_init(&s);
    ds_put_hex_dump(&s, data, 64, 0, false);
//    VLOG_INFO("++++++ packet size: %d, msg: \n%s", 64, ds_cstr(&s));
    ds_destroy(&s);

    free(match);
    //st_entry->last_status = 2;
//	xlate_output_action(ctx, 1, 0, false);
}

// execute SP actions
static int execute_sp_actions(struct dp_packet *packet, struct AT_MATCH_ENTRY *at_entry)
{   int act_flag_1 ;
//    VLOG_INFO("sp_actions\n");
//    VLOG_INFO("act type is : %d\n", at_entry->act.actype);
    switch(at_entry->act.actype)
    {
        case SAT_OUTPUT:
        {
            // TODO: set output port to IN_PORT for test
//            VLOG_INFO("  Action type is Output, port is %d\n", at_entry->act.acparam);
            //xlate_output_action(ctx, at_entry->act.acparam, 0, false);

            packet->port_id = at_entry->act.acparam;  //lty
            packet->port_flag = 0xffff;

            act_flag_1 = at_entry->act.acparam;
//            VLOG_INFO("+++++ lty dp_packet port id = %d",packet->port_id);
            break;
        }
        case SAT_DROP:
        {
            printf("  Action type is Drop\n");
            return 1;
            // TODO: no idea how to drop a packet, maybe just do nothing
            break;
        }
            //by zzl
       case SAT_TOOPENFLOW:
       {
           //execute_controller_action(ctx, 0, OFPR_ACTION, 0);
           break;
       }
        case ACT_SETSRCFIELD:
        {
            //printf("set source ip\n");
//            VLOG_INFO("Action is SETSRCFIELD, original ip is %d, mod ip is %d\n", ctx->xin->flow.nw_src, at_entry->act.acparam);
//            xlate_setsrcfield_action(ctx, at_entry->act.acparam, 0, false);
            break;
        }
        case ACT_SETDSTFIELD:
        {
            VLOG_INFO("Action is SETDSTFIELD,  mod ip is %d\n", at_entry->act.acparam);
            sp_setdstfield_action(packet, at_entry->act.acparam, 0, false);
            break;
        }
        default:
        {
            printf("  SP action type not found!\n");
            break;
        }
    }
    return 0;
}



static void
odp_pof_goto_sp(struct dp_packet *packet, const struct ovs_key_goto_sp *key, bool may_packet_in, long long ingress_time, struct bandwidth_info *bd_info)
{   //#define INVISIBLE_PKT_SIZE           24  /* in bytes, 12+8+4=24B */
    float bandwidth_sp= 0.0;
    //FILE *fp;

//    VLOG_INFO("++++ pjq Inside function xlate_sp!\n");
    // fetch app indexes from the bitmap, and find app nodes from g_apps
    int i = 0; //inner use
    char I[2]; // string
    struct CONTROLLAPP* app = NULL;
    uint8_t bitmap = key->bitmap;
    bool app_found = false;
    // look up the bitmap (it represents the appid) in the appslist
    LIST_FOR_EACH(app , node, &g_apps.appslist)
    {
        //VLOG_INFO("++++ pjq appid : %d \n", app->appid);
        //Search the g_appslist with appid "i"
        if( app->appid == bitmap)
        {
            app_found = true;
            break;
        }
    }
    if(!app_found)
    {
        VLOG_INFO("++++ pjq No relavant id APP found!\n");
        return;
        //break;
    }

    struct STATUS_TABLE* st = app -> pst;
    struct STATUS_TRANZ_TABLE* stt = app -> pstt;
    struct ACTION_TABLE* at = app -> pat;

    // fetch and parse st match bitmap
    struct sp_match_x st_match = st -> st_match;
//    uint64_t st_match_bitmap = st -> match_bitmap;
//    char* st_match_string = parse_match(ctx, st_match_bitmap);
    char* st_match_string = parse_match(packet, st_match);
//    VLOG_INFO("+++++ lty st_match_string=:%s", st_match_string);
    if(!st_match_string)
    {
        printf("**Match field NULL!\n");
        free(st_match_string);
        return;
    }

    // look up the ST with the Hash, and get current_state
    uint32_t current_state;
    struct ST_MATCH_ENTRY *st_entry;
    bool st_entry_found = false;
    HMAP_FOR_EACH_WITH_HASH(st_entry, node, hash_string(st_match_string, 0), &(st->st_entrys))
    {
        st_entry_found = true;
       // printf("++ST entry found!\n");
        current_state = st_entry->last_status;
        //printf("  Current_state is: %d\n", current_state);
//        VLOG_INFO("+++++ pjq data: %s", st_entry->data);
        break;
    }
    if(!st_entry_found)
    {
       printf("**ST entry not found!\n");
        return;
    }

    uint32_t next_state = current_state;

    // look up the STT with current_state and event-relavant params, and get next_state
    uint64_t param_left  = 0;
    uint64_t param_right = 0;
    int cnt =0;

    bool event = false;
    bool event_exist = false;
    bool stt_entry_found = false;
    uint32_t egress_time_sp = (uint32_t) time_wall_usec();        // current time
    struct STT_MATCH_ENTRY* stt_entry = NULL;

    //fp=fopen("/home/lty/LTY_test_1.txt","w");

    LIST_FOR_EACH(stt_entry , node, &(stt->stt_entrys))
    {
//        if(stt_entry->param_left_type == SFAPARAM_CONST)
//        {param_left = stt_entry->param_left;}
//        else
//        {param_left  = get_event_param(ctx, stt_entry->param_left_type);}
//        if(stt_entry->param_right_type == SFAPARAM_CONST)
//        {param_right = stt_entry->param_right;}
//        else
//        {param_right = get_event_param(ctx, stt_entry->param_right_type);}

//      lty: random calculate
        double x;
        struct drand48_data randBuffer;

        srand48_r(time(NULL), &randBuffer);

        drand48_r(&randBuffer, &x);
        x=x*0;




  //      VLOG_INFO("in list for stt, stt.right param: %lu, left param: %lu, cur state: %d, next state: %d", stt_entry->param_right, stt_entry->param_left, stt_entry->last_status, stt_entry->cur_status);
//        VLOG_INFO("left param field id: %d, right: %d", stt_entry->param_left_match.field_id, stt_entry->param_right_match.field_id);
//        VLOG_INFO("left param field id: %d, right: %d", ntohs(stt_entry->param_left_match.field_id), ntohs(stt_entry->param_right_match.field_id));
        if(stt_entry->param_right_match.field_id == 0xfff0) {
            param_right = stt_entry->param_right;
        } else {
            param_right = parse_match(packet, stt_entry->param_right_match);
        }
        packet->flag = stt_entry->param_left_match.field_id; //lty
        if(stt_entry->param_left_match.field_id==0xfff3){

            //uint64_t egress_time_sp_1 = time_wall_usec();  //current test

            uint32_t ingress_time_sp = (uint32_t) ingress_time;
            //uint64_t diff_tine_test = ingress_time;
//            srand((unsigned int )time(0));
            if(cnt == 0){
                last_diff_time = diff_time_sp;
            }
            printf("+++++lty last_diff_time=%d\n",last_diff_time);
             diff_time_sp = ntohs(egress_time_sp - ingress_time_sp)>>8;  // for packet level

            uint8_t jitter = abs(diff_time_sp-last_diff_time);
//            VLOG_INFO("test_time:%d,%d",egress_time_sp-ingress_time_sp,ntohs(egress_time_sp-ingress_time_sp));
           printf("+++++lty  diff_time_sp=%d\n",diff_time_sp);
            //VLOG_INFO("+++++lty test egress_time_sp=%ld, ingress_time_sp=%lld, diff_time_sp=%ld",egress_time_sp_1,ingress_time,diff_tine_test);
            param_left = jitter;
        }
        else if(stt_entry->param_left_match.field_id==0xfff2){
            bandwidth_sp = (bd_info->n_bytes + INVISIBLE_PKT_SIZE * bd_info->n_packets)/ (bd_info->diff_time * 1.0) * 8;  // Mbps

           //     VLOG_INFO("+++++lty: n_bytes = %lu, n_packets = %lu, diff_time = %lu, bandwidth = %f",bd_info->n_bytes,bd_info->n_packets,bd_info->diff_time,bandwidth_sp);

        //    fprintf(fp,"+++++lty: n_bytes = %lu, n_packets = %lu, diff_time = %lu, bandwidth = %f",bd_info->n_bytes,bd_info->n_packets,bd_info->diff_time,bandwidth_sp);
            param_left = bandwidth_sp*1000000+x;
        }
        else if(stt_entry->param_left_match.field_id==0xfff1){

            //uint64_t egress_time_sp_1 = time_wall_usec();  //current test

            uint32_t ingress_time_sp = (uint32_t) ingress_time;
            //uint64_t diff_tine_test = ingress_time;
//            srand((unsigned int )time(0));

            uint8_t diff_time_sp = ntohs(egress_time_sp - ingress_time_sp)>>8;  // for packet level
//            VLOG_INFO("test_time:%d,%d",egress_time_sp-ingress_time_sp,ntohs(egress_time_sp-ingress_time_sp));
//            VLOG_INFO("+++++lty egress_time_sp=%d, ingress_time_sp=%d, diff_time_sp=%d",egress_time_sp,ingress_time_sp,diff_time_sp);
            //VLOG_INFO("+++++lty test egress_time_sp=%ld, ingress_time_sp=%lld, diff_time_sp=%ld",egress_time_sp_1,ingress_time,diff_tine_test);
            param_left = diff_time_sp+x;
        }
        else if(stt_entry->param_left_match.field_id==0xfff0){
            param_left = stt_entry->param_left;
        }
        else{
            param_left =0; //lty
            int left_len = stt_entry->param_left_match.len / 4;
            char* left_tmp;
            left_tmp = parse_match(packet, stt_entry->param_left_match);
            int mi = 1;
            for(int i = 0; i < left_len; i++) {
                param_left += left_tmp[i] * mi;
                mi = mi * 16;
//                VLOG_INFO("left_tmp[i]: %d, mi: %d, para left: %lu", left_tmp[i], mi, param_left);
//                VLOG_INFO("cha: %d", left_tmp[i] - '0');
        }

        }





        //printf("right param is %lld, ", stt_entry->param_right);
        //param_right = stt_entry->param_right;
        printf("Param left = %lld, Param right = %lld\n", param_left, param_right);
     //   fprintf(fp,"Param left = %lld, Param right = %lld\n", param_left, param_right);
      //  fclose(fp);
        event = get_event(param_left, param_right, stt_entry->oprator);
        if(event)
        {
 //           printf("  Event exists!\n");
            event_exist = true;
            if(current_state == stt_entry->last_status)
            {
                stt_entry_found = true;

                next_state = stt_entry->cur_status;
    //            printf("++STT entry found!\n Param left = %lld, Param right = %lld\n", param_left, param_right);
                break;
            }
        }
        cnt = cnt+1;
    }
    if(!stt_entry_found && event_exist)
    {
//        printf("**STT entry not found, next state is set to 0!\n");
//        next_state = 0; //lty
    }

   // printf("  Next_state is: %d\n", next_state);
    current_state = next_state; //lty
    // fetch and parse bitmap of AT
//    uint64_t at_match_bitmap = at->bitmap;
    char* at_match_string = parse_match_at(packet, at->at_match, current_state);
    //VLOG_INFO("at_match_string=%s",at_match_string);  //lty
    //VLOG_INFO("at->at_match.offset=%d, len=%d, fieldid=%d",at->at_match.offset,at->at_match.len,at->at_match.field_id);  //lty
    if(!at_match_string) //lty:at_match_string=TRUE
    {
        printf("**Match field NULL!\n");
        free(at_match_string);
        return;
    }



    sprintf(I,"%d",current_state);
    int should_drop;
    // look up the AT with the Hash, get actions, and execute them
    struct AT_MATCH_ENTRY *at_entry;

    char *hash_test_0 = malloc(strlen(at_match_string)+1);
    strcpy(hash_test_0, at_match_string);
    strcat(hash_test_0,I);
//    char *hash_test_1 = malloc(strlen(at_match_string)+1);
//    strcpy(hash_test_1, at_match_string);
//    strcat(hash_test_1,"1");
  //  VLOG_INFO("######lty: hash_test_1 's hash value = %d",  hash_string(hash_test_0,0));
    //VLOG_INFO("at_entry->node=%u,at_entry->last_status=%d",at_entry->node,at_entry->last_status);
  //  VLOG_INFO("++++lty in at look up , hash value: %d", hash_string(at_match_string, 0));
//    if(current_state==1){
        HMAP_FOR_EACH_WITH_HASH(at_entry, node, hash_string(hash_test_0, 0), &(at->at_entrys))
        {
            //VLOG_INFO("at_entry->last_status = %d", at_entry->last_status);
            if(at_entry->last_status == current_state)
            {
                //printf("++AT entry found!\n");
                should_drop = execute_sp_actions(packet, at_entry);
                break;
            }
//        printf("++AT entry found!\n");
//        should_drop = execute_sp_actions(packet, at_entry);
//        break;
        }
//    }
//    else if(current_state==3){
//        HMAP_FOR_EACH_WITH_HASH(at_entry, node, hash_string(hash_test_1, 0), &(at->at_entrys))
//        {
//            //VLOG_INFO("at_entry->last_status = %d", at_entry->last_status);
//            if(at_entry->last_status == current_state)
//            {
//                //printf("++AT entry found!\n");
//                should_drop = execute_sp_actions(packet, at_entry);
//                break;
//            }
////        printf("++AT entry found!\n");
////        should_drop = execute_sp_actions(packet, at_entry);
////        break;
//        }
//    }
//    HMAP_FOR_EACH_WITH_HASH(at_entry, node, hash_string(at_match_string, 0), &(at->at_entrys))
//    {
//        //VLOG_INFO("at_entry->last_status = %d", at_entry->last_status);
//        if(at_entry->last_status == current_state)
//        {
//            //printf("++AT entry found!\n");
//            should_drop = execute_sp_actions(packet, at_entry);
//            break;
//        }
////        printf("++AT entry found!\n");
////        should_drop = execute_sp_actions(packet, at_entry);
////        break;
//    }

    // update the state
    if(next_state != 0)
    {
        //printf("  State updating...\n\n");
        st_entry->last_status = next_state;
    }

    free(st_match_string);
    free(at_match_string);

    if(should_drop == 1) return 1;

    return 0;
}

static void
odp_execute_set_action(struct dp_packet *packet, const struct nlattr *a)
{
    enum ovs_key_attr type = nl_attr_type(a);
    const struct ovs_key_ipv4 *ipv4_key;
    const struct ovs_key_ipv6 *ipv6_key;
    struct pkt_metadata *md = &packet->md;

    switch (type) {
    /*VLOG_INFO("+++++++++++sqy odp_execute_set_action: before switch-case");*/
    case OVS_KEY_ATTR_PRIORITY:
        md->skb_priority = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_TUNNEL:
        odp_set_tunnel_action(a, &md->tunnel);
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        md->pkt_mark = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet, nl_attr_get(a), NULL);
        break;

    case OVS_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
        packet_set_ipv4(packet, ipv4_key->ipv4_src,
                        ipv4_key->ipv4_dst, ipv4_key->ipv4_tos,
                        ipv4_key->ipv4_ttl);
        break;

    case OVS_KEY_ATTR_IPV6:
        ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
        packet_set_ipv6(packet, ipv6_key->ipv6_src, ipv6_key->ipv6_dst,
                        ipv6_key->ipv6_tclass, ipv6_key->ipv6_label,
                        ipv6_key->ipv6_hlimit);
        break;

    case OVS_KEY_ATTR_TCP:
        if (OVS_LIKELY(dp_packet_get_tcp_payload(packet))) {
            const struct ovs_key_tcp *tcp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));

            packet_set_tcp_port(packet, tcp_key->tcp_src,
                                tcp_key->tcp_dst);
        }
        break;

    case OVS_KEY_ATTR_UDP:
        if (OVS_LIKELY(dp_packet_get_udp_payload(packet))) {
            const struct ovs_key_udp *udp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_udp));

            packet_set_udp_port(packet, udp_key->udp_src,
                                udp_key->udp_dst);
        }
        break;

    case OVS_KEY_ATTR_SCTP:
        if (OVS_LIKELY(dp_packet_get_sctp_payload(packet))) {
            const struct ovs_key_sctp *sctp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_sctp));

            packet_set_sctp_port(packet, sctp_key->sctp_src,
                                 sctp_key->sctp_dst);
        }
        break;

    case OVS_KEY_ATTR_MPLS:
        set_mpls_lse(packet, nl_attr_get_be32(a));
        break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, nl_attr_get(a), NULL);
        break;

    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
        if (OVS_LIKELY(dp_packet_get_icmp_payload(packet))) {
            const struct ovs_key_icmp *icmp_key
                = nl_attr_get_unspec(a, sizeof(struct ovs_key_icmp));

            packet_set_icmp(packet, icmp_key->icmp_type, icmp_key->icmp_code);
        }
        break;

    case OVS_KEY_ATTR_ND:
        if (OVS_LIKELY(dp_packet_get_nd_payload(packet))) {
            const struct ovs_key_nd *nd_key
                   = nl_attr_get_unspec(a, sizeof(struct ovs_key_nd));
            packet_set_nd(packet, nd_key->nd_target, nd_key->nd_sll,
                          nd_key->nd_tll);
        }
        break;

    case OVS_KEY_ATTR_DP_HASH:
        md->dp_hash = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_RECIRC_ID:
        md->recirc_id = nl_attr_get_u32(a);
        break;

    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case __OVS_KEY_ATTR_MAX:
    default:
        VLOG_INFO("+++++++++++sqy odp_execute_set_action: case: default");
        OVS_NOT_REACHED();
    }
}

#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)

static void
odp_execute_masked_set_action(struct dp_packet *packet,
                              const struct nlattr *a, long long ingress_time,
                              struct bandwidth_info *bd_info)
{
    struct pkt_metadata *md = &packet->md;
    enum ovs_key_attr type = nl_attr_type(a);
    struct mpls_hdr *mh;

    switch (type) {
        case OVS_KEY_ATTR_SET_FIELD:
//            VLOG_INFO("+++++++++++zqt odp_execute_masked_set_action: before OVS_KEY_ATTR_SET_FIELD");
            odp_pof_set_field(packet, nl_attr_get(a),
                              get_mask(a, struct ovs_key_set_field),
                              ingress_time, bd_info);
//            VLOG_INFO("+++++++++++zqt odp_execute_masked_set_action: after OVS_KEY_ATTR_SET_FIELD");
            break;
        case OVS_KEY_ATTR_MODIFY_FIELD:
//            VLOG_INFO("+++++++++++zqt odp_execute_masked_set_action: before OVS_KEY_ATTR_MODIFY_FIELD");
            odp_pof_modify_field(packet, nl_attr_get(a),
                                 get_mask(a, struct ovs_key_modify_field));
//            VLOG_INFO("+++++++++++zqt odp_execute_masked_set_action: after OVS_KEY_ATTR_MODIFY_FIELD");
            break;
        case OVS_KEY_ATTR_ADD_FIELD:
//            VLOG_INFO("+++++++++++zqt odp_execute_masked_set_action: before OVS_KEY_ATTR_ADD_FIELD");
            odp_pof_add_field(packet, nl_attr_get(a),
                              get_mask(a, struct ovs_key_add_field),
                              ingress_time, bd_info);
            break;
        case OVS_KEY_ATTR_GOTO_SP:
//            VLOG_INFO("+++++++++ pjq odp_execute_masked_set_action: before OVS_KEY_ATTR_GOTO_SP");
            odp_pof_goto_sp(packet, nl_attr_get(a), true,ingress_time, bd_info);
    case OVS_KEY_ATTR_DELETE_FIELD:
    	/*VLOG_INFO("+++++++++++tsf odp_execute_masked_set_action: before OVS_KEY_ATTR_DELETE_FIELD");*/
    	odp_pof_delete_field(packet, nl_attr_get(a),
    						get_mask(a, struct ovs_key_delete_field));
    	break;
    case OVS_KEY_ATTR_PRIORITY:
        md->skb_priority = nl_attr_get_u32(a)
            | (md->skb_priority & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_SKB_MARK:
        md->pkt_mark = nl_attr_get_u32(a)
            | (md->pkt_mark & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_ETHERNET:
        odp_eth_set_addrs(packet, nl_attr_get(a),
                          get_mask(a, struct ovs_key_ethernet));
        break;

    case OVS_KEY_ATTR_IPV4:
        odp_set_ipv4(packet, nl_attr_get(a),
                     get_mask(a, struct ovs_key_ipv4));
        break;

    case OVS_KEY_ATTR_IPV6:
        odp_set_ipv6(packet, nl_attr_get(a),
                     get_mask(a, struct ovs_key_ipv6));
        break;

    case OVS_KEY_ATTR_TCP:
        odp_set_tcp(packet, nl_attr_get(a),
                    get_mask(a, struct ovs_key_tcp));
        break;

    case OVS_KEY_ATTR_UDP:
        odp_set_udp(packet, nl_attr_get(a),
                    get_mask(a, struct ovs_key_udp));
        break;

    case OVS_KEY_ATTR_SCTP:
        odp_set_sctp(packet, nl_attr_get(a),
                     get_mask(a, struct ovs_key_sctp));
        break;

    case OVS_KEY_ATTR_MPLS:
        mh = dp_packet_l2_5(packet);
        if (mh) {
            put_16aligned_be32(&mh->mpls_lse, nl_attr_get_be32(a)
                               | (get_16aligned_be32(&mh->mpls_lse)
                                  & ~*get_mask(a, ovs_be32)));
        }
        break;

    case OVS_KEY_ATTR_ARP:
        set_arp(packet, nl_attr_get(a),
                get_mask(a, struct ovs_key_arp));
        break;

    case OVS_KEY_ATTR_ND:
        odp_set_nd(packet, nl_attr_get(a),
                   get_mask(a, struct ovs_key_nd));
        break;

    case OVS_KEY_ATTR_DP_HASH:
        md->dp_hash = nl_attr_get_u32(a)
            | (md->dp_hash & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_RECIRC_ID:
        md->recirc_id = nl_attr_get_u32(a)
            | (md->recirc_id & ~*get_mask(a, uint32_t));
        break;

    case OVS_KEY_ATTR_TUNNEL:    /* Masked data not supported for tunnel. */
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case __OVS_KEY_ATTR_MAX:
    default:
        OVS_NOT_REACHED();
    }
}

static void
odp_execute_sample(void *dp, struct dp_packet *packet, bool steal,
                   const struct nlattr *action,
                   odp_execute_cb dp_execute_action)
{
    const struct nlattr *subactions = NULL;
    const struct nlattr *a;
    struct dp_packet_batch pb;
    size_t left;

    NL_NESTED_FOR_EACH_UNSAFE (a, left, action) {
        int type = nl_attr_type(a);

        switch ((enum ovs_sample_attr) type) {
        case OVS_SAMPLE_ATTR_PROBABILITY:
            if (random_uint32() >= nl_attr_get_u32(a)) {
                if (steal) {
                    dp_packet_delete(packet);
                }
                return;
            }
            break;

        case OVS_SAMPLE_ATTR_ACTIONS:
            subactions = a;
            break;

        case OVS_SAMPLE_ATTR_UNSPEC:
        case __OVS_SAMPLE_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
        }
    }

    packet_batch_init_packet(&pb, packet);
    odp_execute_actions(dp, &pb, steal, nl_attr_get(subactions),
                        nl_attr_get_size(subactions), dp_execute_action, NULL);
}

static bool
requires_datapath_assistance(const struct nlattr *a)
{
    enum ovs_action_attr type = nl_attr_type(a);

    switch (type) {
        /* These only make sense in the context of a datapath. */
    case OVS_ACTION_ATTR_OUTPUT:
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
    case OVS_ACTION_ATTR_TUNNEL_POP:
    case OVS_ACTION_ATTR_USERSPACE:
    case OVS_ACTION_ATTR_RECIRC:
    case OVS_ACTION_ATTR_CT:
        return true;

    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_TRUNC:
        return false;

    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    return false;
}

void
odp_execute_actions(void *dp, struct dp_packet_batch *batch, bool steal,
                    const struct nlattr *actions, size_t actions_len,
                    odp_execute_cb dp_execute_action,
                    void *bandwidth_info)
{    //lty

    struct dp_packet **packets = batch->packets;
    int cnt = batch->count;
    const struct nlattr *a;
    unsigned int left;
    int i;
    struct dp_netdev_execute_aux {
        struct dp_netdev_pmd_thread *pmd;
        long long now;
        const struct flow *flow;
    };
    struct dp_netdev_execute_aux *aux = dp;
    long long ingress_time = aux != NULL ? aux->now : 0;
    struct bandwidth_info *bd_info = bandwidth_info;
    /*VLOG_INFO("+++++++tsf odp_execute_actions: bd_info.comp_latch=%d, diff_time=%d us, n_packets=%d, n_bytes=%d",
        		bd_info->comp_latch, bd_info->diff_time, bd_info->n_packets, bd_info->n_bytes);*/

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        /*VLOG_INFO("+++++++++++sqy odp_execute_actions: type = %d", type);*/
        bool last_action = (left <= NLA_ALIGN(a->nla_len));

        if (requires_datapath_assistance(a)) {
            if (dp_execute_action) {
                /* Allow 'dp_execute_action' to steal the packet data if we do
                 * not need it any more. */
                bool may_steal = steal && last_action;

                dp_execute_action(dp, batch, a, may_steal);

                if (last_action) {
                    /* We do not need to free the packets. dp_execute_actions()
                     * has stolen them */
                    return;
                }
            }
            continue;
        }

        bool flag = false;
        batch->port_flag = false;

        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_HASH: {
            const struct ovs_action_hash *hash_act = nl_attr_get(a);

            /* Calculate a hash value directly.  This might not match the
             * value computed by the datapath, but it is much less expensive,
             * and the current use case (bonding) does not require a strict
             * match to work properly. */
            if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
                struct flow flow;
                uint32_t hash;

                for (i = 0; i < cnt; i++) {
                    flow_extract(packets[i], &flow);
                    hash = flow_hash_5tuple(&flow, hash_act->hash_basis);

                    packets[i]->md.dp_hash = hash;
                }
            } else {
                /* Assert on unknown hash algorithm.  */
                OVS_NOT_REACHED();
            }
            break;
        }

        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);

            for (i = 0; i < cnt; i++) {
                eth_push_vlan(packets[i], vlan->vlan_tpid, vlan->vlan_tci);
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
            for (i = 0; i < cnt; i++) {
                eth_pop_vlan(packets[i]);
            }
            break;

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);

            for (i = 0; i < cnt; i++) {
                push_mpls(packets[i], mpls->mpls_ethertype, mpls->mpls_lse);
            }
            break;
         }

        case OVS_ACTION_ATTR_POP_MPLS:
            for (i = 0; i < cnt; i++) {
                pop_mpls(packets[i], nl_attr_get_be16(a));
            }
            break;

        case OVS_ACTION_ATTR_SET:
            /*VLOG_INFO("+++++++++++sqy odp_execute_actions: before odp_execute_set_action");*/
            for (i = 0; i < cnt; i++) {
                odp_execute_set_action(packets[i], nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SET_MASKED:
            /*VLOG_INFO("+++++++++++sqy odp_execute_actions: before odp_execute_masked_set_action");*/
            for (i = 0; i < cnt; i++) {
                odp_execute_masked_set_action(packets[i], nl_attr_get(a), ingress_time, bd_info);

                if(flag == false && packets[i]->port_flag == 0xffff) {
                    batch->port_flag = true;
                    flag = true;
                }
            }
            break;

        case OVS_ACTION_ATTR_SAMPLE:
            for (i = 0; i < cnt; i++) {
                odp_execute_sample(dp, packets[i], steal && last_action, a,
                                   dp_execute_action);
            }

            if (last_action) {
                /* We do not need to free the packets. odp_execute_sample() has
                 * stolen them*/
                return;
            }
            break;

        case OVS_ACTION_ATTR_TRUNC: {
            const struct ovs_action_trunc *trunc =
                        nl_attr_get_unspec(a, sizeof *trunc);

            batch->trunc = true;
            for (i = 0; i < cnt; i++) {
                dp_packet_set_cutlen(packets[i], trunc->max_len);
            }
            break;
        }

        case OVS_ACTION_ATTR_OUTPUT:
        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_UNSPEC:
        case __OVS_ACTION_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }

    if (steal) {
        for (i = 0; i < cnt; i++) {
            dp_packet_delete(packets[i]);
        }
    }
}
