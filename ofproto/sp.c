#include "sp.h"
#include "connmgr.h"

#include "util.h"
#include "openvswitch/vlog.h"
#include "stdlib.h"
#include "string.h"
#include <config.h>

VLOG_DEFINE_THIS_MODULE(sp);

/*
 * Description		called in sp_msg_decode procedure, the function will process the sp init msg
 * 					it will init the status table, status transition table, action table. we now define
 * 					one status table for one application. Moreover, we define one status transition
 * 					table and one action table associate with the status table.
 * Input 			ofconn openflow connection
 * 					ofp_header pointer to the openflow header, the data is just behind the header, you can find the
 * 					payload by "pointer to header" + sizeof( struct ofp_header )
 * Output			1	means error in initialize the status table
 * 					0	means the pkt is successfully initialize the status table
 */
enum sperr sp_msg_init(struct ofconn *ofconn, const struct ofp_header *sph )
{
	VLOG_INFO("++++ pjq sp enter init procedure!\n");

	int i = 0; //inner use
	char * cursor = NULL;
	uint32_t len = 0 ;

	if( g_apps.islistinit == false )
	{
		ovs_list_init(&g_apps.appslist);
		g_apps.islistinit = true;
	}

	//alloc app
	struct CONTROLLAPP* app = xmalloc( sizeof(struct CONTROLLAPP) );
	struct sp_msg_init_st* pst =(struct sp_msg_init_st*) ( (char*)sph+sizeof( struct ofp_header));

	cursor = (char*)pst+sizeof( *pst );
    //VLOG_INFO("+++++lty: cursor=%s",cursor);

	VLOG_INFO("++++++pjq, sizeof struct CONTROLLAPP: %ld, sizeof struct ofp_header: %ld", sizeof(struct CONTROLLAPP),
              sizeof(struct ofp_header));

	//set appid
	app->appid = ntohl(pst->aid);
	VLOG_INFO("+++++++ pjq appid: %d", app->appid);

	struct CONTROLLAPP* tmp_app = NULL;
	LIST_FOR_EACH(tmp_app , node, &g_apps.appslist)
	{
		if( tmp_app->appid == app->appid)
		{
			VLOG_INFO("+++++ pjq sp init the same table, so return now ! -----\n");
			free(app);
			app = NULL;
			return 0;
		}
	}

	//alloc st table
	struct STATUS_TABLE* st = xmalloc( sizeof(*st) );
	//init hmap st_entrys
	hmap_init( &st->st_entrys );
	int loop_ct = ntohl(pst->counts);

    VLOG_INFO("+++++lty: st_loop_ct=%d,pst->counts=%d",loop_ct,pst->counts);
	//get & set match_bitmap
//	st->match_bitmap = ntohll(pst->mmp);
//    st->st_match = pst->st_match;
    st->st_match.field_id = ntohs(pst->st_match.field_id);
    st->st_match.offset = ntohs(pst->st_match.offset);
    st->st_match.len = ntohs(pst->st_match.len);

    VLOG_INFO("+++++ pjq st match, field id: %d, offset: %d, len: %d", st->st_match.field_id,
    		  st->st_match.offset, st->st_match.len);

    VLOG_INFO("+++++ pjq before init st, loop_ct: %d", loop_ct);
	if( loop_ct > 0 )
	{
		for( ; i < loop_ct ; i++)
			{
				struct ST_MATCH_ENTRY* sme = xmalloc( sizeof(*sme));
				sme->last_status = ntohl(*(uint32_t*)cursor);
				cursor = cursor+sizeof(uint32_t);
				len =ntohl(*(uint32_t*)cursor);
				char* data = xmalloc( len + 2 );
				data[len+1]='\0';
				data[len] ='\0';
				memcpy((void*)data,(void*)(cursor+sizeof(uint32_t)),len);
				sme->data = data;
				cursor = cursor+sizeof(uint32_t)+8;
				VLOG_INFO("++++ pjq add to st status is : %ld,data is %s \n",sme->last_status,sme->data);
				hmap_insert(&st->st_entrys,&sme->node,hash_string(sme->data,0));
			}
	}

	//cursor point to the stt and alloc stt
	struct STATUS_TRANZ_TABLE* stt = xmalloc( sizeof(*stt));
	ovs_list_init(&stt->stt_entrys);





    uint32_t stt_count = ntohl(*(uint32_t*)cursor);
	struct sp_msg_init_stt* stt_tmp = (struct sp_msg_init_stt*)(cursor+sizeof(uint32_t));


    char* test_msg = cursor + 4;
    struct ds s;
    ds_init(&s);
    ds_put_hex_dump(&s, test_msg, 96*7, 0, false);
    VLOG_INFO("++++++ pjq before init stt, msg: \n%s", ds_cstr(&s));
    ds_destroy(&s);
//    xsleep(10);

    i = 0;
	VLOG_INFO("++++++pjq before init stt, stt_count: %d", stt_count);
	VLOG_INFO("++++++pjq sizeof sp_msg_init_stt: %d", sizeof(stt_tmp));



	for( ; i < stt_count;i++)
	{
        test_msg = (char *)stt_tmp;
        ds_init(&s);
        ds_put_hex_dump(&s, test_msg, 96, 0, false);
        VLOG_INFO("++++++ pjq before init stt, i: %d, msg: \n%s", i, ds_cstr(&s));
        ds_destroy(&s);
		struct STT_MATCH_ENTRY* sttme = xmalloc( sizeof(*sttme) );
		VLOG_INFO("+++++++pjq sizeof sttme: %ld", sizeof(*sttme));
		VLOG_INFO("+++++++pjq sizeof struct sp_msg_init_stt: %ld", sizeof(struct sp_msg_init_stt));
		VLOG_INFO("+++++++pjq test_msg: %p", test_msg);

        stt_tmp->param_right_match.field_id = ntohs(stt_tmp->param_right_match.field_id);
        stt_tmp->param_right_match.offset = ntohs(stt_tmp->param_right_match.offset);
        stt_tmp->param_right_match.len = ntohs(stt_tmp->param_right_match.len);

        stt_tmp->param_left_match.field_id = ntohs(stt_tmp->param_left_match.field_id);
        stt_tmp->param_left_match.offset = ntohs(stt_tmp->param_left_match.offset);
        stt_tmp->param_left_match.len = ntohs(stt_tmp->param_left_match.len);

		sttme->cur_status = ntohl(stt_tmp->cur_status);
		sttme->oprator = ntohl(stt_tmp->oprator);
		sttme->param_left = ntohll(stt_tmp->param_left);
		sttme->param_left_match = stt_tmp->param_left_match;
		sttme->param_right = ntohll(stt_tmp->param_right);


		sttme->param_right_match = stt_tmp->param_right_match;
		sttme->last_status = ntohl(stt_tmp->last_status);
		VLOG_INFO("add to stt left param is %lu, right param is %lu,op : %d, last: %d next : %d \n",
				sttme->param_left,sttme->param_right,sttme->oprator,sttme->last_status,sttme->cur_status);
        VLOG_INFO("left param len: %d, right param len: %d", sttme->param_left_match.len, sttme->param_right_match.len);
		ovs_list_insert(&stt->stt_entrys,&sttme->node);
		stt_tmp++;
	}

	//cur point to the at and alloc at
	cursor = (char*)stt_tmp;
	struct ACTION_TABLE* at = xmalloc( sizeof(*at) );
	hmap_init(&at->at_entrys);
	struct sp_msg_init_at* at_tmp = (struct sp_msg_init_at* )cursor;
	loop_ct = ntohs(at_tmp->counts);
//	at->bitmap = ntohll(at_tmp->bitmap);
//    at->at_match = at_tmp->at_match;
    at->at_match.field_id = ntohs(at_tmp->at_match.field_id);
    at->at_match.offset = ntohs(at_tmp->at_match.offset);
    at->at_match.len = ntohs(at_tmp->at_match.len);

	VLOG_INFO("+++++ pjq at match, field id: %d, offset: %d, len: %d", at->at_match.field_id,
			  at->at_match.offset, at->at_match.len);


    test_msg = cursor;
    ds_init(&s);
    ds_put_hex_dump(&s, test_msg, 12, 0, false);
    VLOG_INFO("++++++ pjq before init at, msg: \n%s", ds_cstr(&s));
    ds_destroy(&s);

	cursor = cursor+sizeof(struct sp_msg_init_at);
	i = 0 ;
	VLOG_INFO("++++++pjq before init at, at_count: %d", loop_ct);


    VLOG_INFO("+++++lty: loop_ct=%d",loop_ct);
	for(i=0 ; i < loop_ct ; i++)
	{
	    VLOG_INFO("++++++ pjq in init at, i = %d", i);
		struct AT_MATCH_ENTRY* ame = xmalloc( sizeof(*ame));
		ame->act.actype = ntohl( ((struct SP_ACTION*)cursor)->actype);
		ame->act.acparam = ntohl(((struct SP_ACTION*)cursor)->acparam);
		ame->last_status = ntohl(*(uint32_t*)(cursor+sizeof( struct SP_ACTION )));
		len = ntohl(*(uint32_t*)(cursor+sizeof( struct SP_ACTION )+sizeof(uint32_t)));
		//alloc the data to store data string
		ame->data = xmalloc(len+2);
		ame->data[len + 1] = '\0';
		ame->data[len] = '\0';
		memcpy(ame->data,cursor+sizeof(struct SP_ACTION)+2*sizeof(uint32_t) , len);
		VLOG_INFO("+++ pjq add to at action type : %ld, action param : %ld , last status : %ld,data is %s \n",
				ame->act.actype,ame->act.acparam,ame->last_status,ame->data);
		hmap_insert( &at->at_entrys, &ame->node,hash_string(ame->data,0));
		cursor += sizeof(struct SP_ACTION)+ 2*sizeof(uint32_t)+8;
	}

	//add st stt at to appcontroll
	app->pat = at;
	app->pst = st;
	app->pstt = stt;

	// insert app into g_apps;
	ovs_list_insert(&(g_apps.appslist) , &(app->node));

	VLOG_INFO("++++++pjq return sp msg process ok");
	return SP_MSG_PROCESS_OK;


}

enum sperr sp_msg_st_mod(struct ofconn *ofconn, const struct ofp_header *sph)
{
	VLOG_INFO("+++ pjq enter sp st mod !\n");

	struct sp_msg_mod* pmsg = (char*)sph+sizeof(struct ofp_header);

	uint32_t aid = ntohl(pmsg->appid);

	if(g_apps.islistinit == false )
		return SP_MSG_PROCESS_ERROR;

	struct CONTROLLAPP* app = NULL;
	bool bfound = false;

	LIST_FOR_EACH(app , node, &g_apps.appslist)
	{
		if( app->appid == aid)
		{
			bfound = true;
			break;
		}
	}

	if( bfound == false )
		return SP_MSG_PROCESS_ERROR;
	struct STATUS_TABLE* st = app->pst;

	int count = ntohl(pmsg->count);

	VLOG_INFO("+++++++pjq st mod count: %d", count);

	char* cursor = (char*)pmsg+2*sizeof(uint32_t);

    int i = 0;
    uint32_t status_tmp = 0 ;
    uint32_t len_tmp = 0 ;
    char * data_tmp = NULL;

    for( ; i < count;i++){
        struct ST_MATCH_ENTRY* stmatch_tmp = NULL;

        int tmt_tmp = ntohl(*( int *)cursor);
        status_tmp = 0 ;
        len_tmp = 0;
        data_tmp= NULL;
        if( tmt_tmp == ENTRY_ADD )
        {
            //do add entry
            status_tmp = ntohl(*(uint32_t*)( cursor+sizeof(uint32_t)));
            len_tmp = ntohl(*(uint32_t*)( cursor+2*sizeof(uint32_t)));
            VLOG_INFO("+++++ len tmp: %d, status: %d", len_tmp, status_tmp);
            data_tmp = xmalloc(len_tmp+2);
            data_tmp[len_tmp+1] = '\0';
            data_tmp[len_tmp] = '\0';
//            for(int j = 0; j < len_tmp; j++) {
//                VLOG_INFO("++++++ lty data tmp %d : %d", j, data_tmp[j]);
//            }

            memcpy(data_tmp , cursor + 3*sizeof(uint32_t),len_tmp);

            struct ds s;
            ds_init(&s);
            ds_put_hex_dump(&s, data_tmp, len_tmp, 0, false);
            VLOG_INFO("++++++ lty data tmp \n%s", ds_cstr(&s));
            ds_destroy(&s);

			VLOG_INFO("++++++ pjq data tmp: %s, len tmp: %d", data_tmp, len_tmp);
//            if( hmap_first_with_hash(&(st->st_entrys),hash_string(data_tmp,0)) != NULL)
//            {
//                VLOG_INFO("++++ pjq BUG--CHECK find dup entry while adding !\n");
//                free(data_tmp);
//                data_tmp = NULL;
//                cursor =cursor+ 3*sizeof(uint32_t)+8; // 8 means value's length, if value's length is less than 8, pad to zero.
//                continue;
//            }
            stmatch_tmp = xmalloc(sizeof(*stmatch_tmp));
            stmatch_tmp->last_status = status_tmp;
            stmatch_tmp->data = data_tmp;
            VLOG_INFO("+++++ pjq st-mod  op is add , is %s ,  status is: %d\n",data_tmp,status_tmp);
            VLOG_INFO("+++++ lty st-mod  op is add , data_tmp is %d\n", hash_string(data_tmp,0));
            hmap_insert(&(st->st_entrys),&(stmatch_tmp->node),hash_string(data_tmp,0));
            cursor =cursor+ 3*sizeof(uint32_t)+8;

        }else if( tmt_tmp == ENTRY_UPDATE)
        {
            //do update
            status_tmp = ntohl(*(uint32_t*)( cursor+sizeof(uint32_t)));
            len_tmp = ntohl(*(uint32_t*)( cursor+2*sizeof(uint32_t)));
			VLOG_INFO("+++++ len tmp: %d, status: %d", len_tmp, status_tmp);
            data_tmp = xmalloc(len_tmp+2);
            data_tmp[len_tmp+1] = '\0';
            data_tmp[len_tmp] = '\0';
            memcpy(data_tmp , cursor+3*sizeof(uint32_t),len_tmp);
			VLOG_INFO("++++++ pjq data tmp: %s, len tmp: %d", data_tmp, len_tmp);
            stmatch_tmp = (struct ST_MATCH_ENTRY* )hmap_first_with_hash(&(st->st_entrys),hash_string(data_tmp,0));
            if( stmatch_tmp == NULL)
            {
                VLOG_INFO("+++ pjq BUG--CHECK can not find entry while update st!\n");
                free(data_tmp);
                data_tmp = NULL;
                cursor =cursor+ 3*sizeof(uint32_t)+8;
                continue;
            }
            VLOG_INFO("++++ pjq st-mod  op is update , data is %s , new status is: %ld\n",data_tmp,status_tmp);
            stmatch_tmp->last_status = status_tmp;
            cursor =cursor+ 3*sizeof(uint32_t)+8;

        }else if(tmt_tmp == ENTRY_DEL){
            //do del
            len_tmp = ntohl(*(uint32_t*)( cursor+2*sizeof(uint32_t)));
			VLOG_INFO("+++++ len tmp: %d", len_tmp);
            data_tmp = xmalloc(len_tmp+2);
            data_tmp[len_tmp+1] = '\0';
            data_tmp[len_tmp] = '\0';
            memcpy(data_tmp , cursor+3*sizeof(uint32_t),len_tmp);
			VLOG_INFO("++++++ pjq data tmp: %s, len tmp: %d", data_tmp, len_tmp);
            stmatch_tmp = (struct ST_MATCH_ENTRY* )hmap_first_with_hash(&(st->st_entrys),hash_string(data_tmp,0));
            if( stmatch_tmp == NULL)
            {
                VLOG_INFO("++++ pjq BUG--CHECK can not find entry while del st!\n");
                free(data_tmp);
                data_tmp = NULL;
                cursor =cursor+ 3*sizeof(uint32_t)+8;
                continue;
            }
            VLOG_INFO("++++ pjq st-mod  op is del , data is %s\n",data_tmp);
            hmap_remove(&(st->st_entrys),stmatch_tmp);
            cursor =cursor+ 3*sizeof(uint32_t)+8;

        }else
        {
            VLOG_INFO("++++ pjq BUG-CHECK! invalid st mode type!\n");
            return SP_MSG_PROCESS_ERROR;
        }

    }

    VLOG_INFO("++++ pjq leaving st mod done ok! \n");
    return SP_MSG_PROCESS_OK;

}

enum sperr sp_msg_at_mod(struct ofconn *ofconn, const struct ofp_header *sph)
{
	    printf("enter sp at mod !\n");

		struct sp_msg_mod* pmsg = (char*)sph+sizeof(struct ofp_header);
		uint32_t aid = ntohl(pmsg->appid);

		if(g_apps.islistinit == false )
			return SP_MSG_PROCESS_ERROR;

		struct CONTROLLAPP* app = NULL;
		bool bfound = false;

		LIST_FOR_EACH(app , node, &g_apps.appslist)
		{
			if( app->appid == aid)
			{
				bfound = true;
				break;
			}
		}

		if( bfound == false )
			return SP_MSG_PROCESS_ERROR;

		struct ACTION_TABLE* at = app->pat;

		uint32_t count = ntohl(pmsg->count);
		char* cursor = (char*)pmsg+2*sizeof(uint32_t);

        VLOG_INFO("+++++++pjq at mod count: %d", count);

		int i = 0;
		uint32_t status_tmp = 0 ;
		uint32_t len_tmp = 0 ;
		char * data_tmp = NULL;
		struct AT_MATCH_ENTRY* atmatch_tmp = NULL;
		struct SP_ACTION* sact_tmp = NULL;
        char * hash_test = NULL;
        char * hash_test_1 = NULL;
        int hash_cnt = 1;
        int hash_update = 2;
		for( ; i < count;i++){
            struct sp_msg_mod_at* at_tmp = NULL ;
            //struct sp_msg_mod_at* sact_tmp = NULL ;
            //struct SP_ACTION* sact_tmp = NULL;
            at_tmp = xmalloc(sizeof(*at_tmp));
            at_tmp = (struct sp_msg_mod_at*)(cursor) ;
            //sact_tmp = xmalloc(sizeof(*sact_tmp));
           // sact_tmp = (struct SP_ACTION*)(cursor) ; //lty try
			VLOG_INFO("++++++pjq in at mod, i = %d", i);

			int tmt_tmp = ntohl(at_tmp->type);

//			uint32_t tmt_tmp = *(uint32_t*)cursor;
			status_tmp = 0 ;
			len_tmp = 0;
			data_tmp= NULL;
            char I[2];
			if( tmt_tmp == ENTRY_ADD )
			{

				len_tmp = ntohl(at_tmp->len);
                VLOG_INFO("+++++lty: in add entry len_tmp = %d",len_tmp);
                data_tmp = xmalloc(len_tmp + 2);
                data_tmp[len_tmp+1] = '\0';
                data_tmp[len_tmp] = '\0';
                char* hash_data = xmalloc(len_tmp + 6);
                hash_data[len_tmp + 5] = '\0';
                hash_data[len_tmp + 4] = '\0';
//                memcpy(data_tmp ,at_tmp->value,len_tmp);
                memcpy(data_tmp , cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t),len_tmp);
                memcpy(hash_data , cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t),len_tmp);
                //hash_test_1 = hash_data;
				atmatch_tmp = xmalloc(sizeof(*atmatch_tmp));
//				atmatch_tmp->last_status = status_tmp;
				atmatch_tmp->last_status = ntohl(at_tmp->status);
				atmatch_tmp->act.actype = ntohl(at_tmp->act_type);
				atmatch_tmp->act.acparam = ntohl(at_tmp->act_param);
				atmatch_tmp->data = data_tmp;
                sprintf(I,"%d",atmatch_tmp->last_status);
                VLOG_INFO("+++++lty,test is : %d", hash_string(data_tmp,0));
                memcpy(hash_data + len_tmp, cursor+sizeof(struct SP_ACTION)+1*sizeof(uint32_t),4);
                if (i ==0)
                    hash_test = hash_data;
                if(i==1&&hash_data == hash_test)
                    VLOG_INFO("#####lty:hast TRUE");
                else if(i==1&&hash_data != hash_test)
                    VLOG_INFO("#####lty:hast FALSE");
                hash_test_1 = malloc(strlen(hash_data)+1);
                strcpy(hash_test_1, hash_data);
                strcat(hash_test_1,I);

               // VLOG_INFO("######lty: hash_test_1 's hash value = %d",  hash_string(hash_test_1,0));
                struct ds s;
                ds_init(&s);
                ds_put_hex_dump(&s, hash_data, len_tmp + 4, 0, false);
               // VLOG_INFO("++++++ lty hash data tmp \n%s", ds_cstr(&s));
                ds_destroy(&s);

				VLOG_INFO("++++ pjq at-mod  op is add , new data is %s , new status is: %d, new actype : %d , new actparam : %d \n",
						atmatch_tmp->data,atmatch_tmp->last_status,atmatch_tmp->act.actype,atmatch_tmp->act.acparam);
//				uint64_t p[1] = {at_tmp->value};
                VLOG_INFO("+++++lty before hmap insert,node hash value= %d", atmatch_tmp->node.hash);
				hmap_insert(&(at->at_entrys),&(atmatch_tmp->node),hash_string(hash_test_1, 0));

				VLOG_INFO("+++++pjq after hmap insert,hash_data= %s, hash value is : %d", hash_data,hash_string(hash_test_1, 0));
			    cursor =cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t)+8;
                //VLOG_INFO("at_tmp = %s",at_tmp->value);
//				at_tmp++;
                hash_cnt++;

			}else if( tmt_tmp == ENTRY_UPDATE)
			{       VLOG_INFO("+++++ lty: do update");
				//do update

				sact_tmp = (struct SP_ACTION*)(cursor+sizeof(uint32_t));

				status_tmp = ntohl(*(uint32_t*)( cursor+sizeof(uint32_t)+ sizeof(struct SP_ACTION)));
                sprintf(I,"%d",status_tmp);
                VLOG_INFO("+++++lty: in entry update status tmp = %d",status_tmp);
				len_tmp = ntohl(*(uint32_t*)( cursor+sizeof(struct SP_ACTION)+2*sizeof(uint32_t)));
                VLOG_INFO("+++++lty: in entry update len tmp = %d",len_tmp);
				data_tmp = xmalloc(len_tmp+2);
				data_tmp[len_tmp+1] = '\0';
				data_tmp[len_tmp] = '\0';
				char *hash_data = xmalloc(len_tmp + 6);
                hash_data[len_tmp + 5] = '\0';
                hash_data[len_tmp + 4] = '\0';
                memcpy(hash_data , cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t),len_tmp);
                hash_test_1 = malloc(strlen(hash_data)+1);
                strcpy(hash_test_1, hash_data);
                strcat(hash_test_1,I);

                VLOG_INFO("######lty: hash_test_1 's hash value = %d",  hash_string(hash_test_1,0));
                VLOG_INFO("+++++lty before atmatch_tmp,hash_data = %s, hash value is : %d", hash_data, hash_string(hash_data, 0));
                atmatch_tmp = (struct AT_MATCH_ENTRY* )hmap_first_with_hash(&(at->at_entrys),hash_string(hash_test_1,0));


                VLOG_INFO("+++++ lty before update, status = %d, acparam = %d, actype = %d",atmatch_tmp->last_status,atmatch_tmp->act.acparam,atmatch_tmp->act.actype);
				if( atmatch_tmp == NULL)
				{
					VLOG_INFO(" +++ pjq BUG--CHECK can not find entry while update Action Table!\n");
					free(hash_data);
					hash_data=NULL;
					cursor = cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t)+8;
					continue;
				}
				VLOG_INFO("+++ at-mod  op is update , data is %s , new status is: %d,new actype : %d , new actparam : %d\n",
						data_tmp,status_tmp,ntohl(sact_tmp->actype),ntohl(sact_tmp->acparam));
				atmatch_tmp->last_status = status_tmp;
				atmatch_tmp->act.acparam = ntohl(sact_tmp->acparam);
				atmatch_tmp->act.actype = ntohl(sact_tmp->actype);

				cursor = cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t)+8;
                hash_update--;
			}else if(tmt_tmp == ENTRY_DEL){
				//do del

                status_tmp = ntohl(*(uint32_t*)( cursor+sizeof(uint32_t)+ sizeof(struct SP_ACTION)));
                sprintf(I,"%d",status_tmp);
				len_tmp = ntohl(*(uint32_t*)( cursor+sizeof(struct SP_ACTION)+2*sizeof(uint32_t)));
				data_tmp = xmalloc(len_tmp+2);
				data_tmp[len_tmp+1] = '\0';
				data_tmp[len_tmp] = '\0';

                char *hash_data = xmalloc(len_tmp + 6);
                hash_data[len_tmp + 5] = '\0';
                hash_data[len_tmp + 4] = '\0';

                memcpy(hash_data , cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t),len_tmp);

                hash_test_1 = malloc(strlen(hash_data)+1);
                strcpy(hash_test_1, hash_data);
                strcat(hash_test_1,I);
                atmatch_tmp = (struct AT_MATCH_ENTRY* )hmap_first_with_hash(&(at->at_entrys),hash_string(hash_test_1,0));
				if( atmatch_tmp == NULL)
				{
					VLOG_INFO("+++ pjq BUG--CHECK can not find entry while del Action Table!\n");
					free(data_tmp);
					data_tmp=NULL;
					cursor = cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t)+8;
					continue;
				}
				VLOG_INFO("++++ pjq at-mod  op is del , data is %s \n",data_tmp);
				hmap_remove(&(at->at_entrys),&(atmatch_tmp->node));
                cursor = cursor+sizeof(struct SP_ACTION)+3*sizeof(uint32_t)+8;
			}else
			{
				VLOG_INFO("++++ pjq BUG-CHECK! invalid at mode type!\n");
				return SP_MSG_PROCESS_ERROR;
			}

		}

		VLOG_INFO("++++ pjq leaving at mod !\n");
		return SP_MSG_PROCESS_OK;


}

/*
 * Description		called in handle_openflow__ procedure, the function first check the msg type
 * 					if it is spmsg , then process the msg else it returns . The error of sperror
 * 					type will not pass out, it will only be used by inner function to do self-check.
 * Input 			ofconn openflow connection
 * 					ofpbuf the point to the openflow msg
 * Output			1	means the pkt should be handled by original openflow procedure
 * 					0	means the pkt is successfully handled by sp module
 */
int sp_msg_decode(struct ofconn *ofconn, const struct ofpbuf *msg)
{
		const struct ofp_header *oh = msg->data;
	    enum sperr error;

	    //VLOG_INFO("+++++ pjq In sp_msg_decode! type is %d \n",oh->type);

	    VLOG_INFO("+++++++ pjq sp msg type is %d-----\n",oh->type);

	    switch( oh->type )
	    {
	    case OFPTYPE_SP_TABLE_CREATE:
	    	error = sp_msg_init(ofconn,oh);
	    	break;
	    case OFPTYPE_SP_ST_ENTRY_MOD:
	    	error = sp_msg_st_mod(ofconn,oh);
	    	break;
	    case OFPTYPE_SP_AT_ENTRY_MOD:
	    	error = sp_msg_at_mod(ofconn,oh);
	    	break;
	    default:
	    	//VLOG_INFO("++++ pjq non-sp msg return to openflow!\n");
	    	return -1 ;
	    }

	    if( error == 0 )
	    {
	    	VLOG_INFO("++++++ pjq successfully handle the sp msg\n");
	    	return 0;
	    }else
	    {
	    	VLOG_INFO("+++++ pjq ###BUG-CHECK### fail to  handle the sp msg\n");
	    	return -1;
	    }

}
