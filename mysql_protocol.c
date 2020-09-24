//
// Created by liuyu on 2020/8/20.
//

/*
 * return -1  _Global.pcap_file_hpp = NULL
 * */
#include "mysql_protocol.h"

struct Global _Global;

int main(int argc,char* argv[])
{
    init_Global();   //init Global param
    getopt_parse(argc,argv);  //getopt parse (result in Global)

    if(_Global.save_file_name != NULL)
        freopen(_Global.save_file_name, "w", stdout);

    if((_Global.pcap_file_hpp=pcap_open_offline(_Global.open_file_name,_Global.pcap_error_info) )== NULL)        //open Pcap_file
    {
        printf("\nError: Unable to open the pcap file:%s %s\n", _Global.open_file_name, _Global.pcap_error_info); //打印文件的错误信息
        usage();
        return -1;
    }
    _Global.file = pcap_file(_Global.pcap_file_hpp);
    if(_Global.mode == mysql_protocol_mode)
    {
        mysql_protocol_parse();
        Meter_exit();
    }

    if(_Global.save_file_name != NULL)
        freopen("/dev/tty", "w", stdout);
    if(_Global.save_file_name != NULL)
        printf("Data in the %s\n", _Global.save_file_name);
    return 0;
}

static void init_Global()
{
    memset(&_Global,0,sizeof(Global));  //memeset _Global
    _Global.session_count = 1;
    _Global.handshak_flag = 0;
    _Global.statement_id = (u_int16_t *)malloc(1024*1024*2);
    memset(_Global.statement_id,0,1024*1024*2);
    _Global.save_file_name = NULL;
    _Global.mem_flag = 0;
    _Global.last_1_flag = 0;
    _Global.last_2_flag = 0;
    _Global.test = 0;
}

static void getopt_parse(int argc,char* argv[])
{
//    if (argc < 3)
//    {
//        usage(argv[0]);
//        return;
//    }
    _Global.open_file_name = argv[argc - 1];
    int opt;
    struct option opt_choose[] =
            {
                    {"mysql",0,NULL,'m'},
                    {"save",1,NULL,'s'},
            };
    while ((opt = getopt_long(argc,argv,"ms:",opt_choose,NULL))!=-1)
    {
        switch (opt)
        {
            case 'm':
                _Global.mode = mysql_protocol_mode;
                break;
            case 's':
                _Global.save_file_name = optarg;
                break;
            default:
                //usage(optarg);
                break;
        }
    }
}

static void usage()
{
    printf("-m          --mysql  <file_name>        parse mysql_protocol\n");
    printf("-s          --save  <save_file_name>    save the info of pcap_file\n");
}

static void mysql_protocol_parse()
{
    _Global.sestion_hash = hash_table_new();
    pcap_loop(_Global.pcap_file_hpp,0,mysql_protocol_parse_cb,NULL);
    enum_sestion();
}

static void mysql_protocol_parse_cb(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
//    printf("Session seq : %d       ",_Global.test);
//    _Global.test ++;
    Ip_head * ip_head = (Ip_head*)(pkt_data + sizeof(Fram_head)); //decide Protocol
    if (ip_head->Protocol != 0x06)
        return; //如果不是tcp就返回
    Tcp_head * tcp_head = (Tcp_head*)(pkt_data + sizeof(Fram_head) + sizeof(Ip_head));
    if(ntohs(tcp_head->Src_port) != 3306 && ntohs(tcp_head->Dst_port) != 3306)   //not 3306 not do
        return;
    /*server handshak ues this choos*/
    if (tcp_head->Opt == 0x02)
    {
        return;
    }
    else if (tcp_head->Opt == 0x12)
    {
        _Global.set_syn++;
        return;
    }
    else if (_Global.set_syn && tcp_head->Opt==0x10)
    {
        _Global.set_syn--;
        _Global.handshak_flag = 1;
        return;
    }
    /*-----------------------------*/
    int off = (14 + (ip_head->Ip_vision_and_len & 0x0f) * 4 + (tcp_head->Head_len >> 4) * 4) + 3;   //seq_id
    _Global.real_len = off -3;
    _Global.total_len = header->caplen;
    u_int32_t len = (*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff;
    if((ntohs(ip_head->Total_len)-(ip_head->Ip_vision_and_len & 0x0f) * 4- (tcp_head->Head_len >> 4) * 4) <=0) //处理有padding值的情况,长度从ip数据报开始计算就可以解决
    {
      return;
    }
    if((header->caplen - (off - 3)) <= 0 )   //kill ack(no info)
        return;
    char key[CHARSIZE];
    get_key(tcp_head,ip_head,key); //get key and free;

    if(hash_table_get(_Global.sestion_hash,key)==NULL)
    {
        Sestion_Stat * tem =(Sestion_Stat*) malloc(sizeof(Sestion_Stat));
        memset(tem,0,sizeof(Sestion_Stat));
        /*save five tip*/
        tem->proto = 0x06;
        inet_ntop((int)AF_INET, (const void *)&(ip_head->Src_ip), (tem->Src_ip), 16);
        inet_ntop((int)AF_INET, (const void *)&(ip_head->Dst_ip), (tem->Dst_ip), 16);
        tem->Src_port = ntohs(tcp_head->Src_port);
        tem->Dst_port = ntohs(tcp_head->Dst_port);
        Fram_head * fram_head = (Fram_head*)(pkt_data); //get mac
        memcpy(tem->S_mac,fram_head->S_mac,6);
        memcpy(tem->D_mac,fram_head->D_mac,6);
        tem->session_id = _Global.session_count;
        printf("Session id : %d       ",tem->session_id);
        /*start_____end*/
        memcpy(&tem->begin, &header->ts, sizeof(struct timeval));//start time
        tem->total_packet=1; //single session packet
        tem->total_size =header->len;
        if(ntohs(tcp_head->Src_port) < ntohs(tcp_head->Dst_port))  //server
        {

            printf("Server :  ");
            if(pkt_data[off] == 0 )
            {
                _Global.handshak_flag = 1;
                handshak_parse_server(pkt_data,off);
            }
            else if((pkt_data[off+1] == 0x00 || pkt_data[off+1] == 0xfe) && header->caplen - (off - 3) -4 == len )
            {
                ok_packet_parse(pkt_data,off);
            }
            else if((pkt_data[off+1] == 0x00 || pkt_data[off+1] == 0xfe) && header->caplen - (off - 3) -4 > len && len == 12)
            {
                prepare_ok_packet_parse(pkt_data,off);
            }
            else if(pkt_data[off+1] == 0xff)
            {
                error_packet_parse(pkt_data,off);
            }
            else //result set
            {
                result_set_parse(pkt_data,off);
            }
        }
        else   //client
        {
            printf("Client :  ");
            if(_Global.handshak_flag && pkt_data[off]== 1)
            {
                handshak_parse_client(pkt_data,off);
                _Global.handshak_flag = 0;
            }
            else
            {
                Command_Phase(pkt_data,off+1);
            }
//            printf("Session : id %d \n",tem->session_id);
//            printf("%02x\n",pkt_data[off]);
        }
        hash_table_put2(_Global.sestion_hash,key,tem,NULL); //no free
        _Global.session_count++;
    }
    else
    {
        if(_Global.mem_flag ==1)
        {

            if(_Global.last_1_flag)
            {
                _Global.last[1]=pkt_data[off - 3];
                _Global.last[2]=pkt_data[off - 2];
                u_int32_t yy=*((u_int32_t*)(_Global.last));
                off += yy + 3;
                _Global.last_1_flag = 0;
                _Global.row_count++;
            }
            else if(_Global.last_2_flag)
            {
                _Global.last[3]=0x00;
                _Global.last_2_flag = 0;
                u_int32_t yy=*((u_int32_t*)(_Global.last));
                off += yy + 2;
                _Global.row_count++;
            }
            else if(_Global.tem_len>header->caplen - _Global.real_len)
            {
                printf("Total len is %d need skip %u\t",header->caplen-_Global.real_len,_Global.tem_len);
                _Global.tem_len -= (header->caplen-_Global.real_len);
                printf("last should skip %u in next\n",_Global.tem_len);
                _Global.row_count++;
                return;
            }
            else
            {
                off += _Global.tem_len;
                printf("Total len is %d need skip %u\t",header->caplen-_Global.real_len,_Global.tem_len);
                u_int32_t first = ((*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff);
                printf("next need %u last is %u\t",first,header->caplen-1-off);
                _Global.tem_len = first-header->caplen+off+1;
//            pkt_data + off - 3
                _Global.mem_flag = 1;
                _Global.row_count++;
//              if(((*(u_int32_t *) (pkt_data + off - 3 + _Global.tem_len)) & 0x00ffffff) > header->caplen - _Global.real_len)
//                return;
            }
        }
        Sestion_Stat * tem=hash_table_get(_Global.sestion_hash,key);
        tem->total_packet++;
        tem->total_size += header->len;
        memcpy(&tem->end, &header->ts, sizeof(struct timeval));//updata end time
        printf("Session id : %d       ",tem->session_id);

        if(ntohs(tcp_head->Src_port) < ntohs(tcp_head->Dst_port))  //server
        {
            printf("Server :  ");
            if(_Global.handshak_flag && pkt_data[off]== 0)
            {
                handshak_parse_server(pkt_data,off);
            }
            else if((pkt_data[off+1] == 0x00 || pkt_data[off+1] == 0xfe) && header->caplen - (off - 3) -4 == len)
            {
                ok_packet_parse(pkt_data,off);
            }
            else if((pkt_data[off+1] == 0x00 || pkt_data[off+1] == 0xfe) && header->caplen - (off - 3) -4 > len && _Global.mem_flag != 1)
            {
                prepare_ok_packet_parse(pkt_data,off);
            }
            else if(pkt_data[off+1] == 0xff)
            {
                error_packet_parse(pkt_data,off);
            }
            else //result set
            {
                result_set_parse(pkt_data,off);
            }
        }
        else   //client
        {
            printf("Client :  ");
            if(_Global.handshak_flag && pkt_data[off]== 1)
            {
                handshak_parse_client(pkt_data,off);
                _Global.handshak_flag = 0;
            }
            else
            {
                Command_Phase(pkt_data,off+1);
            }
        }
    }
}

static void handshak_parse_server(const u_char* pkt_data,int off)  //off is arrive Packet number
{
    printf("server handshak\n");
    printf("\tVersion : ");
    int version_set = 2;
    while((pkt_data[off + version_set]) != 0x00)
    {
        printf("%c",pkt_data[off + version_set]);
        version_set++;
    }
    printf("       ");

    version_set += 32;
    while((pkt_data[off + version_set]) != 0x00)
    {
        version_set++;
    }
    version_set++;
    printf("Auth plugin : ");
    while((pkt_data[off + version_set]) != 0x00)
    {
        printf("%c",pkt_data[off + version_set]);
        version_set++;
    }
    printf("\n");
}

static void prepare_ok_packet_parse(const u_char* pkt_data,int off)
{
    printf("prepare_ok_packet_parse\n");
//    int ora_off = off;
    u_int32_t ok_len = (*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff;

    if(ok_len>_Global.real_len)    //Defense for packet is unnormal
        return;
//    printf("ok packet\n");  //off is pointed to seq num
    u_int32_t yy = (*(u_int32_t *) (pkt_data + off+2));
    if(yy > 65535)    //Defense for packet is unnormal
        return;

    printf("\tstatement_id : %u",yy);
    printf("     num_columns : %hu",(*(u_int16_t *) (pkt_data + off + 6)));
    _Global.num_params = (*(u_int16_t *) (pkt_data + off + 8));
    _Global.statement_id[yy] = (*(u_int16_t *) (pkt_data + off + 8));
    printf("     num_params : %hu",(*(u_int16_t *) (pkt_data + off + 8)));
    printf("     warning_count : %hu",(*(u_int16_t *) (pkt_data + off + 11)));
    printf("\n");
    off += ok_len + 4;
    while (1)
    {
        ok_len = (*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff;
        if(ok_len>_Global.real_len)    //Defense for packet is unnormal
            return;
        if(pkt_data[off + 1] == 0xfe && ok_len <= 8)
            break;
        show_filed_info(pkt_data,off + 2);
        off +=  ok_len + 4;
    }
}
static void ok_packet_parse(const u_char* pkt_data,int off)
{
    u_int16_t status_flags;
//    int ora_off = off;
    u_int32_t ok_len = (*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff;

    if(ok_len>_Global.real_len)    //Defense for packet is unnormal
        return;

    printf("ok packet\n");  //off is pointed to seq num
    off++;
    //           point to       int<1> 	header 	[00] or [fe] the OK packet header
    off++;
              //point to first byte of int<lenenc> 	affected_rows 	affected rows
    printf("\tAffected Rows : ");
    int tem_off=0;
    u_long limit = int_lenenc_parse(pkt_data,off,ok_len,&tem_off);
    off += tem_off ;
    printf("%lu",limit);
    off ++;   //          point to first byte of int<lenenc> 	last_insert_id 	last insert-id

    int_lenenc_parse(pkt_data,off,ok_len,&tem_off);
    off += tem_off;
    off ++;   //          point to next byte;
    if (_Global.client_cap & CLIENT_PROTOCOL_41)
    {
        //int<2> 	status_flags 	Status Flags
        //int<2> 	warnings 	number of warnings
        status_flags = *((u_int16_t*)(pkt_data+off));
        u_int16_t warnings = status_flags = *((u_int16_t*)(pkt_data+off+2));
        printf("       Server Status : %0x    Warning  %d",status_flags,warnings);
        off += 4;
    }
    else if (_Global.client_cap & CLIENT_TRANSACTIONS)
    {
        //int<2> 	status_flags 	Status Flags
        printf("CLIENT_TRANSACTIONS");
        status_flags = *((u_int16_t*)pkt_data+off);
        printf("%0x",status_flags);
        off += 2;
    }

//    if (_Global.client_cap & CLIENT_SESSION_TRACK)
//    {
//        printf("CLIENT_SESSION_TRACK");
//        int tem_off=0;
//        u_long limit = int_lenenc_parse(pkt_data,off,ok_len,&tem_off);
//        off += tem_off + 1;
//        int i;
//        for(i=0;i<limit;i++)
//        {
////            printf("%c",pkt_data[off+i]);
//        }
//        off += limit;  //point to next byte
////        string<lenenc> 	info 	human readable status information
//        if (status_flags & 0x4000)
//        {
//            printf("0x4000");
//            int tem_off;
//            u_long limit = int_lenenc_parse(pkt_data,off,ok_len,&tem_off);
//            off += tem_off + 1;
//            int i;
////            for(i=0;i<limit;i++)
////            {
////                printf("%c",pkt_data[off+i]);
////            }
//            off += limit;  //point to next byte
////            string<lenenc> 	session_state_changes 	session state info
//        }
//    }
//    else
//    {
//        for(;off-ora_off<=ok_len;off++)
//        {
//            printf("%c",pkt_data[off]);
//        }
////        string<EOF> 	info 	human readable status information
//    }

    printf("\n");
}
/*len is 3 byte value*/
/*off if must point to the first byte*/
/*pkt_data is packet content*/
/*tem_off is return offset*/
/*return is pointed to end of the lenenc byte*/     //if you want to go on tem_off ++
u_long int_lenenc_parse(const u_char* pkt_data,int off,u_int32_t len,int* tem_off)  //return the size of lenenc  (return tem_off offset)
{
    (*tem_off) = 0;
    u_long lenenc_value;
    if(pkt_data[off] <251)
    {
        lenenc_value = (0x00000000000000ff & (u_long)pkt_data[off]);
    }
    else if(pkt_data[off] == 0xfc)
    {
        lenenc_value = (0x000000000000ffff & (u_long)pkt_data[off+1] & (u_long)pkt_data[off+2]<<8);
        (*tem_off) += 2;
    }
    else if(pkt_data[off] == 0xfd)
    {
        lenenc_value = (0x0000000000ffffff & (u_long)pkt_data[off+1] & (u_long)pkt_data[off+2]<<8 & (u_long)pkt_data[off+3]<<16);
        (*tem_off )+= 3;
    }
    else if(pkt_data[off] == 0xfe && len > 8)
    {
        lenenc_value = (0xffffffffffffffff & (u_long)pkt_data[off+1] & (u_long)pkt_data[off+2]<<8 & (u_long)pkt_data[off+3]<<16 &  (u_long)pkt_data[off+4]<<24 & (u_long)pkt_data[off+5]<<32 &  (u_long)pkt_data[off+6]<<40 &  (u_long)pkt_data[off+7]<<48 & (u_long)pkt_data[off+8]<<56 );
        (*tem_off) += 8;
    }
    else
    {
        printf("EOF packet");
    }
    return lenenc_value;
}

static void error_packet_parse(const u_char* pkt_data,int off)
{
    printf("error packet\n");
    int tem = 0;//mark EOF
    u_int32_t error_len = (*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff;
    tem +=2;
    off += 2;  //point to error_code first byte
    u_int16_t error_code = *((u_int16_t*)(pkt_data + off));
    printf("\terror : %hu        ",error_code);
    off += 2; //point to error_code down behind byte
    tem +=2;
    if(_Global.client_cap & CLIENT_PROTOCOL_41 )
    {
        printf("SQL stat  :  ");
        int i;
        for(i=0;i<6;i++)
        {
          printf("%c",pkt_data[off + i]);
        }
        off += 6;
        tem += 6;
    }
    printf("\n\tError message :  ");
    int i;
    for(i=0;tem<=error_len;i++)
    {
        if(pkt_data[off + i] == 0x0a)
        {
            printf("\\n");
        }
        else
            printf("%c",pkt_data[off + i]);
        tem++;
    }
    printf("\n");
}

static void result_set_parse(const u_char* pkt_data,int off) {
    _Global.type_choose_count = 0;  //reset choose count
    u_int32_t first = (*(u_int32_t *) (pkt_data + off - 3)) & 0x00ffffff;
    if (first == 1) {
        _Global.type_choose = (u_char*)malloc(_Global.num_params);
        u_int8_t Number_of_fields = pkt_data[off + 1];
        _Global.num_params = Number_of_fields;    //record num_params info
        int count = 0;
        off += 5;
        int tem = 0;
        printf("Number_of_field  is   %d    Result is\n",Number_of_fields);
        while (1)
        {
            u_int32_t c =(*(u_int32_t *) (pkt_data + off + tem - 3 ))& 0x00ffffff;
            _Global.packet_num = pkt_data[off + tem];
            if(pkt_data[off + tem + 1] == 0xfe && c <= 8)
                break;
            if(count == Number_of_fields)
                break;
            int d = show_filed_info (pkt_data,tem + off + 2);
            _Global.type_choose[_Global.type_choose_count] = pkt_data[tem + off + 2 + d];
            _Global.type_choose_count ++;
            tem += (((*(u_int32_t *) (pkt_data + off + tem - 3 ))& 0x00ffffff) + 4);
            count++;
        }
        int rowoff = 0;
        u_int32_t len = 0 ;

        len = ((*(u_int32_t *) (pkt_data + off + tem - 3 ))& 0x00ffffff);
        if(pkt_data[off + tem + 1] == 0xfe &&  len<=8)
            rowoff += len + 4;
        u_int row_count = 0;
        _Global.row_count = 0;
        while(1)
        {
            u_int8_t filed_count = 0;
            len = ((*(u_int32_t *) (pkt_data + off + tem + rowoff - 3 ))& 0x00ffffff);
            if(_Global.total_len - off - tem - rowoff  < len )  //last len
            {
                _Global.mem_flag = 1;
                _Global.tem_len = len - (_Global.total_len - off - tem - rowoff) + 1;
//                _Global.tem_mem = (u_char*)malloc(len+4);
//                _Global.now_mem = _Global.total_len - off - tem - rowoff + 3;
//                memcpy(_Global.tem_mem,pkt_data + off + tem + rowoff - 3,_Global.now_mem);
                printf("\t\tprotocol total len is %u packet to long %u in next",len,_Global.tem_len);
                break;
//                for(i=0;i<_Global.total_len - off - tem - rowoff + 4;i++)
//                {
//                    printf("%02x ",_Global.tem_mem[i]);
//                }
             //store
            }
            _Global.packet_num = pkt_data[off + tem + rowoff];
            if(pkt_data[off + tem + rowoff +  1] == 0xfe &&  len<=8)
            {
              printf("\tTotal row : %u",row_count);
              break;
            }
            int filed_off = 0;
            if(len <= 1)
                break;
            if(pkt_data[off + tem + rowoff + filed_off + 1] == 0x00 && len>1)
            {}
            else
                printf("\t\tRow info : ");
            int prepare_off = 3;
            _Global.get_count = 0;
            while (1)
            {
                if(pkt_data[off + tem + rowoff + filed_off + 1] == 0x00 && len>1)  //prepare stmt
                {
                    printf("\t");
                    //   printf("%0x",pkt_data[off + tem + rowoff + filed_off + 1]);
                    prepare_off +=  prepare_choose_type(pkt_data,off + tem + rowoff + prepare_off);
                    _Global.get_count ++;
                    if(_Global.get_count >= _Global.num_params)
                    {
                        break;
                    }
                    if(prepare_off >= len)
                    {
                        break;
                    }
                }
                else                                                    //normal stmt
                {
                    int i;
                    //   printf("%0x",pkt_data[off + tem + rowoff + filed_off + 1]);
                    int op = 0;
                    u_long liuyu_temp = int_lenenc_parse(pkt_data,off + tem + rowoff + filed_off + 1,10,&op);
                    for(i=0;i<liuyu_temp;i++)
                    {
                        printf("%c",pkt_data[off + tem + rowoff  + filed_off+ 2 + i + op]);
                    }
                    filed_count ++;
                    if(filed_count >= Number_of_fields)
                    {
                        break;
                    }
                    filed_off += pkt_data[off + tem + rowoff + filed_off + 1] + 1 + op;
                    printf("\t  ");
                }

            }
//
            printf("\n");
            row_count++;
            _Global.row_count++;
            rowoff += len + 4;
        }
        printf("\n");
    }
    else if(first != 1 && pkt_data[off] ==0x01 && _Global.mem_flag == 0 ){
        int tem = 0;
        printf("Filed list Responds :  \n");
        while (1)
        {
            u_int32_t c =(*(u_int32_t *) (pkt_data + off + tem - 3 ))& 0x00ffffff;
            _Global.packet_num = pkt_data[off];
            if(c>_Global.real_len)    //Defense for packet is unnormal
                break;
            if(pkt_data[off + tem + 1] == 0xfe && c <= 8)
                break;
            show_filed_info(pkt_data,tem + off + 2);
            tem += (((*(u_int32_t *) (pkt_data + off + tem - 3 ))& 0x00ffffff) + 4);
        }
      //  pkt_data[off - 1];  //catalog len
    }
    else if (_Global.packet_num  == _Global.packet_num + 1 && _Global.client_command_mode == Query_client )
    {
        printf("big result\n");
    }
    else if (pkt_data[off]  == (u_int8_t)(_Global.packet_num + 2) && _Global.client_command_mode == Prepare_client && pkt_data[off+1]==0x00 && first>8)
    {
        printf("big result for prepare\n");
        int rowoff = 0;
        u_int32_t len = 0 ;
        len = ((*(u_int32_t *) (pkt_data + off - 3 ))& 0x00ffffff);
        int c = 0;
        while(1)
        {

            if(_Global.total_len - off -  rowoff + 3 == 1)
            {
                _Global.last_1_flag = 1;
                _Global.last[0]=pkt_data[off +  rowoff - 3];
                break;
            }
            if(_Global.total_len - off -  rowoff + 3 == 2)
            {
                _Global.last_2_flag = 1;
                _Global.last[0]=pkt_data[off +  rowoff - 3];
                _Global.last[1]=pkt_data[off +  rowoff - 2];
                break;
            }
            u_int8_t filed_count = 0;
            len = ((*(u_int32_t *) (pkt_data + off +  rowoff - 3 ))& 0x00ffffff);

            if(pkt_data[off + rowoff +  1] == 0xfe &&  len<=8)
            {
              printf("\tTotal row : %u",_Global.row_count);
              _Global.mem_flag = 0;
              _Global.tem_len = 0;
              break;
            }

            if(_Global.total_len - off -  rowoff  <= len )  //last len
            {
                _Global.mem_flag = 1;
                _Global.tem_len = len - (_Global.total_len - off -  rowoff) +1;
                printf("\n\tprotocol total len is %u packet to long %u in next\n",len,_Global.tem_len);
                if(c==0)
                {
                    _Global.packet_num ++;
                }
                break;
            }

            if(_Global.total_len - off -  rowoff  == len + 1 )  //last len
            {
                _Global.tem_len = 0;
                break;
            }
            _Global.packet_num = pkt_data[off +  rowoff];

            int filed_off = 0;
            if(len <= 1)
                break;
            if(pkt_data[off +  rowoff + filed_off + 1] == 0x00 && len>1)
            {}
            else
                printf("\t\tRow info : ");
            int prepare_off = 3;
            _Global.get_count = 0;
            while (1)
            {
                if(pkt_data[off + rowoff + filed_off + 1] == 0x00 && len>1)  //prepare stmt
                {
                    printf("\t");
                    //   printf("%0x",pkt_data[off + tem + rowoff + filed_off + 1]);
                    prepare_off +=  prepare_choose_type(pkt_data,off +  rowoff + prepare_off);
                    _Global.get_count ++;
                    if(_Global.get_count >= _Global.num_params)
                    {
                        break;
                    }
                    if(prepare_off >= len)
                    {
                        break;
                    }
                }
                else                                                    //normal stmt
                {
                    int i;
                    //   printf("%0x",pkt_data[off + tem + rowoff + filed_off + 1]);
                    for(i=0;i<pkt_data[off +  rowoff + filed_off + 1];i++)
                    {
                        printf("%c",pkt_data[off +  rowoff  + filed_off+ 2 + i]);
                    }
                    filed_count ++;
                    if(filed_count >= _Global.num_params)
                    {
                        break;
                    }
                    filed_off += pkt_data[off +  rowoff + filed_off + 1] + 1 ;
                    printf("\t  ");
                }

            }
//
            printf("\n");
            rowoff += len + 4;
            _Global.row_count++;
            c++;
        }
        printf("\n");

    }
    else
    {
        printf("Responsd  the   %d  connect to the %d  last  %d",_Global.packet_num++,_Global.packet_num-1,_Global.tem_len);
        printf("\n");
    }
}

static void  choose_type(const u_char* pkt_data,int off)
{
    switch (pkt_data[off]) {
        case 0x00:
            printf("FIELD_TYPE_DECIMAL");
            break;
        case 0x01:
            printf("FIELD_TYPE_TINY");
            break;
        case 0x02:
            printf("FIELD_TYPE_SHORT");
            break;
        case 0x03:
            printf("FIELD_TYPE_LONG");
            break;
        case 0x04:
            printf("FIELD_TYPE_FLOAT");
            break;
        case 0x05:
            printf("FIELD_TYPE_DOUBLE");
            break;
        case 0x06:
            printf("FIELD_TYPE_NULL");
            break;
        case 0x07:
            printf("FIELD_TYPE_TIMESTAMP");
            break;
        case 0x08:
            printf("FIELD_TYPE_LONGLONG");
            break;
        case 0x09:
            printf("FIELD_TYPE_INT24");
            break;
        case 0x0a:
            printf("FIELD_TYPE_DATE");
            break;
        case 0x0b:
            printf("FIELD_TYPE_TIME");
            break;
        case 0x0c:
            printf("FIELD_TYPE_DATETIME");
            break;
        case 0x0d:
            printf("FIELD_TYPE_YEAR");
            break;
        case 0x0e:
            printf("FIELD_TYPE_NEWDATE");
            break;
        case 0x0f:
            printf("FIELD_TYPE_VARCHAR (new in MySQL 5.0)");
            break;
        case 0x10:
            printf("FIELD_TYPE_BIT (new in MySQL 5.0)");
            break;
        case 0xf6:
            printf("FIELD_TYPE_NEWDECIMAL (new in MYSQL 5.0");
            break;
        case 0xf7:
            printf("FIELD_TYPE_ENUM");
            break;
        case 0xf8:
            printf("FIELD_TYPE_SET");
            break;
        case 0xf9:
            printf("FIELD_TYPE_TINY_BLOB");
            break;
        case 0xfa:
            printf("FIELD_TYPE_MEDIUM_BLOB");
            break;
        case 0xfb:
            printf("FIELD_TYPE_LONG_BLOB");
            break;
        case 0xfc:
            printf("FIELD_TYPE_BLOB");
            break;
        case 0xfd:
            printf("FIELD_TYPE_VAR_STRING");
            break;
        case 0xfe:
            printf("FIELD_TYPE_STRING");
            break;
        case 0xff:
            printf("FIELD_TYPE_GEOMETRY");
            break;
        default:
            printf("Can't find type report debug for liuyu");
            break;
    }


}

static int  choose_type_s(const u_char* pkt_data,int off)
{
    int tem_off=0;
    u_long limit;
    int i;
    switch (pkt_data[off]) {
        case 0x00:
            printf("FIELD_TYPE_DECIMAL");
            break;
        case 0x01:
            printf("FIELD_TYPE_TINY");
            break;
        case 0x02:
            printf("FIELD_TYPE_SHORT");
            printf(":   %hd \n",*((int16_t*)(pkt_data + _Global.type_value_offset)));
            return 2;
        case 0x03:
            printf("FIELD_TYPE_LONG");
            printf(":    %u \n",*((int32_t*)(pkt_data + _Global.type_value_offset)));
            return 4;
        case 0x04:
            printf("FIELD_TYPE_FLOAT");
            printf(":    %f \n",*((float *)(pkt_data + _Global.type_value_offset)));
            return 4;
        case 0x05:
            printf("FIELD_TYPE_DOUBLE");
            printf(":    %lf \n",*((double *)(pkt_data + _Global.type_value_offset)));
            return 8;
        case 0x06:
            printf("FIELD_TYPE_NULL");
            break;
        case 0x07:
            printf("FIELD_TYPE_TIMESTAMP");
            break;
        case 0x08:
            printf("FIELD_TYPE_LONGLONG");
            break;
        case 0x09:
            printf("FIELD_TYPE_INT24");
            break;
        case 0x0a:
            printf("FIELD_TYPE_DATE");
            break;
        case 0x0b:
            printf("FIELD_TYPE_TIME");
            break;
        case 0x0c:
            printf("FIELD_TYPE_DATETIME:     ");
            printf("%hu-%d-%d %d:%d:%d",
                   *((u_int16_t*)(pkt_data+_Global.type_value_offset+1)),
                    pkt_data[_Global.type_value_offset+3],
                    pkt_data[_Global.type_value_offset+4],
                   pkt_data[_Global.type_value_offset+5],
                   pkt_data[_Global.type_value_offset+6],
                   pkt_data[_Global.type_value_offset+7]
                   );
            printf("\n");
            return pkt_data[_Global.type_value_offset]+1;
        case 0x0d:
            printf("FIELD_TYPE_YEAR");
            break;
        case 0x0e:
            printf("FIELD_TYPE_NEWDATE");
            break;
        case 0x0f:
            printf("FIELD_TYPE_VARCHAR (new in MySQL 5.0)");
            break;
        case 0x10:
            printf("FIELD_TYPE_BIT (new in MySQL 5.0)");
            break;
        case 0xf6:
            printf("FIELD_TYPE_NEWDECIMAL (new in MYSQL 5.0");
            break;
        case 0xf7:
            printf("FIELD_TYPE_ENUM");
            break;
        case 0xf8:
            printf("FIELD_TYPE_SET");
            break;
        case 0xf9:
            printf("FIELD_TYPE_TINY_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,_Global.type_value_offset,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[_Global.type_value_offset+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
            break;
        case 0xfa:
            printf("FIELD_TYPE_MEDIUM_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,_Global.type_value_offset,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[_Global.type_value_offset+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
            break;
        case 0xfb:
            printf("FIELD_TYPE_LONG_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,_Global.type_value_offset,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[_Global.type_value_offset+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
            break;
        case 0xfc:
            printf("FIELD_TYPE_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,_Global.type_value_offset,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[_Global.type_value_offset+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
            break;
        case 0xfd:
            printf("FIELD_TYPE_VAR_STRING:    ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,_Global.type_value_offset,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[_Global.type_value_offset+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
        case 0xfe:
            printf("FIELD_TYPE_STRING");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,_Global.type_value_offset,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[_Global.type_value_offset+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
            break;
        case 0xff:
            printf("FIELD_TYPE_GEOMETRY");
            break;
        default:
            printf("Can't find type report debug for liuyu");
            break;
    }
    return 0;
}

static void handshak_parse_client(const u_char* pkt_data,int off)
{
    printf("client handshak\n");
    u_int32_t* cap_c = (u_int32_t*)(pkt_data+off+1);
    u_int32_t cap = *cap_c;
    _Global.client_cap = cap;   //restore ok and error used it

    int version_set = 33;
    printf("\tusername : ");
    while((pkt_data[off + version_set]) != 0x00)
    {
        printf("%c",pkt_data[off + version_set]);
        version_set++;
    }

    version_set += 2;
    printf("\t\t   password : ");
    int i;
    for(i=0;i<pkt_data[off + version_set - 1];i++)
    {
        printf("%02x",pkt_data[off + version_set + i]);
    }
    printf("   ");
    version_set += pkt_data[off + version_set - 1];


    if(cap & CLIENT_CONNECT_WITH_DB)
    {
        printf("database : ");
        while((pkt_data[off + version_set]) != 0x00)
        {
            printf("%c",pkt_data[off + version_set]);
            version_set++;
        }
        version_set++;
        printf("    ");
    }
    if (cap & CLIENT_PLUGIN_AUTH )
    {
        printf("Auth : ");
        while((pkt_data[off + version_set]) != 0x00)
        {
            printf("%c",pkt_data[off + version_set]);
            version_set++;
        }
        version_set++;
        printf("    ");
    }
    if (cap & CLIENT_CONNECT_ATTRS)
    {
        int i;
        int max = version_set + pkt_data[version_set + off];
        version_set += 2;
        printf("\n\tATTR : \n");
        while (version_set < max)
        {
            printf("           ");
            for(i=0;i<pkt_data[version_set + off - 1];i++)
            {
                printf("%c",pkt_data[off + version_set + i]);
            }
            printf(" : ");
            version_set += pkt_data[off + version_set - 1];
            version_set ++;
//        printf("%02x",pkt_data[version_set + off - 1]);
            for(i=0;i<pkt_data[version_set + off - 1];i++)
            {
                printf("%c",pkt_data[off + version_set + i]);
            }
            version_set += pkt_data[off + version_set - 1];
            version_set++;
            printf("\n");
        }
    }
    printf("\n");
}

static void Command_Phase(const u_char* pkt_data,int off)
{
    switch (pkt_data[off])
    {
        case 0x00:
            printf("sleep\n");
            break;
        case 0x01:
            printf("quit\n");
            break;
        case 0x02:
            printf("init db : ");
            Init_db_parse(pkt_data,off);
            break;
        case 0x03:
            Query_parse(pkt_data,off);
            _Global.client_command_mode = Query_client;
            break;
        case 0x04:
            printf("Filed list  :  ");
            File_list_parse(pkt_data,off);
            break;
        case 0x05:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x06:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x07:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x08:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x09:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x0a:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x0b:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x0c:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x0d:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x0e:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x0f:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x10:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x11:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x12:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x13:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x14:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x15:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x16:
            Com_stmt_prepare(pkt_data,off);
            break;
        case 0x17:
            Com_stmt_execute(pkt_data,off);
            _Global.client_command_mode = Prepare_client;
            break;
        case 0x18:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x19:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x1a:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x1b:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x1c:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x1d:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x1e:
            printf("Can't parse , connect to liuyu\n");
            break;
        case 0x1f:
            printf("Can't parse , connect to liuyu\n");
            break;
    }
}

static int Com_stmt_execute(const u_char* pkt_data,int off)
{
    printf("Execute \n");
    printf("\tstatement_id : %u",(*(u_int32_t *) (pkt_data + off+1)));
    u_int32_t yy = (*(u_int32_t *) (pkt_data + off+1));
    printf("      Flags : ");
    Execute_flags_choose(pkt_data[off+5]);
    printf("           Execute info : \n");
    int i;
    int set = 0;
    if(_Global.statement_id[yy]>0)
    {
        if( pkt_data[(_Global.statement_id[yy]+7)/8 + off + 10] == 1 )
        {
            for(i=0;i<_Global.statement_id[yy];i++)
            {
                printf("\t\t");
                _Global.type_value_offset = (_Global.statement_id[yy]+7)/8 + off + 11 + _Global.statement_id[yy] * 2 + set;
                set += choose_type_s(pkt_data,(_Global.statement_id[yy]+7)/8 + off + 11 + 2*i);
            }
            printf("\n");
        }
    }
    return 0;
}

static int Com_stmt_prepare(const u_char* pkt_data,int off)
{
    printf("Prepare \n");
    printf("\tPrepare info : ");
    u_int32_t len = (*(u_int32_t*)(pkt_data + off-4)) & 0x00ffffff;
    int i;
    off++;
    for(i = 0;i<len-1; i++)
    {
        printf("%c",pkt_data[off+i]);
    }
    printf("\n");
    return 0;
}

void Execute_flags_choose(char c)
{
    switch (c) {
        case 0x00:
            printf("CURSOR_TYPE_NO_CURSOR");
            break;
        case 0x01:
            printf("CURSOR_TYPE_READ_ONLY ");
            break;
        case 0x02:
            printf("CURSOR_TYPE_FOR_UPDATE");
            break;
        case 0x04:
            printf("CURSOR_TYPE_SCROLLABLE");
            break;
        default:
            printf("Bug connect liuyu\n");
            break;
    }

}

static int Meter_exit()
{
    if (_Global.pcap_file_hpp != NULL)
        pcap_close(_Global.pcap_file_hpp);
    if (_Global.pcap_dev_hpp != NULL)
        pcap_close(_Global.pcap_dev_hpp);
    return 0;
}

int get_key(Tcp_head* tcp_head,Ip_head* ip_head,char* key)
{
    char Src_ip[30];
    char Drc_ip[30];
    inet_ntop((int) AF_INET, (const void *) &(ip_head->Src_ip), (char *) (Src_ip), 16);
    inet_ntop((int) AF_INET, (const void *) &(ip_head->Dst_ip), (char *) (Drc_ip), 16);
    if (ntohs(tcp_head->Src_port) < ntohs(tcp_head->Dst_port)) //server
    {
        sprintf(key, "%d%d%s%s", ntohs(tcp_head->Src_port), ntohs(tcp_head->Dst_port), Src_ip, Drc_ip);
    }
    if (ntohs(tcp_head->Src_port) > ntohs(tcp_head->Dst_port)) //client
    {
        sprintf(key, "%d%d%s%s", ntohs(tcp_head->Dst_port), ntohs(tcp_head->Src_port), Drc_ip, Src_ip);
        //make sure <server_port><client_port><server_ip><client_ip>
    }
    return 1;
}

int enum_sestion()
{
    struct tm *start_sestion = NULL; //定义开始会话时间
    struct tm *end_sestion = NULL;	 //定义结束会话时间
    char* tem = hash_table_first(_Global.sestion_hash);
    if(tem == NULL)
    {
        printf("No info");
        return -1;
    }
    Sestion_Stat *  data = hash_table_get(_Global.sestion_hash,tem);
    data->end.tv_usec /= 1000;
    data->begin.tv_usec /= 1000;
    int elapsed = (data->end.tv_sec - data->begin.tv_sec) * 1000 + (data->end.tv_usec - data->begin.tv_usec); //以毫秒计算
    elapsed = (elapsed > 0) ? elapsed : 0;
    if (data->total_packet == 1)
        elapsed = 0;

    int yy = 0;
    if(data->Dst_port < data->Src_port) yy = 1;
    start_sestion = localtime(&(data->begin.tv_sec));
    printf("\nSession info :\n");
    printf("\nSession id : %d\n",data->session_id);
    printf("Server: %0x:%0x:%0x:%0x:%0x:%0x %15s:%7u  \nclient: %0x:%0x:%0x:%0x:%0x:%0x %15s:%7u  \n",
           (!yy)?data->S_mac[0]:data->D_mac[0],
           (!yy)?data->S_mac[1]:data->D_mac[1],
           (!yy)?data->S_mac[2]:data->D_mac[2],
           (!yy)?data->S_mac[3]:data->D_mac[3],
           (!yy)?data->S_mac[4]:data->D_mac[4],
           (!yy)?data->S_mac[5]:data->D_mac[5],
           yy?data->Dst_ip:data->Src_ip,
           yy?data->Dst_port:data->Src_port,
           yy?data->S_mac[0]:data->D_mac[0],
           yy?data->S_mac[1]:data->D_mac[1],
           yy?data->S_mac[2]:data->D_mac[2],
           yy?data->S_mac[3]:data->D_mac[3],
           yy?data->S_mac[4]:data->D_mac[4],
           yy?data->S_mac[5]:data->D_mac[5],
           (!yy)?data->Dst_ip:data->Src_ip,
           (!yy)?data->Dst_port:data->Src_port
    );
    printf("Start Time:     %4d-%02d-%02d %02d:%02d:%02d \n",
           start_sestion->tm_year + 1900,
           start_sestion->tm_mon + 1,
           start_sestion->tm_mday,
           start_sestion->tm_hour,
           start_sestion->tm_min,
           start_sestion->tm_sec);

    end_sestion = localtime(&(data->end.tv_sec)); //两次调用Localtime返回的是同一个指针，得先存下来
    printf("End Time:       %4d-%02d-%02d %02d:%02d:%02d \n",
           end_sestion->tm_year + 1900,
           end_sestion->tm_mon + 1,
           end_sestion->tm_mday,
           end_sestion->tm_hour,
           end_sestion->tm_min,
           end_sestion->tm_sec);

    printf("Total Packet: %8u  \nTotal Size: %10u\nElapsed : %d ms\n",
           data->total_packet,
           data->total_size,
           elapsed
    );
    printf("\n");
    int i=1;
    while (tem)
    {
        i++;
        tem = hash_table_next(_Global.sestion_hash,tem);
        if(tem == NULL) return 0;
        data = hash_table_get(_Global.sestion_hash,tem);
        data->end.tv_usec /= 1000;
        data->begin.tv_usec /= 1000;
        elapsed = (data->end.tv_sec - data->begin.tv_sec) * 1000 + (data->end.tv_usec - data->begin.tv_usec); //以毫秒计算
        elapsed = (elapsed > 0) ? elapsed : 0;
        if (data->total_packet == 1)
            elapsed = 0;
        yy = 0;
        if(data->Dst_port<data->Src_port) yy = 1;
        start_sestion = localtime(&(data->begin.tv_sec));
        printf("\nSession info :\n");
        printf("\nSession id : %d\n",data->session_id);
        printf("Server: %0x:%0x:%0x:%0x:%0x:%0x %15s:%7u  \nclient: %0x:%0x:%0x:%0x:%0x:%0x %15s:%7u  \n",
               (!yy)?data->S_mac[0]:data->D_mac[0],
               (!yy)?data->S_mac[1]:data->D_mac[1],
               (!yy)?data->S_mac[2]:data->D_mac[2],
               (!yy)?data->S_mac[3]:data->D_mac[3],
               (!yy)?data->S_mac[4]:data->D_mac[4],
               (!yy)?data->S_mac[5]:data->D_mac[5],
               yy?data->Dst_ip:data->Src_ip,
               yy?data->Dst_port:data->Src_port,
               yy?data->S_mac[0]:data->D_mac[0],
               yy?data->S_mac[1]:data->D_mac[1],
               yy?data->S_mac[2]:data->D_mac[2],
               yy?data->S_mac[3]:data->D_mac[3],
               yy?data->S_mac[4]:data->D_mac[4],
               yy?data->S_mac[5]:data->D_mac[5],
               (!yy)?data->Dst_ip:data->Src_ip,
               (!yy)?data->Dst_port:data->Src_port
        );
        printf("Start Time:     %4d-%02d-%02d %02d:%02d:%02d \n",
               start_sestion->tm_year + 1900,
               start_sestion->tm_mon + 1,
               start_sestion->tm_mday,
               start_sestion->tm_hour,
               start_sestion->tm_min,
               start_sestion->tm_sec);

        end_sestion = localtime(&(data->end.tv_sec)); //两次调用Localtime返回的是同一个指针，得先存下来
        printf("End Time:       %4d-%02d-%02d %02d:%02d:%02d \n",
               end_sestion->tm_year + 1900,
               end_sestion->tm_mon + 1,
               end_sestion->tm_mday,
               end_sestion->tm_hour,
               end_sestion->tm_min,
               end_sestion->tm_sec);

        printf("Total Packet: %8u  \nTotal Size: %10u \nElapsed : %d ms\n",
               data->total_packet,
               data->total_size,
               elapsed
        );
        printf("\n");
    }
    return 0;

}

static int Query_parse(const u_char* pkt_data,int off)
{

  printf("query  :    ");
  u_int32_t c = (*(u_int32_t*)(pkt_data + off-4)) & 0x00ffffff;
  u_int32_t last = _Global.total_len  - off;
  char* uio;
  off++;
  int i;
  for(i=0;i<last - 1;i++)
  {
    if(pkt_data[off + i]==0x0a)
      printf("\\n");
    else
    {
      printf("%c",pkt_data[off + i]);
    }
    if(i%120==0 && i/120>=1)
      printf("\n");
  }
if(c==last)   //防止普通情况进入下面
{
  printf("\n");
  return 1;
}
  Data_head data_head;
  Fram_head fram_head;
  Ip_head ip_head;
  Tcp_head tcp_head;
  int c_count = 0;
  while (c>last)
  {
    fread(&data_head,16,1,_Global.file);
    fread(&fram_head,14,1,_Global.file);
    fread(&ip_head,20,1,_Global.file);
    fread(&tcp_head,20,1,_Global.file);
    int yaya = (14 + (ip_head.Ip_vision_and_len & 0x0f) * 4 + (tcp_head.Head_len >> 4) * 4);
    fseek(_Global.file,yaya-54,SEEK_CUR);
    printf("\n");
    for(i=0;i<data_head.Caplen - yaya;i++)
    {
      char c = fgetc(_Global.file);
      printf("%c",c);
      if(i%80==0 && i/80>=1)
        printf("\n");
      if(c==0x29)
      {
        printf("\n");
        return 0;
      }
    }
    last+=data_head.Caplen - yaya;
    c_count++;
//        printf("LEN:%d",data_head.Caplen - yaya);
//        if(c_count>=991)
//            break;
  }
  printf("%d",last);    //格式控制

  return 1;
}

static int show_filed_info(const u_char* pkt_data,int off)
{
    int ora_off = off;
    printf("\tfiled info :   ");
    off += pkt_data[off - 1];
    printf("database : ");
    int i;
    off++;
    for (i = 0; i < pkt_data[off - 1]; i++) {
        printf("%c", pkt_data[off + i]);
    }
    off += pkt_data[off - 1];
    off++;
    printf("        table  :   ");
    for (i = 0; i < pkt_data[off - 1]; i++) {
        printf("%c", pkt_data[off + i]);
    }
    off += pkt_data[off - 1];
    off++;

    off += pkt_data[off - 1];  //oragenal table name
    off++;
    printf("        name  :   ");
    for (i = 0; i < pkt_data[off - 1]; i++) {
        printf("%c", pkt_data[off + i]);
    }
    off += pkt_data[off - 1];
    off++;

    off += pkt_data[off - 1];
    off++;
    off += 6;
    printf("        type  :   ");
    choose_type(pkt_data, off);
    ora_off = off - ora_off;
    //  printf("%d  ---",pkt_data[off]);

    printf("\n");
    return ora_off;
}

static int Init_db_parse(const u_char* pkt_data,int off)
{
    u_int32_t len = (*(u_int32_t*)(pkt_data + off-4)) & 0x00ffffff;
    int i;
    for(i=1;i<len;i++)
    {
        printf("%c",pkt_data[off + i]);
    }
    printf("\n");
    return 0;
}

static int File_list_parse(const u_char* pkt_data,int off)
{
    u_int32_t len = (*(u_int32_t*)(pkt_data + off-4)) & 0x00ffffff;
    int i;
    for(i=1;i<len-1;i++)
    {
        printf("%c",pkt_data[off + i]);
    }
    printf("\n");
    return 0;
}

static int prepare_choose_type(const u_char* pkt_data,int off)
{
    int tem_off=0;
    u_long limit;
    int i;
    switch (_Global.type_choose[_Global.get_count]) {
        case 0x00:
            printf("FIELD_TYPE_DECIMAL");
            break;
        case 0x01:
            printf("FIELD_TYPE_TINY");
            break;
        case 0x02:
            printf("FIELD_TYPE_SHORT");
            printf(":   %hd \n",*((int16_t*)(pkt_data + off)));
            return 2;
        case 0x03:
            printf("FIELD_TYPE_LONG");
            printf(":    %u \n",*((int32_t*)(pkt_data + off)));
            return 4;
        case 0x04:
            printf("FIELD_TYPE_FLOAT");
            printf(":    %f \n",*((float *)(pkt_data + off)));
            return 4;
        case 0x05:
            printf("FIELD_TYPE_DOUBLE");
            printf(":    %lf \n",*((double *)(pkt_data + off)));
            return 8;
        case 0x06:
            printf("FIELD_TYPE_NULL");
            break;
        case 0x07:
            printf("FIELD_TYPE_TIMESTAMP");
            break;
        case 0x08:
            printf("FIELD_TYPE_LONGLONG");
            break;
        case 0x09:
            printf("FIELD_TYPE_INT24");
            break;
        case 0x0a:
            printf("FIELD_TYPE_DATE");
            break;
        case 0x0b:
            printf("FIELD_TYPE_TIME");
            break;
        case 0x0c:
            printf("FIELD_TYPE_DATETIME:     ");
            printf("%hu-%d-%d %d:%d:%d",
                   *((u_int16_t*)(pkt_data+off+1)),
                   pkt_data[off+3],
                   pkt_data[off+4],
                   pkt_data[off+5],
                   pkt_data[off+6],
                   pkt_data[off+7]
            );
            printf("\n");
            return 8;
        case 0x0d:
            printf("FIELD_TYPE_YEAR");
            break;
        case 0x0e:
            printf("FIELD_TYPE_NEWDATE");
            break;
        case 0x0f:
            printf("FIELD_TYPE_VARCHAR (new in MySQL 5.0)");
            break;
        case 0x10:
            printf("FIELD_TYPE_BIT (new in MySQL 5.0)");
            break;
        case 0xf6:
            printf("FIELD_TYPE_NEWDECIMAL (new in MYSQL 5.0");
            break;
        case 0xf7:
            printf("FIELD_TYPE_ENUM");
            break;
        case 0xf8:
            printf("FIELD_TYPE_SET");
            break;
        case 0xf9:
            printf("FIELD_TYPE_TINY_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,off,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[off+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
        case 0xfa:
            printf("FIELD_TYPE_MEDIUM_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,off,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[off+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
        case 0xfb:
            printf("FIELD_TYPE_LONG_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,off,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[off+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
        case 0xfc:
            printf("FIELD_TYPE_BLOB  :  ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,off,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[off+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
        case 0xfd:
            printf("FIELD_TYPE_VAR_STRING:    ");
            tem_off=0;
            limit = int_lenenc_parse(pkt_data,off,10,&tem_off);
            for(i=1;i<limit+1;i++)
            {
                printf("%c",pkt_data[off+i]);
            }
            printf("\n");
            return limit+tem_off + 1;
        case 0xfe:
            printf("FIELD_TYPE_STRING");
            for(i=0;i<pkt_data[off];i++)
            {
                printf("%c",pkt_data[off + 1 + i]);
            }
            break;
        case 0xff:
            printf("FIELD_TYPE_GEOMETRY");
            for(i=0;i<pkt_data[off];i++)
            {
                printf("%c",pkt_data[off + 1 + i]);
            }
            break;
        default:
            printf("Can't find type report debug for liuyu");
            break;
    }
    return 0;
}

