//
// Created by liuyu on 2020/8/20.
//
#pragma once
#ifndef INC_20200820_MYSQL_PROTOCOL_MYSQL_PROTOCOL_H
#define INC_20200820_MYSQL_PROTOCOL_MYSQL_PROTOCOL_H
#endif //INC_20200820_MYSQL_PROTOCOL_MYSQL_PROTOCOL_H
/*---include normal header---*/
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include "Hash.h"
#include <arpa/inet.h>
#include <time.h>
#define CHARSIZE 100
#define IPSIZE 20
#define CLIENT_LONG_PASSWORD  0x00000001
#define CLIENT_FOUND_ROWS  0x00000002
#define CLIENT_LONG_FLAG 0x00000004
#define CLIENT_CONNECT_WITH_DB 0x00000008
#define CLIENT_NO_SCHEMA 0x00000010
#define CLIENT_COMPRESS 0x00000040
#define CLIENT_ODBC 0x00000040
#define CLIENT_LOCAL_FILES 0x00000080
#define CLIENT_IGNORE_SPACE 0x00000100
#define CLIENT_PROTOCOL_41 0x00000200
#define CLIENT_INTERACTIVE 0x00000400
#define CLIENT_SSL 0x00000800
#define CLIENT_IGNORE_SIGPIPE 0x00001000
#define CLIENT_TRANSACTIONS 0x00002000
#define CLIENT_RESERVED 0x00004000
#define CLIENT_SECURE_CONNECTION 0x00008000
#define CLIENT_MULTI_STATEMENTS 0x00010000
#define CLIENT_MULTI_RESULTS 0x00020000
#define CLIENT_PS_MULTI_RESULTS 0x00040000
#define CLIENT_PLUGIN_AUTH 0x00080000
#define CLIENT_CONNECT_ATTRS 0x00100000
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS 0x00400000
#define CLIENT_SESSION_TRACK 0x00800000
#define CLIENT_DEPRECATE_EOF 0x01000000

/*--enum struct--*/
enum
{
    mysql_protocol_mode
};
enum
{
    Query_client,
    Prepare_client
};
/*--struct def--*/
typedef struct Global
{
    pcap_t* pcap_file_hpp;
    pcap_t* pcap_dev_hpp;
    pcap_dumper_t* pcap_dump_hpp;
    char pcap_error_info[CHARSIZE];
    char* open_file_name;
    HashTable * sestion_hash;
    int mode;
    u_int32_t session_count;
    int set_syn;
    int handshak_flag;
    u_int32_t client_cap;
    u_int16_t num_params;
    int type_value_offset;
    u_int16_t * statement_id;
    u_char * type_choose;    //prepare responsd type record
    u_int type_choose_count;
    u_int get_count;
    int real_len;
    int total_len;
    u_int8_t packet_num;
    int client_command_mode;
    char* save_file_name;
    u_char* tem_mem;
    int tem_len;
    int mem_flag;
    int last_1_flag;
    int last_2_flag;
    u_int8_t last[4];
    int test;
    u_int now_mem;
    u_int row_count;
    FILE* file;
}Global;

typedef struct Ip_head //IP头部20个字节
{
    u_int8_t Ip_vision_and_len; //4位的版本号和4位的首部长度
    u_int8_t Serv_type;         //服务类型
    u_int16_t Total_len;        //ip数据报的总长度
    u_int16_t Id;               //分片之后的唯一标识
    u_int16_t Flag_segment;     //3位标志和13位的片偏移
    u_int8_t TTL;               //生存周期
    u_int8_t Protocol;          //协议类型
    u_int16_t Check_crc;        //头部crc校验
    u_int32_t Src_ip;           //源IP
    u_int32_t Dst_ip;           //目标IP
} Ip_head;

typedef struct Tcp_head //TCP头部20字节
{
    u_int16_t Src_port;      //源端口
    u_int16_t Dst_port;      //目标端口
    u_int32_t Seq_num;       //序号
    u_int32_t Ack_num;       //确认号
    u_int8_t Head_len;       //头部长度加上4位的保留
    u_int8_t Opt;            //前面两位的保留字段和 后面6位的选项
    u_int16_t Window_size;   //窗口大小
    u_int16_t Check_num;     //校验和
    u_int16_t Rgent_Pointer; //紧急指针
} Tcp_head;

typedef struct Fram_head
{
    u_int8_t D_mac[6];  //目标MAC
    u_int8_t S_mac[6];  //源MAC
    u_int16_t Net_type; //协议类型
} Fram_head;

typedef struct
{
    u_int8_t D_mac[6];  //目标MAC
    u_int8_t S_mac[6];  //源MAC
    int proto;	//协议
    unsigned int total_packet;  //一共的包数
    unsigned int total_size;	//一共的大小
    char Src_ip[IPSIZE];           //源IP
    char Dst_ip[IPSIZE];           //目标IP
    int Src_port;
    int Dst_port;
    struct timeval begin;   //开始的时间
    struct timeval end;		//结束的时间戳
    int session_id;    //record the ip of sesstion
}Sestion_Stat; //用来存每个会话信息

typedef struct Data_head
{
  u_int32_t Get_time_m;//时间戳UNIX
  u_int32_t Get_time_s;//时间戳精确
  u_int32_t Caplen;//数据帧的长度
  u_int32_t Len;//实际数据的长度
}Data_head;
/*--funtion def--*/

static void init_Global();     //init Global param
static void getopt_parse(int argc,char* argv[]);   //parse getopt argument
static void usage();        //for user info
static int Meter_exit();
static void mysql_protocol_parse();
static void mysql_protocol_parse_cb(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int get_key(Tcp_head* tcp_head,Ip_head* ip_head,char* key);
static void Command_Phase(const u_char* pkt_data,int off);
static void handshak_parse_server(const u_char* pkt_data,int off);
static void ok_packet_parse(const u_char* pkt_data,int off);
static void error_packet_parse(const u_char* pkt_data,int off);
static void result_set_parse(const u_char* pkt_data,int off);
static void handshak_parse_client(const u_char* pkt_data,int off);
int enum_sestion();
static int Query_parse(const u_char* pkt_data,int off);
static void  choose_type(const u_char* pkt_data,int off);
static int show_filed_info(const u_char* pkt_data,int off);
u_long int_lenenc_parse(const u_char* pkt_data,int off,u_int32_t len,int* tem_off);
static int Com_stmt_prepare(const u_char* pkt_data,int off);
static int Com_stmt_execute(const u_char* pkt_data,int off);
static void prepare_ok_packet_parse(const u_char* pkt_data,int off);
void Execute_flags_choose(char c);
static int choose_type_s(const u_char* pkt_data,int off);
static int Init_db_parse(const u_char* pkt_data,int off);
static int File_list_parse(const u_char* pkt_data,int off);
static int prepare_choose_type(const u_char* pkt_data,int off);