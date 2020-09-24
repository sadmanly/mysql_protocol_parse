//
// Created by root on 2020/8/20.
//

#ifndef INC_20200820_MYSQL_PROTOCOL_HASH_H
#define INC_20200820_MYSQL_PROTOCOL_HASH_H

#endif //INC_20200820_MYSQL_PROTOCOL_HASH_H
//
// Created by root on 2020/8/5.
//

#ifndef METER_CLION_20200803_HASH_H
#define METER_CLION_20200803_HASH_H

#endif //METER_CLION_20200803_HASH_H
//
// Created by root on 2020/8/4.
//

#ifndef HASH_TEST_HASH_H
#define HASH_TEST_HASH_H

#endif //HASH_TEST_HASH_H
#pragma once
typedef struct HashTable HashTable;

#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* new an instance of HashTable */
HashTable* hash_table_new();

/*
delete an instance of HashTable,
all values are removed auotmatically.
*/
void hash_table_delete(HashTable* ht);

/*
add or update a value to ht,
free_value(if not NULL) is called automatically when the value is removed.
return 0 if success, -1 if error occurred.
*/

#define hash_table_put(ht,key,value) hash_table_put2(ht,key,value,NULL);
char* hash_table_put2(HashTable* ht, char* key, void* value, void(*free_value)(void*));

/* get a value indexed by key, return NULL if not found. */
void* hash_table_get(HashTable* ht, char* key);

/* remove a value indexed by key */
void hash_table_rm(HashTable* ht, char* key);

char* hash_table_next(HashTable* ht, char *key);
char* hash_table_first(HashTable* ht);
/* get hash_code*/
unsigned int hash_33(char* key);
void* hash_table_code_get(HashTable* ht, u_int code,char* key);
void* hash_table_get_key(HashTable* ht, char* key);

#ifdef __cplusplus
}
#endif