//
// Created by root on 2020/8/20.
//

#include "Hash.h"
//
// Created by root on 2020/8/4.
//

#define TABLE_SIZE (1024*1024)

/* element of the hash table's chain list */
struct kv
{
    struct kv* next;
    char* key;
    void* value;
    void(*free_value)(void*);
};

/* HashTable */
struct HashTable
{
    struct kv ** table;
};

/* constructor of struct kv */
static void init_kv(struct kv* kv)
{
    kv->next = NULL;
    kv->key = NULL;
    kv->value = NULL;
    kv->free_value = NULL;
}
/* destructor of struct kv */
static void free_kv(struct kv* kv)
{
    if (kv) {
        if (kv->free_value) {
            kv->free_value(kv->value);
        }
        free(kv->key);
        kv->key = NULL;
        free(kv);
    }
}
/* the classic Times33 hash function */
unsigned int hash_33(char* key)
{
    if(key ==NULL)
    {
        printf("key NULL");
        return 1;
    }
    unsigned int hash = 0;
    while (*key)
    {
        hash = (hash << 5) + hash + *key++;
    }
    return hash;
}

/* new a HashTable instance */
HashTable* hash_table_new()
{
    HashTable* ht = malloc(sizeof(HashTable));
    if (NULL == ht) {
        hash_table_delete(ht);
        return NULL;
    }
    ht->table = malloc(sizeof(struct kv*) * TABLE_SIZE);
    if (NULL == ht->table) {
        hash_table_delete(ht);
        return NULL;
    }
    memset(ht->table, 0, sizeof(struct kv*) * TABLE_SIZE);

    return ht;
}
/* delete a HashTable instance */
void hash_table_delete(HashTable* ht)
{
    if (ht) {
        if (ht->table) {
            int i = 0;
            for (i = 0; i<TABLE_SIZE; i++) {
                struct kv* p = ht->table[i];
                struct kv* q = NULL;
                while (p) {
                    q = p->next;
                    free_kv(p);
                    p = q;
                }
            }
            free(ht->table);
            ht->table = NULL;
        }
        free(ht);
    }
}

/* insert or update a value indexed by key */
char* hash_table_put2(HashTable* ht, char* key, void* value, void(*free_value)(void*))
{
    if(ht == NULL)
    {
        printf("HASH_TABLE NULL");
        exit(0);
    }
    int i = hash_33(key) % TABLE_SIZE;
    struct kv* p = ht->table[i];
    struct kv* prep = p;

    while (p) { /* if key is already stroed, update its value */
        if (strcmp(p->key, key) == 0) {
            if (p->free_value) {
                p->free_value(p->value);
            }
            p->value = value;
            p->free_value = free_value;
            break;
        }
        prep = p;
        p = p->next;
    }

    char* last_key;
    if (p == NULL) {/* if key has not been stored, then add it */
        char* kstr = malloc(strlen(key) + 1);
        last_key = kstr;
        if (kstr == NULL) {
            return NULL;
        }
        struct kv * kv = malloc(sizeof(struct kv));
        if (NULL == kv) {
            free(kstr);
            kstr = NULL;
            return NULL;
        }
        init_kv(kv);
        kv->next = NULL;
        strcpy(kstr, key);
        kv->key = kstr;
        kv->value = value;
        kv->free_value = free_value;

        if (prep == NULL) {
            ht->table[i] = kv;
        }
        else {
            prep->next = kv;
        }
    }
    return last_key;
}

/* get a value indexed by key */
void* hash_table_get(HashTable* ht, char* key)
{
    if(ht == NULL)
    {
        printf("HASH_TABLE NULL");
        exit(0);
    }
    int i = hash_33(key) % TABLE_SIZE;
    struct kv* p = ht->table[i];
    while (p) {
        if (strcmp(key, p->key) == 0) {
            return p->value;
        }
        p = p->next;
    }
    return NULL;
}

void* hash_table_get_key(HashTable* ht, char* key)
{
    if(ht == NULL)
    {
        printf("HASH_TABLE NULL");
        exit(0);
    }
    int i = hash_33(key) % TABLE_SIZE;
    struct kv* p = ht->table[i];
    while (p) {
        if (strcmp(key, p->key) == 0) {
            return p->key;
        }
        p = p->next;
    }
    return NULL;
}


void* hash_table_code_get(HashTable* ht, u_int code,char* key)
{
    int i = code;
    struct kv* p = ht->table[i];
    while (p) {
        if (strcmp(key, p->key) == 0) {
            return p->value;
        }
        p = p->next;
    }
    return NULL;
}


/* remove a value indexed by key */
void hash_table_rm(HashTable* ht, char* key)
{
    int i = hash_33(key) % TABLE_SIZE;

    struct kv* p = ht->table[i];
    struct kv* prep = p;
    while (p) {
        if (strcmp(key, p->key) == 0) {
            free_kv(p);
            if (p == prep) {
                ht->table[i] = NULL;
            }
            else {
                prep->next = p->next;
            }
        }
        prep = p;
        p = p->next;
    }
}

char* hash_table_next(HashTable* ht, char *key)
{
    int flag = 0;
    int i = hash_33(key) % TABLE_SIZE;
    struct kv* p = ht->table[i];
    while (p)
    {
        if (strcmp(key, p->key) == 0)
        {
            flag = 1;
        }
        p = p->next;
        if(NULL != p && flag)
        {
            return p->key;
        }
    }
    for( i+=1;i<TABLE_SIZE;i++)
    {
        struct kv* p = ht->table[i];
        if(p != NULL)
        {
            return p->key;
        }
    }
    return NULL;
}

char* hash_table_first(HashTable* ht)
{
    if(ht == NULL) return NULL;
    int i = 0;
    for( ;i<TABLE_SIZE;i++)
    {
        struct kv* p = ht->table[i];
        if(p != NULL)
        {
            return p->key;
        }
    }
    return NULL;
}


