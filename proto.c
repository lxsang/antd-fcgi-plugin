
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "proto.h"

#define PARAMS_LENGTH_11 ((0<<0) | (0<<1))
#define PARAMS_LENGTH_14 ((0<<0) | (1<<1))
#define PARAMS_LENGTH_41 ((1<<0) | (0<<1))
#define PARAMS_LENGTH_44 ((1<<0) | (1<<1))

typedef struct {
    unsigned char nameLengthB0;  /* nameLengthB0  >> 7 == 0 */
    unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
    char value[0];
} FCGI_NameValuePair11;

typedef struct {
    unsigned char nameLengthB0;  /* nameLengthB0  >> 7 == 0 */
    unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
    unsigned char valueLengthB2;
    unsigned char valueLengthB1;
    unsigned char valueLengthB0;
    char value[0];
} FCGI_NameValuePair14;

typedef struct {
    unsigned char nameLengthB3;  /* nameLengthB3  >> 7 == 1 */
    unsigned char nameLengthB2;
    unsigned char nameLengthB1;
    unsigned char nameLengthB0;
    unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
    char value[0];
} FCGI_NameValuePair41;

typedef struct {
    unsigned char nameLengthB3;  /* nameLengthB3  >> 7 == 1 */
    unsigned char nameLengthB2;
    unsigned char nameLengthB1;
    unsigned char nameLengthB0;
    unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
    unsigned char valueLengthB2;
    unsigned char valueLengthB1;
    unsigned char valueLengthB0;
    char value[0];
} FCGI_NameValuePair44;

typedef union {
    FCGI_NameValuePair11 d11;
    FCGI_NameValuePair14 d14;
    FCGI_NameValuePair41 d41;
    FCGI_NameValuePair44 d44;
} FCGI_Params_Body;

static int fcgi_send_record(antd_client_t* cl, FCGI_Header* header, uint8_t* buff, size_t len)
{
    if(!header)
    {
        ERROR("Record header should not empty");
        return -1;
    }

    // send the header
    int ret = antd_send(cl, (uint8_t*)header, sizeof(FCGI_Header));
    if(ret != sizeof(FCGI_Header))
    {
        ERROR("fcgi_send_record: Unable to send record header, only %d of %d bytes sent: %s", ret, sizeof(FCGI_Header), strerror(errno));
        return -1;
    }
    if(!buff)
    {
        return 0;
    }
    // send the data
    ret = antd_send(cl, (uint8_t*)buff, len);
    if(ret != (int)len)
    {
        ERROR("fcgi_send_record: Unable to send record data, only %d of %d bytes sent", ret, len);
        return -1;
    }
    return 0;
}

int fcgi_begin_request(antd_client_t* cl, uint16_t id, uint16_t role, uint8_t flags)
{
    FCGI_BeginRequestRecord record;
    record.header.version = FCGI_VERSION_1;
    record.header.type = FCGI_BEGIN_REQUEST;
    record.header.requestIdB1 = id >> 8;
    record.header.requestIdB0 = id & 0xFF;
    record.header.contentLengthB1 = 0;
    record.header.contentLengthB0 = 8;
    record.header.paddingLength = 0;

    record.body.roleB1 = role >> 8;
    record.body.roleB0 = role & 0xFF;
    record.body.flags = flags;

    int ret = antd_send(cl, (uint8_t*)&record, sizeof(record));
    if(ret != sizeof(record))
    {
        ERROR("fcgi_begin_request: Unable to send record data, only %d of %d bytes sent", ret, sizeof(record));
        return -1;
    }
    return 0;
}

int fcgi_abort_request(antd_client_t* cl, uint16_t id)
{
    FCGI_Header header;
    header.version = FCGI_VERSION_1;
    header.type = FCGI_BEGIN_REQUEST;
    header.requestIdB1 = id >> 8;
    header.requestIdB0 = id & 0xFF;
    header.contentLengthB1 = 0;
    header.contentLengthB0 = 0;
    header.paddingLength = 0;
    int ret = antd_send(cl, (uint8_t*)&header, sizeof(header));
    if(ret != sizeof(header))
    {
        ERROR("fcgi_abort_request: Unable to send record data, only %d of %d bytes sent", ret, sizeof(header));
        return -1;
    }
    return 0;
}

int fcgi_send_param(antd_client_t* cl, int id, const char* key, const char* value)
{
    size_t k_length = strlen(key);
    size_t v_length = strlen(value);
    //LOG("sending [%s] -> [%s]", key, value);
    FCGI_Params_Body* body = NULL;
    uint8_t* buff = NULL;
    size_t clen = k_length + v_length;
    if(clen > 0)
    {
        size_t max_buff_len = sizeof(FCGI_Params_Body) + k_length + v_length + 8;

        buff = (uint8_t*)malloc(max_buff_len);
        if(!buff)
        {
            ERROR("Unable to allocate PARAMS record buffer memory: %s", strerror(errno));
            return -1;
        }
    }
    
    body = (FCGI_Params_Body*) buff;

    FCGI_Header header;
    header.version = FCGI_VERSION_1;
    header.type = FCGI_PARAMS;
    header.requestIdB1 = id >> 8;
    header.requestIdB0 = id & 0xFF;
    
    if(clen > 0)
    {
        uint8_t encoding_type = (((k_length & 0xFF) >> 7) << 0) | (((v_length & 0xFF)>>7) << 1);
        switch(encoding_type)
        {
            case PARAMS_LENGTH_11:
                body->d11.nameLengthB0 = k_length;
                body->d11.valueLengthB0 = v_length;
                memcpy(body->d11.value, key, k_length);
                memcpy(body->d11.value+k_length, value, v_length);
                clen += 2; 
                break;
            case PARAMS_LENGTH_14:
                body->d14.nameLengthB0 = k_length;
                body->d14.valueLengthB3 = (v_length >> 24) | 0x80;
                body->d14.valueLengthB2 = (v_length >> 16) & 0xFF;
                body->d14.valueLengthB1 = (v_length >> 8) & 0xFF;
                body->d14.valueLengthB0 = v_length & 0xFF;

                memcpy(body->d14.value, key, k_length);
                memcpy(body->d14.value+k_length, value, v_length);
                clen += 5;
                break;
            case PARAMS_LENGTH_41:
                body->d41.valueLengthB0 = v_length;
                body->d41.nameLengthB3 = (k_length >> 24) | 0x80;
                body->d41.nameLengthB2 = (k_length >> 16) & 0xFF;
                body->d41.nameLengthB1 = (k_length >> 8) & 0xFF;
                body->d41.nameLengthB0 = k_length & 0xFF;
                memcpy(body->d41.value, key, k_length);
                memcpy(body->d41.value+k_length, value, v_length);
                clen += 5;
                break;
            case PARAMS_LENGTH_44:
                body->d44.nameLengthB3 = (k_length >> 24) | 0x80;
                body->d44.nameLengthB2 = (k_length >> 16) & 0xFF;
                body->d44.nameLengthB1 = (k_length >> 8) & 0xFF;
                body->d44.nameLengthB0 = k_length & 0xFF;
                body->d44.valueLengthB3 = (v_length >> 24) | 0x80;
                body->d44.valueLengthB2 = (v_length >> 16) & 0xFF;
                body->d44.valueLengthB1 = (v_length >> 8) & 0xFF;
                body->d44.valueLengthB0 = v_length & 0xFF;
                memcpy(body->d44.value, key, k_length);
                memcpy(body->d44.value+k_length, value, v_length);
                clen += 8;
                break;
            default:
                // this should never happends
                free(buff);
                return -1;
        }
    }

    
    header.contentLengthB1 = clen >> 8;
    header.contentLengthB0 = clen & 0xFF;
    header.paddingLength = (clen % 8 == 0)? 0 : 8 - (clen % 8);

    // send the record
    int ret = fcgi_send_record(cl, &header, buff, clen + header.paddingLength);
    if(buff)
        free(buff);
    return ret;
}


int fcgi_send_stdin(antd_client_t* cl, int id, uint8_t* padded_data, size_t len, uint8_t paddlen)
{
    FCGI_Header header;
    header.version = FCGI_VERSION_1;
    header.type = FCGI_STDIN;
    header.requestIdB1 = id >> 8;
    header.requestIdB0 = id & 0xFF;
    header.contentLengthB1 = len >> 8;
    header.contentLengthB0 = len & 0xFF;
    header.paddingLength = paddlen;
    // send the record
    return fcgi_send_record(cl, &header, padded_data, len + paddlen);
}


int fcgi_read_header(antd_client_t* cl, FCGI_Header* header)
{
    uint8_t* buff = (uint8_t*) header;
    int ret = antd_recv(cl, buff, sizeof(FCGI_Header));
    if(ret != sizeof(FCGI_Header))
    {
        ERROR("Unable to read header: received %d bytes out of %d bytes", ret, sizeof(FCGI_Header));
        return -1;
    }
    return 0;
}

int fcgi_read_data(antd_client_t* cl, FCGI_Header* header, uint8_t* buffer)
{
    int len = ((header->contentLengthB1 << 8) | header->contentLengthB0) + header->paddingLength;
    int ret = antd_recv(cl, buffer, len);
    if(ret != len)
    {
        ERROR("Unable to read record body: received %d bytes out of %d bytes", ret, len);
        return -1;
    }
    return 0;
}

uint8_t* fcgi_read_payload(antd_client_t* cl, FCGI_Header* header, int* size)
{
    int len = ((header->contentLengthB1 << 8) | header->contentLengthB0) + header->paddingLength;
    uint8_t* buff = (uint8_t*) malloc(len + 1);
    if(!buff)
    {
        ERROR("Unable to allocate buffer of size %d", len);
        return NULL;
    }
    int ret = antd_recv(cl, buff, len);
    if(ret != len)
    {
        ERROR("Unable to read record body: received %d bytes out of %d bytes", ret, len);
        free(buff);
        return NULL;
    }
    *size = len - header->paddingLength;
    buff[*size] = '\0';
    return buff;
}