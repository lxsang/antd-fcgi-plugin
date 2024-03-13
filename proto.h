#ifndef PROTO_H
#define PROTO_H
#include <unistd.h>
#include <antd/handle.h>
/*
 * Listening socket file number
 */
#define FCGI_LISTENSOCK_FILENO 0

typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;

/*
 * Number of bytes in a FCGI_Header.  Future versions of the protocol
 * will not reduce this number.
 */
#define FCGI_HEADER_LEN  8

/*
 * Value for version component of FCGI_Header
 */
#define FCGI_VERSION_1           1

/*
 * Values for type component of FCGI_Header
 */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

/*
 * Value for requestId component of FCGI_Header
 */
#define FCGI_NULL_REQUEST_ID     0

typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
#define FCGI_KEEP_CONN  1

/*
 * Values for role component of FCGI_BeginRequestBody
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[3];
} FCGI_EndRequestBody;

typedef struct {
    FCGI_Header header;
    FCGI_EndRequestBody body;
} FCGI_EndRequestRecord;

/*
 * Values for protocolStatus component of FCGI_EndRequestBody
 */
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3

/*
 * Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records
 */
#define FCGI_MAX_CONNS  "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS   "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS "FCGI_MPXS_CONNS"

typedef struct {
    unsigned char type;    
    unsigned char reserved[7];
} FCGI_UnknownTypeBody;

typedef struct {
    FCGI_Header header;
    FCGI_UnknownTypeBody body;
} FCGI_UnknownTypeRecord;

/**
* The role component sets the role the Web server expects the application to play. The currently-defined roles are:
* FCGI_RESPONDER
* FCGI_AUTHORIZER
* FCGI_FILTER
* The flags component contains a bit that controls connection shutdown:
* flags & FCGI_KEEP_CONN: If zero, the application closes the connection 
* after responding to this request. If not zero, the application does not 
* close the connection after responding to this request; the Web server 
* retains responsibility for the connection
*/
int fcgi_begin_request(antd_client_t*  cl, uint16_t id, uint16_t role, uint8_t flags);

/**
* The Web server sends a FCGI_ABORT_REQUEST record to abort a request. After receiving {FCGI_ABORT_REQUEST, R},
* the application responds as soon as possible with {FCGI_END_REQUEST, R, {FCGI_REQUEST_COMPLETE, appStatus}}. 
* This is truly a response from the application, not a low-level acknowledgement from the FastCGI library.
* A Web server aborts a FastCGI request when an HTTP client closes its transport connection while the FastCGI request is running on behalf of that client.
*/
int fcgi_abort_request(antd_client_t* cl, uint16_t id);

/**
* FCGI_PARAMS is a stream record type used in sending name-value pairs from the Web server to the application. The name-value pairs are sent down the stream one after the other, in no specified order.
*/
int fcgi_send_param(antd_client_t* cl, int id, const char* key, const char* value);
/**
* FCGI_STDIN is a stream record type used in sending arbitrary data from the Web server to the application.
* FCGI_DATA is a second stream record type used to send additional data to the application.
*
* The param data should be padded buffer with size len + paddlen
*/
int fcgi_send_stdin(antd_client_t* cl, int id, uint8_t* padded_data, size_t len, uint8_t paddlen);

/**
* Read record header from application
*/
int fcgi_read_header(antd_client_t* cl, FCGI_Header* header);

/**
* Read error message from stderr
*
* It is the responisbility of the caller to make 
* sure that the buffer lenth is big enough for the
* Content data + padded len
*/
int fcgi_read_data(antd_client_t* cl, FCGI_Header* header, uint8_t* buffer);

uint8_t* fcgi_read_payload(antd_client_t* cl, FCGI_Header* header, int* size);

#endif