#define PLUGIN_IMPLEMENT 1
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <antd/plugin.h>
#include <antd/scheduler.h>
#include <antd/utils.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#include <libgen.h>
#include "proto.h"

#ifdef MAX_PATH_LEN
#undef MAX_PATH_LEN
#endif
#define MAX_PATH_LEN 108
#define MAX_BACK_LOG 64
#define PROCESS_TIMEOUT 200u

#define FCGI_CLIENT_REQUEST_SENT (0)
#define FCGI_CLIENT_WAIT_FOR_RESPONSE_HEADER (-1)
#define FCGI_CLIENT_WAIT_FOR_RESPONSE_DATA (-2)

typedef struct {
    // FastCGI application path
    char app_bin[MAX_PATH_LEN];
    // TCP host or Unix domain socket
    char address[MAX_PATH_LEN];
    // only for TCP socket
    int port;
    // server fd
    int fd;
    // pid of the application process
    pid_t pid;
} fcgi_config_t;

static fcgi_config_t g_config;

static int mk_socket();
static int read_config();
static int open_un_socket();
static int open_tcp_socket();
static int open_socket();
static char* read_line(char** buff, int* size);
static int read_header(antd_client_t* cl, antd_request_t* rq);
static int read_data(antd_client_t* cl, antd_request_t* rq);
static void *process(void *data);
static int send_request(antd_client_t *cl, antd_request_t* rq);
void* handle(void* data);
static int mk_un_socket();
static int mk_tcp_socket();

static int read_config()
{
    char * tmp;
    (void*) memset(g_config.app_bin, 0, MAX_PATH_LEN);
    (void*) memset(g_config.address, 0, MAX_PATH_LEN);
    g_config.port = -1;
    g_config.fd = -1;
    g_config.pid = -1;
    regmatch_t regex_matches[3];
    // read plugin configuration
    if(!__plugin__.config)
    {
        PLUGIN_PANIC("No plugin configuration found. Please specify it in server config file");
        return -1;
    }
    tmp = (char*) dvalue(__plugin__.config, "socket");
    if(!tmp)
    {
        PLUGIN_PANIC("No socket configuration found (socket)");
        return -1;
    }
    if(strncmp(tmp,"unix:", 5) == 0)
    {
        if(strlen(tmp + 5) > MAX_PATH_LEN - 1)
        {
            PLUGIN_PANIC("socket configuration is too long: %s", tmp);
            return -1;
        }
        snprintf(g_config.address, MAX_PATH_LEN,"%s", tmp+5);
        LOG("Found Unix domain socket configuration: %s", g_config.address);
    }
    else if(regex_match("^([a-zA-Z0-9\\-_\\.]+):([0-9]+)$", tmp,3, regex_matches))
    {
        if(regex_matches[1].rm_eo - regex_matches[1].rm_so > MAX_PATH_LEN - 1)
        {
            PLUGIN_PANIC("socket configuration is too long: %s", tmp);
            return -1;
        }
        memcpy(g_config.address, tmp + regex_matches[2].rm_so, regex_matches[2].rm_eo - regex_matches[2].rm_so);
        g_config.port = atoi(g_config.address);
        (void*) memset(g_config.address, 0, MAX_PATH_LEN);
        memcpy(g_config.address, tmp + regex_matches[1].rm_so, regex_matches[1].rm_eo - regex_matches[1].rm_so);
        LOG("Found TCP socket configuration: %s:%d", g_config.address, g_config.port);
    }
    else
    {
        PLUGIN_PANIC("Unknown socket configuration: %s", tmp);
        return -1;
    }
    tmp = (char*) dvalue(__plugin__.config, "bin");
    if(tmp)
    {
        if(strlen(tmp) > MAX_PATH_LEN - 1)
        {
            PLUGIN_PANIC("Bin application configuration is too long: %s", tmp);
            return -1;
        }
        snprintf(g_config.app_bin, MAX_PATH_LEN,"%s", tmp);
        LOG("Binary application configuration: %s", g_config.app_bin);
        // create the server socket then launched it
        g_config.fd = mk_socket();
        if(g_config.fd == -1)
        {
            PLUGIN_PANIC("Unable to create FastCGI server socket");
            return -1;
        }
        // launch the application
        g_config.pid = fork();
        if(g_config.pid == -1)
        {
            PLUGIN_PANIC("Unable to create FastCGI server socket");
            close(g_config.fd);
            g_config.fd = -1;
            g_config.pid = -1;
            return -1;
        }
        if(g_config.pid == 0)
        {
            // child
            // close the original stdin
            close(0);
            // redirect the stdin to the socket
            dup2(g_config.fd, 0);
            char *argv[] = {g_config.app_bin, 0};
            char *env[] = {NULL, NULL};
            env[0] = getenv("ANTD_DEBUG");
            if(env[0] && (
                (strcmp(env[0], "1") == 0) || (strcmp(env[0], "true") == 0)) )
            {
                env[0] = "debug=1";
            }
            else
            {
                env[0] = "debug=0";
            }
            execve(argv[0], &argv[0], &env[0]);
            _exit(1);
        }
        // parent
        LOG("FastCGI process (%d) created", g_config.pid);
    }
    return 0;
}

static int mk_un_socket()
{
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    //remove socket file if exists
    (void) remove(g_config.address);
    // create the socket
    (void)strncpy(address.sun_path, g_config.address, sizeof(address.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        ERROR("Unable to create Unix domain socket: %s", strerror(errno));
        return -1;
    }
    if (bind(fd, (struct sockaddr *)(&address), sizeof(address)) == -1)
    {
        ERROR("Unable to bind name: %s to a socket: %s", address.sun_path, strerror(errno));
        close(fd);
        return -1;
    }
    // mark the socket as passive mode

    if (listen(fd, MAX_BACK_LOG) == -1)
    {
        ERROR("Unable to listen to socket: %d (%s): %s", fd, g_config.address, strerror(errno));
        close(fd);
        return -1;
    }
    LOG("Socket %s is created successfully: %d", g_config.address, fd);
    return fd;
}
static int mk_tcp_socket()
{
    int fd = -1;
    struct sockaddr_in name;
    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        ERROR("Unable to create TCP socket socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    {
        ERROR("Unable to set reuse address on port %d - setsockopt: %s", g_config.port, strerror(errno));
    }

    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(g_config.port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&name, sizeof(name)) < 0)
    {
        ERROR("Unable to bind TCP socket at port %d -bind: %s", g_config.port, strerror(errno));
        close(fd);
        return -1;
    }
    
    if (listen(fd, MAX_BACK_LOG) < 0)
    {
        ERROR("Unable to listen on Port %d - listen: %s", g_config.port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int open_un_socket()
{
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    // create the socket
    (void)strncpy(address.sun_path, g_config.address, sizeof(address.sun_path));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        ERROR("Unable to create Unix domain socket: %s", strerror(errno));
        return -1;
    }
    if(connect(fd, (struct sockaddr*)(&address), sizeof(address)) == -1)
    {
        ERROR( "Unable to connect to socket '%s': %s", address.sun_path, strerror(errno));
        close(fd);
        return -1;
    }
    LOG("Connected to FastCGI server at %s: %d", g_config.address, fd);
    return fd;
}

static int open_tcp_socket()
{
    struct sockaddr_in servaddr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        PLUGIN_PANIC("Cannot create TCP socket %s:d: %s",g_config.address, g_config.port, strerror(errno));
        return -1;
    }
    
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(g_config.address);
    servaddr.sin_port = htons(g_config.port);
 
    // connect the client socket to server socket
    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))!= 0) {
        ERROR( "Unable to connect to socket '%s:%d': %s", g_config.address, g_config.port, strerror(errno));
        close(fd);
        return -1;
    }
    LOG("Connected to server: %s:%d at [%d]", g_config.address, g_config.port, fd);
    return fd;
}

static int open_socket()
{
    if(g_config.port != -1)
    {
        return open_tcp_socket();
    }
    else
    {
        return open_un_socket();
    }
}

static int mk_socket()
{
    if(g_config.port != -1)
    {
        return mk_tcp_socket();
    }
    else
    {
        return mk_un_socket();
    }
}

void init()
{
    use_raw_body();
    if(read_config() != 0)
        return;
    // create the socket
    //if(create_socket() != 0)
    //    return;
    LOG("FastCGI init successful");

}
void destroy()
{
    if(g_config.pid > 0)
    {
        LOG("Process killed: %d", g_config.pid);
        (void)kill(g_config.pid, SIGKILL);
        g_config.pid = -1;
    }
    if(g_config.fd > 0)
    {
        LOG("Close server socket: %d", g_config.fd);
        close(g_config.fd);
        g_config.fd = -1;
    }
}


static char* read_line(char** buff, int* size)
{
    int i = 0;
    while(i <= *size-1 && (*buff)[i] != '\n') i++;
    if(i > 0 && i <= *size - 1)
        (*buff)[i] = '\0';
    char* line = *buff;
    *size = *size - i - 1;
    *buff = *buff + i+1;
    return line;
}

static int read_header(antd_client_t* cl, antd_request_t* rq)
{
    FCGI_Header header;
    antd_response_header_t rhd;
    rhd.header = dict();
    rhd.cookie = list_init();
    rhd.status = 200;
    char *k;
    char *v;
    int len, ret;
    regmatch_t matches[3];
    uint8_t * payload;
    char* line;
    char* ptr;
    while(cl->state == FCGI_CLIENT_WAIT_FOR_RESPONSE_HEADER)
    {
        ret = fcgi_read_header(cl,&header);
        if(ret < 0)
        {
            (void)fcgi_abort_request(cl, cl->sock);
            LOG("fcgi_read_header() on %d: %s", cl->sock, strerror(errno));
            return -1;
        }
        payload = fcgi_read_payload(cl, &header, &ret);
        switch(header.type)
        {
            case FCGI_STDOUT:
                // write data to the other side
                if(payload && ret > 0)
                {
                    ptr = (char*)payload;
                    while(ret > 0)
                    {
                        line = read_line(&ptr, &ret);
                        trim(line, '\r');
                        if(strlen(line) == 0)
                        {
                            cl->state = FCGI_CLIENT_WAIT_FOR_RESPONSE_DATA;
                            // write out header and the rest of the data
                            antd_send_header(rq->client, &rhd);
                            if(ret > 0)
                            {
                                if(antd_send(rq->client,ptr, ret) != ret)
                                {
                                    (void)fcgi_abort_request(cl, cl->sock);
                                    ERROR("Error atnd_send(): %s", strerror(errno));
                                    free(payload);
                                    return -1;
                                }
                            }
                            break;
                        }
                        if(ret < 0) break;
                        if (regex_match("\\s*Status\\s*:\\s+([0-9]{3})\\s+([a-zA-Z0-9 ]*)", line, 3, matches))
                        {
                            len = matches[1].rm_eo - matches[1].rm_so;
                            k = (char *)malloc(len + 1);
                            memset(k, 0, len + 1);
                            memcpy(k, line + matches[1].rm_so, len);
                            rhd.status = atoi(k);
                            LOG("Response status %d", rhd.status);
                            free(k);
                        }
                        else if (regex_match("^([a-zA-Z0-9\\-]+)\\s*:\\s*(.*)$", line, 3, matches))
                        {
                            len = matches[1].rm_eo - matches[1].rm_so;
                            k = (char *)malloc(len + 1);
                            memset(k, 0, len + 1);
                            memcpy(k, line + matches[1].rm_so, len);
                            verify_header(k);
                            len = matches[2].rm_eo - matches[2].rm_so;
                            v = (char *)malloc(len + 1);
                            memset(v, 0, len + 1);
                            memcpy(v, line + matches[2].rm_so, len);
                            LOG("Header [%s] -> [%s]", k, v);
                            if (strcmp(k, "Set-Cookie") == 0)
                            {
                                list_put_ptr(&rhd.cookie, v);
                            }
                            else
                            {
                                dput(rhd.header, k, v);
                            }
                            free(k);
                        }
                        else
                        {
                            LOG("Ignore invalid header: %s", line);
                        }
                        
                    }
                }
                break;
            case FCGI_STDERR:
                if(payload && ret > 0)
                {
                    ERROR("%s", (char*) payload);
                }
                break;
            case FCGI_END_REQUEST:
                LOG("End request received, this should not happen %d", cl->sock);
                // FCGI_EndRequestBody* body = (FCGI_EndRequestBody*) payload;
                if(payload) free(payload);
                return -1;
            default:
                LOG("Unsupported record type: 0x%02x", header.type);
                break;
        }
        if(payload) free(payload);
    }
    return 0;
}

static int read_data(antd_client_t* cl, antd_request_t* rq)
{
    FCGI_Header header;
    int ret = fcgi_read_header(cl,&header);
    if(ret < 0)
    {
        (void)fcgi_abort_request(cl, cl->sock);
        LOG("fcgi_read_header() on %d: %s", cl->sock, strerror(errno));
        return -1;
    }
    uint8_t * payload = fcgi_read_payload(cl, &header, &ret);
    switch(header.type)
    {
        case FCGI_STDOUT:
            // write data to the other side
            if(payload && ret > 0)
            {
                if(antd_send(rq->client,payload, ret) != ret)
                {
                    (void)fcgi_abort_request(cl, cl->sock);
                    ERROR("Error atnd_send(): %s", strerror(errno));
                    free(payload);
                    return -1;
                }
            }
            break;
        case FCGI_STDERR:
            if(payload && ret > 0)
            {
                ERROR("%s", (char*) payload);
            }
            break;
        case FCGI_END_REQUEST:
            LOG("End request received, close connection %d", cl->sock);
            if(payload) free(payload);
            return -1;
        default:
            LOG("Unsupported record type: 0x%02x", header.type);
            break;
    }
    if(payload) free(payload);
    return 0;
}

static void *process(void *data)
{
    antd_request_t *rq = (antd_request_t *)data;
    antd_client_t* cl = (antd_client_t* ) dvalue(rq->request, "FCGI_CL_DATA");
    struct pollfd pfds[2];
    int status;
    if(g_config.pid > 0)
    {
        if(waitpid(g_config.pid, &status, WNOHANG) > 0)
        {
            PLUGIN_PANIC("FastCGI process exits unexpectedly");
            antd_close(cl);
            dput(rq->request, "FCGI_CL_DATA", NULL);
            return antd_create_task(NULL, data, NULL, rq->client->last_io);
        }
    }

    pfds[0].fd = rq->client->sock;
    pfds[0].events = POLLIN;
    if(rq->client->ssl)
    {
        pfds[0].events = POLLIN | POLLOUT;
    }
    pfds[1].fd = cl->sock;
    pfds[1].events = POLLIN;
    if(cl->state == FCGI_CLIENT_REQUEST_SENT)
    {
        (void)fcgi_send_stdin(cl, cl->sock, NULL, 0, 0);
        if (ws_enable(rq->request))
        {
            cl->state = FCGI_CLIENT_WAIT_FOR_RESPONSE_DATA;
        }
        else
        {
            cl->state = FCGI_CLIENT_WAIT_FOR_RESPONSE_HEADER;
        }
    }

    int rc = poll(pfds, 2, PROCESS_TIMEOUT);
    antd_task_t* task;
    uint8_t buff[BUFFLEN];
    int ret;
    switch (rc)
    {
        case -1:
            ERROR("Error on poll(): %s", strerror(errno));
            (void)fcgi_abort_request(cl, cl->sock);
            antd_close(cl);
            dput(rq->request, "FCGI_CL_DATA", NULL);
            return antd_create_task(NULL, data, NULL, rq->client->last_io);
        case 0:
            // time out
            task = antd_create_task(process, (void *)rq, NULL, time(NULL));
            antd_task_bind_event(task, rq->client->sock, 0, TASK_EVT_ON_WRITABLE | TASK_EVT_ON_READABLE);
            antd_task_bind_event(task, cl->sock, 0, TASK_EVT_ON_READABLE);
            return task;
        // we have data
        default:
            // If data is on webserver
            if ((pfds[0].revents & POLLIN) || (rq->client->ssl && (pfds[0].revents & POLLOUT)) )
            {
                while((ret = antd_recv_upto(rq->client,buff, BUFFLEN)) > 0)
                {
                    // write data to the application stdin
                    if(fcgi_send_stdin(cl, cl->sock,buff, ret, (ret % 8 == 0)? 0 : 8 - (ret % 8) ) != 0)
                    {
                        ERROR("Error on fcgi_send_stdin(): %s", strerror(errno));
                        (void)fcgi_abort_request(cl, cl->sock);
                        antd_close(cl);
                        dput(rq->request, "FCGI_CL_DATA", NULL);
                        return antd_create_task(NULL, data, NULL, rq->client->last_io);
                    }
                    if(cl->state > 0)
                        cl->state -= ret;
                    LOG("sending %s: %d", buff, cl->state);
                }
                if(ret < 0)
                {
                    LOG("antd_recv_upto() on %d: %s",rq->client->sock,  strerror(errno));
                    (void)fcgi_abort_request(cl, cl->sock);
                    antd_close(cl);
                    dput(rq->request, "FCGI_CL_DATA", NULL);
                    return antd_create_task(NULL, data, NULL, rq->client->last_io);
                }
            }
            else if(pfds[0].revents &(POLLERR | POLLHUP))
            {
                ERROR("POLLERR or POLLHUP received on %d", rq->client->sock);
                (void)fcgi_abort_request(cl, cl->sock);
                antd_close(cl);
                dput(rq->request, "FCGI_CL_DATA", NULL);
                return antd_create_task(NULL, data, NULL, rq->client->last_io);
            }
            if(pfds[1].revents & POLLIN)
            {
                if(cl->state == FCGI_CLIENT_WAIT_FOR_RESPONSE_HEADER)
                {
                    if(read_header(cl, rq) != 0)
                    {
                        antd_close(cl);
                        dput(rq->request, "FCGI_CL_DATA", NULL);
                        return antd_create_task(NULL, data, NULL, rq->client->last_io);
                    }
                }
                else
                {
                    if(read_data(cl,rq) != 0)
                    {
                        antd_close(cl);
                        dput(rq->request, "FCGI_CL_DATA", NULL);
                        return antd_create_task(NULL, data, NULL, rq->client->last_io);
                    }
                }                
            }
            else if(pfds[1].revents &(POLLERR | POLLHUP))
            {
                ERROR("POLLERR or POLLHUP received on %d", cl->sock);
                //(void)fcgi_abort_request(cl, cl->sock);
                antd_close(cl);
                dput(rq->request, "FCGI_CL_DATA", NULL);
                return antd_create_task(NULL, data, NULL, rq->client->last_io);
            }
            task = antd_create_task(process, (void *)rq, NULL, time(NULL));
            antd_task_bind_event(task, rq->client->sock, 0, TASK_EVT_ON_WRITABLE | TASK_EVT_ON_READABLE);
            antd_task_bind_event(task, cl->sock, 0, TASK_EVT_ON_READABLE);
            return task;
    }
}

static int send_request(antd_client_t *cl, antd_request_t* rq)
{
    int ret = 0;
    char *tmp = NULL;
    char *root;
    dictionary_t request = (dictionary_t)rq->request;
    dictionary_t header = (dictionary_t)dvalue(rq->request, "REQUEST_HEADER");
    ret += fcgi_begin_request(cl, cl->sock, FCGI_RESPONDER, 0);
    //ret += fcgi_send_param(cl, cl->sock, "", "");
    // ANTD specific params
    ret += fcgi_send_param(cl, cl->sock, "TMP_DIR", __plugin__.tmpdir);
    ret += fcgi_send_param(cl, cl->sock, "DB_DIR", __plugin__.dbpath);
    ret += fcgi_send_param(cl, cl->sock, "LIB_DIR", __plugin__.pdir);
    // CGI parms
    ret += fcgi_send_param(cl, cl->sock, "GATEWAY_INTERFACE", "CGI/1.1");
    ret += fcgi_send_param(cl, cl->sock, "SERVER_SOFTWARE", SERVER_NAME);
    root = (char *)dvalue(request, "SERVER_WWW_ROOT");
    tmp = (char *)dvalue(request, "REQUEST_URI");
    if (!tmp)
    {
        ret += fcgi_send_param(cl, cl->sock, "PATH_INFO", "");
        ret += fcgi_send_param(cl, cl->sock, "REQUEST_URI", "");
    }
    else
    {
        ret += fcgi_send_param(cl, cl->sock, "PATH_INFO", tmp);
        ret += fcgi_send_param(cl, cl->sock, "REQUEST_URI", tmp);
    }

    tmp = (char *)dvalue(request, "REQUEST_QUERY");
    
    if (!tmp)
    {
        ret += fcgi_send_param(cl, cl->sock, "QUERY_STRING", "");
    }
    else
    {
        ret += fcgi_send_param(cl, cl->sock, "QUERY_STRING", tmp);
    }

    tmp = (char *)dvalue(request, "METHOD");
    if (tmp)
    {
        ret += fcgi_send_param(cl, cl->sock, "REQUEST_METHOD", tmp);
    }
    tmp = (char *)dvalue(header, "Content-Type");
    if (tmp)
    {
        ret += fcgi_send_param(cl, cl->sock, "CONTENT_TYPE", tmp);
    }
    else
    {
        ret += fcgi_send_param(cl, cl->sock, "CONTENT_TYPE", "");
    }
    tmp = (char *)dvalue(header, "Content-Length");
    if (tmp)
    {
        cl->state = atoi(tmp);
        ret += fcgi_send_param(cl, cl->sock, "CONTENT_LENGTH", tmp);
    }
    else
    {
        ret += fcgi_send_param(cl, cl->sock, "CONTENT_LENGTH", "");
    }
    ret += fcgi_send_param(cl, cl->sock, "DOCUMENT_ROOT", root);
    tmp = (char *)dvalue(request, "REMOTE_ADDR");
    if(tmp)
    {
        ret += fcgi_send_param(cl, cl->sock, "REMOTE_ADDR", tmp);
        ret += fcgi_send_param(cl, cl->sock, "REMOTE_HOST", tmp);
        
    }
    ret += fcgi_send_param(cl, cl->sock, "SERVER_NAME", SERVER_NAME);
    ret += fcgi_send_param(cl, cl->sock, "SERVER_PORT", (char *)dvalue(request, "SERVER_PORT"));
    ret += fcgi_send_param(cl, cl->sock, "SERVER_PROTOCOL", "HTTP/1.1");
    // add remaining header to the vars
    chain_t it;
    for_each_assoc(it, header)
    {
        tmp = __s("HTTP_%s", it->key);
        char *s = tmp;
        while (*s)
        {
            if (*s == '-')
                *s = '_';
            else if (*s != '_')
                *s = toupper((char)*s);
            s++;
        }
        ret += fcgi_send_param(cl, cl->sock, tmp, (char *)it->value);
        free(tmp);
    }
    tmp = (char *)dvalue(request, "RESOURCE_PATH");
    if (tmp)
    {
        ret += fcgi_send_param(cl, cl->sock, "SCRIPT_NAME", basename(tmp));
        //tmp = __s("%s/%s", root, tmp);
        ret += fcgi_send_param(cl, cl->sock, "SCRIPT_FILENAME", tmp);
        ret += fcgi_send_param(cl, cl->sock, "PATH_TRANSLATED", tmp);
        //free(tmp);
    }
    else
    {
        ret += fcgi_send_param(cl, cl->sock, "SCRIPT_FILENAME", "");
        ret += fcgi_send_param(cl, cl->sock, "PATH_TRANSLATED", "");
        ret += fcgi_send_param(cl, cl->sock, "SCRIPT_NAME", "");
    }
    // redirect status for php
    ret += fcgi_send_param(cl, cl->sock, "REDIRECT_STATUS", "200");
    ret += fcgi_send_param(cl, cl->sock, "", "");
    return ret;
}

void* handle(void* data)
{
    antd_request_t *rq = (antd_request_t *)data;
    // connect to socket
    int fd = open_socket();
    if(fd < 0)
    {
        antd_error(rq->client, 503, "Service unavailable");
        return antd_create_task(NULL, data, NULL, rq->client->last_io);
    }
    set_nonblock(fd);

    // write all header to fastCGI server via params
    antd_client_t* cl = (antd_client_t*) malloc(sizeof(antd_client_t));
    (void)memset(cl, 0, sizeof(antd_client_t));
    cl->sock = fd;
    time(&cl->last_io);
    cl->ssl = NULL;
    // state is used to store content lenth of the current request
    cl->state = FCGI_CLIENT_REQUEST_SENT;
    cl->z_status = 0;
    cl->z_level = ANTD_CNONE;
    cl->zstream = NULL;
    rq->client->z_level = ANTD_CNONE;

    // start the request
    
    if(send_request(cl,rq) != 0)
    {
        ERROR("Unable to send request to application: %d", fd);
        antd_error(rq->client, 500, "Internal server error");
        (void)fcgi_abort_request(cl, cl->sock);
        antd_close(cl);
        return antd_create_task(NULL, data, NULL, rq->client->last_io);
    }

    dput(rq->request, "FCGI_CL_DATA", cl);

    antd_task_t* task = antd_create_task(process, (void *)rq, NULL, time(NULL));
    //antd_task_bind_event(task, rq->client->sock, 0, TASK_EVT_ON_WRITABLE | TASK_EVT_ON_READABLE);
    //antd_task_bind_event(task, fd, 0, TASK_EVT_ON_READABLE);
    return task;
}
