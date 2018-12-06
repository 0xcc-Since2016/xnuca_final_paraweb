#include "httpd.h"
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>
#include<alloca.h>
#include "zlib.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int c, char** v)
{
    serve_forever("8080");
    return 0;
}

void http_respond_header(int);
int sanitize_uri(char* );
int sanitize_str(char* );
void printfile(char* , int);
void FUNC1(char *);
void FUNC2(char *);
void parsePara(char*);
char *request_param(const char*);
void sql_error(MYSQL *);
int checkpwd(char*);
void parsefile(char *);
void logme(char *, char*);
void request(char *);
unsigned char2digit(int);
char* hex_str(char *, int, const char*); 
static char *client_ip;


typedef struct { char *key, *value; } params;
static params reqparam[30] = {{"\0", "\x0"}};
char pwd[256];
char encoding[128];
int is_login = 0;

#define DEST_IP "127.0.0.1"
#define DEST_PORT 8080


void FUNC1(char *uri){
	
	//determine header info.
	if(strstr(uri, ".css")!=NULL){
		http_respond_header(6);
	}
	else if(strstr(uri, ".js")!=NULL){
		http_respond_header(7);
	}
	else if(strstr(uri, ".svg")!=NULL){
		http_respond_header(5);
	}
	else if(strstr(uri, ".jpg")!=NULL){
		http_respond_header(2);
	}
	else if(strstr(uri, ".png")!=NULL){
		http_respond_header(3);
	}
	else if(strstr(uri, ".ico")!=NULL){
		http_respond_header(4);
	}
	else{
	http_respond_header(1); //default case.
	}
	if(strlen(uri)==1){
		uri = "/index.html";
	}
	if(sanitize_uri(uri)==1){
		//fprintf(stderr,"I'm processing %s\n", uri);
		if(request_header("Accept-Encoding")!=NULL){
		if(strstr(request_header("Accept-Encoding"), "gzip")){
			printfile(uri, 1);
		}else{
			printfile(uri, 0);
			}	
		}else{
			printfile(uri, 0);
		}
	}else{
		//logic preventing request unsanitized uri.
		return ;
	}
	//perform ssrf queries interface.
	if(!strcmp(&uri[1], "login.html")) //can be forced to performing login and register functions.
	{
		//fprintf(stderr, "parameter: %s\n", qs);
		params *temp = reqparam;
		char *token;
		while(temp < reqparam + 30){
			char *k, *v; //token is a=b
			if(temp == reqparam){
				k = strtok(qs, "="); if(!k) break;
				v = strtok(NULL, "&"); if(!v) break;
			}else{
				k = strtok(NULL, "="); if(!k) break;
				v = strtok(NULL, "&"); if(!v) break;
			}
			temp->key   = k;
			temp->value = v;
			temp++;
			//fprintf(stderr, "params: %s %s \n", k ,v);
		}
		char *username;
		char *password;
		if((username=request_param("username"))!=NULL){
			if((password=request_param("password"))!=NULL){
				if(!strcmp(username, "admin")){
					//fprintf(stderr, "password: %s\n", password);
					if(checkpwd(password)){
						//fprintf(stderr, "check passed!\n");
						char *menu;
						if((menu=request_param("menu"))!=NULL){
							char *paras = request_param("para");
							if(!strcmp(menu, "parsefile")){
								//handle request for file 
								parsefile(paras);
							}
							else if(!strcmp(menu, "request")){
								request(paras);
							}
							else if(!strcmp(menu, "upload")){
								logme(paras, request_param("filename"));
							}
						}	
					}
				}
			}
		}
	}	
}

void FUNC2(char *uri){
	
	//determine header info.
	if(strstr(uri, ".css")!=NULL){
		http_respond_header(6);
	}
	else if(strstr(uri, ".js")!=NULL){
		http_respond_header(7);
	}
	else if(strstr(uri, ".svg")!=NULL){
		http_respond_header(5);
	}
	else if(strstr(uri, ".jpg")!=NULL){
		http_respond_header(2);
	}
	else if(strstr(uri, ".png")!=NULL){
		http_respond_header(3);
	}
	else if(strstr(uri, ".ico")!=NULL){
		http_respond_header(4);
	}
	else{
	http_respond_header(1); //default case.
	}

	if(strlen(uri)==1){
		uri = "/index.html";
	}
	//fprintf(stderr, "print my uri: %s\n", uri);
	if(sanitize_uri(uri)==1){
		//fprintf(stderr,"I'm processing %s\n", uri);
		if(request_header("Accept-Encoding")!=NULL){
		if(strstr(request_header("Accept-Encoding"), "gzip")){
			printfile(uri, 1);
		}else{
			memcpy(encoding, request_header("Accept-Encoding"), 40);
			printfile(uri, 0);
			}	
		}else{
			printfile(uri, 0);
		}

	}else{
		return ;
	}
	//hijack to Mysql Point Vuln1. Explicit vulnerability.
	if(!strcmp(&uri[1], "cart.html")){
			
		//omit the first.
		strtok(payload, "=");
		strtok(NULL, "&");
		char *key   = strtok(NULL, "=");
		char *value = strtok(NULL, "&");
		if(key==NULL || value==NULL){
			return ;
		}
		if(!strcmp(key, "cargo")){
			MYSQL *conn = sql_conn();
			char *buf = (char*)malloc(102);
			snprintf(buf, 100, "SELECT md5(%s) from cargo;", value);
			//fprintf(stderr, "buf: %s\n", buf);
			if(mysql_query(conn, buf)){
				sql_error(conn);
			}
			MYSQL_RES *result = mysql_store_result(conn);
			if(result==NULL){
				sql_error(conn);
			}
			mysql_fetch_row(result);
			MYSQL_ROW row = mysql_fetch_row(result);
			if(row[0]){
				printf(row[0]);
			}else{
				printf("%s", "(Nil)");
			}
			//clean out
			free(buf);
			mysql_free_result(result);
			mysql_close(conn);
		}
	}
	else if(!strcmp(&uri[1], "product.html")){
		//start parsing payload:
		params *par = reqparam;
		char *token;
		while(par < reqparam + 30){
			char *k, *v; //token is a=b
			if(par == reqparam){
				k = strtok(payload, "="); if(!k) break;
				v = strtok(NULL, "&"); if(!v) break;
			}else{
				k = strtok(NULL, "="); if(!k) break;
				v = strtok(NULL, "&"); if(!v) break;
			}
			par->key = k;
			par->value = v;
			par++;
			//fprintf(stderr, "params: %s %s\n", k, v);
		}
		char *query_param;
		if((query_param=request_param("id"))!=NULL){

			//reformat stack!!
			MYSQL *conn = sql_conn();

			//perform test queries:
			char *query_prefix = "SELECT * FROM cargo where cargo_id=";
			char *query_compose = (char*)malloc(strlen(query_prefix)+ strlen(query_param)+1);
			strcpy(query_compose, query_prefix);
			strcat(query_compose, query_param);
			//fprintf(stderr, "Query parameter: %s\n", query_compose);
			if(mysql_query(conn, query_compose)){
				sql_error(conn);
			}
			//retrieve datas.
			MYSQL_RES *res = mysql_store_result(conn);
			if(res==NULL){
				sql_error(conn);
			}
			int num_fields = mysql_num_fields(res); //get how many fileds are there.
			//fprintf(stderr,"total num fields: %d\n", num_fields);
			MYSQL_ROW row;
			MYSQL_FIELD *field;
			char buffer[120];
			while((row = mysql_fetch_row(res))){
				//fetch row each time
				for(int i = 0; 	i< num_fields; i++){
				//fetch column
					if(i == 0){
						while(field = mysql_fetch_field(res)){
							//puts banners
							printf("%s ", field->name);
						}
						puts("\r\n");
					}
					//printf("%s ", row[i] ? row[i]:"(Nil)");
					if(row[i]){
						if(strstr(row[i], "overdue")){	
							memcpy(buffer, row[i], strlen(row[i])+64);						}
						else{
						memcpy(buffer, row[i], strlen(row[i]));	
							}
					}else{
						memcpy(buffer, "(Nil)", 5);
					}
						printf("%s ", buffer);
				}
			}
			//clean out
			mysql_free_result(res);
			mysql_close(conn);
		}
		//fprintf(stderr, "[*]test: %s\n", request_param("mysql"));
	}	
	//fprintf(stderr, "payload: %s", payload);	
}

char* request_param(const char* key){
	
	params *p = reqparam;
	while(p->key){
		if(strcmp(p->key, key) == 0) return p->value;
		p++;
	}
	return NULL;
}

void patcher(){

	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
	for(int i=0;i<=50;i++){
		;
	}
}

void route(char *client)
{

	client_ip = client;
	if(!strcmp(method, "GET")){
		FUNC1(uri);
	}
	else if(!strcmp(method, "POST")){
		FUNC2(uri);
	}else{
		printf("Unimplemented Method");
	}

	/*
    ROUTE_START()

    ROUTE_GET("/")
    {
        http_respond_header();
		printfile("index.html");	
    }

	ROUTE_GET("/index.html")
	{
        http_respond_header();
		printfile("index.html");
	}
	
	ROUTE_GET(uri){
        http_respond_header(1);
		if(strlen(uri)==1){
			uri = "/index.html";
		}
		if(sanitize_uri(uri)==1){
			fprintf(stderr,"I'm processing %s\n", uri);
			printfile(uri);
		}
	}

    ROUTE_POST("/")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
        printf("Fetch the data using `payload` variable.\r\n");
		printf("are you here now?\r\n");
		puts(payload);
    }
  
    ROUTE_END()
	*/
}

void http_respond_header(int type){

	printf("HTTP/1.1 200 OK\r\n");
	printf("Server: ParanoidServer\r\n");
	switch(type){
		case 1: //plain text.
		printf("Content-Type: text/html\r\n");
		break;
		case 2: //jpeg
		printf("Content-Type: image/jpeg\r\n");
		break;
		case 3: //fonts?
		printf("Content-Type: image/png\r\n");
		break;	
		case 4:
		printf("Content-Type: image/x-icon\r\n");
		break;
		case 5:
		printf("Content-Type: text/xml\r\n");
		break;
		case 6:
		printf("Content-Type: text/css\r\n");
		break;
		case 7:
		printf("Content-Type: application/x-javascript\r\n");
		break;
	}
	printf("Connection: close\r\n");
	printf("\r\n"); //end
}

int sanitize_uri(char *uri){

	if(strlen(uri) > 4096){
		printf("Illegal Uri!\n");
		return 0;
	}
	if(strstr(uri, "..")!=NULL){
		printf("Illegal Uri!\n");
		return 0;
	}
	return 1;
}


int sanitize_str(char *input){

	if(strlen(input) > 1024){
		printf("Illegal String!\n");
		return 0;
	}
	if(strstr(input, "..")!=NULL){
		printf("Illegal String!\n");
		return 0;
	}
	return 1;
}

void printfile(char* filename, int is_gzip){

        char ch;
        FILE *fp;
        char *targetfile = &filename[1];
		char *path = (char*)calloc(strlen(targetfile)+7, 1);
		strcpy(path, "./www/");
		strcpy(&path[6], targetfile);
		if(is_gzip){
			//fprintf(stderr, "to be implement.\n");
			;
		}

        //fprintf(stderr, "reading filename : %s\n", path);

        fp=fopen(path, "rb");

        if(fp == NULL){
                perror("open file failed.\n");
				return ;
        }

		fseek(fp,0L,SEEK_END);
		unsigned int flen = ftell(fp);
		char *file_content = (char*)malloc(flen+1);
		if(file_content==NULL){

			fclose(fp);
			return ;
		}
		fseek(fp,0L,SEEK_SET);
		fread(file_content, flen, 1, fp);
		//fprintf(stderr,"length: %d\n", flen);
		file_content[flen]=0;
		write(1, file_content, flen);
		fclose(fp);		
		free(file_content);
}

MYSQL* sql_conn(){

        //printf("prepare sql connection!\n");
        MYSQL *con = mysql_init(NULL);
        if (con == NULL){
                fprintf(stderr, "%s\n", mysql_error(con));
                exit(-1);
        }
    	if(mysql_real_connect(con, "localhost", "root", "paranoid",
                                NULL, 0, NULL, 0)==NULL){
			sql_error(con);
        }
		if(mysql_query(con, "use shop")){
			//switch db error
			sql_error(con);
		}
		
        return con;
}

void sql_error(MYSQL *con){

	//handle errors.
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	exit(-1);
}

int checkpwd(char *pass){

	if(strlen(pass)> 64 || strlen(pass) < 20){
		return 0;
	}
	if(!strstr(pass,"admin")){
		return 0;
	}
	strcpy(pwd, pass);
	//char *ptr = (char*)malloc(strlen(pass) + 32);
	//strcpy(ptr, pass);
	strcat(pwd, pass);
	char *ptr2= &pwd[64];
	//fprintf(stderr, "ptr1: %s\n", pwd);
	//fprintf(stderr, "ptr2: %s\n", ptr2);

	for(int i=0; i<64; i++){
			if(pwd[i] ^ ptr2[63-i]){
				return 0;
			}
	}
	is_login = 1;
	return 1;
}

void parsefile(char *parameter){
	//fprintf(stderr, "para: %s ", parameter);
	//get remote ip address.
	if(!strcmp(client_ip, "127.0.0.1")){
		//ssrf source check
		//file open
		//check2 request header.
		char *checker;
		if((checker=request_header("Credentials"))==NULL){
			return ;
		}
		if(strcmp(checker, "LG GRAM")){
			return ;
		}
		char *buf = (char*)malloc(0x51);
		//fprintf(stderr, "you're at localhost!\n");
		FILE *fp3;
		if((fp3=fopen(parameter, "rb"))==NULL){
			perror("open failure");
			return ;
		}
		fgets(buf, 0x50, fp3);
		write(1, buf, 0x50); //fake an arbitrary file read.
		fclose(fp3);
		free(buf);
	}
}

void logme(char *parameter, char *filename){

	//fprintf(stderr, "para: %s ", parameter);
	if(filename == NULL || parameter == NULL){
		return ; 
	}
	char target[512];
	if(sanitize_str(parameter)==1 && sanitize_str(filename)==1){
		snprintf(target, 510, "./www/upload/%s", filename);
		FILE *fp2;
		if((fp2=fopen(target ,"wb"))==NULL){
			perror("open failure");
			return ;
		}
		fputs(parameter, fp2);
		fclose(fp2);
	}else{
		return ;
	}
}

void request(char *parameter) {
	//fprintf(stderr, "para: %s ", parameter);
	int length = strlen(parameter);
	char *request_uri = (char*)malloc(strlen(parameter)+0x20);
	hex_str(request_uri, length, parameter);

	if(sanitize_str(request_uri)!=1){
			return ;
	}
	//getchar();
	//Create socket
	int sockfd, new_fd;
	struct sockaddr_in dest_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd==-1){
		perror("Creating socket failed.\n");
		return ;
	}
	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(DEST_PORT);
	dest_addr.sin_addr.s_addr=inet_addr(DEST_IP);
	bzero(&(dest_addr.sin_zero),8);

	if(connect(sockfd,(struct sockaddr*)&dest_addr,sizeof(struct sockaddr))==-1){
		perror("Connection failed.\n");	
		return ;
	} else{
		//printf("connect success");
		//recv(sockfd,buf,MAX_DATA,0); 
		//printf("Received:%s",buf);
		char buf[632];
		char *fix_payload = "GET /%s HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: ComputerVendor\r\nCookie: nilnilnilnil\r\nConnection: close\r\nIdentity: unknown\r\n";
		snprintf(buf, 512, fix_payload, request_uri);
		if(send(sockfd, buf, strlen(buf), 0)==-1){
			printf("request failed.\n");
			return ;
		}	
		char *ret_buf = (char*)malloc(101);
		int recv_size;
		int cnt = 0;
		while(cnt < 7){
			cnt ++;
			memset(ret_buf, 0, 100);
			if((recv_size = recv(sockfd, ret_buf, 100, 0)) < 0){
				break;
			}else{
				write(1, ret_buf, 100);
			}
		}
		free(ret_buf);
		close(sockfd);
	}
}


unsigned char2digit(int ch) {
  static const char Hex[] = "0123456789ABCDEF0123456789abcdef";
  char *p = memchr(Hex, ch, 32);
  if (p) {
    return (unsigned) (p - Hex) % 16;
  }
  return (unsigned) -1;  // error value
}

// Return NULL with ill-formed string
char* hex_str(char *dest, int size, const char *src) {
  char *p = dest;
  if (size <= 0) {
    return NULL;
  }
  size--;
  while (*src) {
    if (size == 0) return NULL;
    size--;

    unsigned msb = char2digit(*src++);
    if (msb > 15) return NULL;
    unsigned lsb = char2digit(*src++);
    if (lsb > 15) return NULL;
    char ch = (char) (msb * 16 + lsb);

    // Optionally test for embedded null character
    if (ch == 0) return NULL;

    *p++ = ch;
  }
  *p = '\0';
  return dest;
}

