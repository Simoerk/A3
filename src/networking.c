#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./networking.h"
#include "./sha256.h"

char server_ip[IP_LEN];
char server_port[PORT_LEN];
char my_ip[IP_LEN];
char my_port[PORT_LEN];

int c;

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = Fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    Fread(buffer, casc_file_size, 1, fp);
    Fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * Combine a password and salt together and hash the result to form the 
 * 'signature'. The result should be written to the 'hash' variable. Note that 
 * as handed out, this function is never called. You will need to decide where 
 * it is sensible to do so.
 */
void get_signature(char* password, char* salt, hashdata_t* hash)
{
    
    char to_hash[PASSWORD_LEN + SALT_LEN];

    memcpy(to_hash, password, PASSWORD_LEN);
    memcpy(&to_hash[PASSWORD_LEN], salt, SALT_LEN);
    get_data_sha(to_hash, *hash, PASSWORD_LEN + SALT_LEN, SHA256_HASH_SIZE);
}

/*
 * Register a new user with a server by sending the username and signature to 
 * the server
 */
void register_user(char* username, char* password, char* salt)
{
    rio_t rio;
    hashdata_t hash;
    get_signature(password, salt, &hash);
    char to_send[REQUEST_HEADER_LEN];

    memcpy(to_send, username, USERNAME_LEN);
    memcpy(&to_send[USERNAME_LEN], &hash, SHA256_HASH_SIZE);
    u_int32_t length = 0;
    memcpy(&to_send[16+SHA256_HASH_SIZE], &length, 4);
    
    int server_socket = Open_clientfd(server_ip, server_port);

    Rio_readinitb(&rio, server_socket);

    Rio_writen(server_socket, to_send, REQUEST_HEADER_LEN);

    char response[MAX_MSG_LEN];
    Rio_readnb(&rio, response, MAX_MSG_LEN);

    char response_header[RESPONSE_HEADER_LEN];
    memcpy(response_header, response, RESPONSE_HEADER_LEN);

    uint32_t payload_length = ntohl(*(uint32_t*)&response_header);
    uint32_t status_code = ntohl(*(uint32_t*)&response_header[4]);
    uint32_t block_number = ntohl(*(uint32_t*)&response_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&response_header[12]);

    hashdata_t block_hash;
    memcpy(block_hash, &response_header[16], SHA256_HASH_SIZE);

    hashdata_t total_hash;
    memcpy(total_hash, &response_header[16+SHA256_HASH_SIZE], SHA256_HASH_SIZE);


    hashdata_t hash_payload;
    get_data_sha(&response[RESPONSE_HEADER_LEN], &hash_payload, payload_length, SHA256_HASH_SIZE);

    for (int i = 0; i < SHA256_HASH_SIZE; i++)
    {
        if (hash_payload[i] != block_hash[i])
        {
            printf("Block hash does not match payload hash in register user");
            exit(1);
        }
    }

    if (status_code == 1){
        printf("%s\n", &response[RESPONSE_HEADER_LEN]);
    } else {
        printf("Error: %s\n", &response[RESPONSE_HEADER_LEN]);
    }
    
    printf("\n");
    close(server_socket);
}

/*
 * Get a file from the server by sending the username and signature, along with
 * a file path. Note that this function should be able to deal with both small 
 * and large files. 
 */
void get_file(char* username, char* password, char* salt, char* to_get)
{
    //Create message
    rio_t rio;
    hashdata_t hash;
    uint32_t length = htonl(strlen(to_get));
    get_signature(password, salt, &hash);
    char to_send[REQUEST_HEADER_LEN+strlen(to_get)];
    memcpy(to_send, username, USERNAME_LEN);
    memcpy(&to_send[USERNAME_LEN], &hash, SHA256_HASH_SIZE);
    memcpy(&to_send[USERNAME_LEN+SHA256_HASH_SIZE], &length, 4);
    memcpy(&to_send[REQUEST_HEADER_LEN], to_get, strlen(to_get));
    
    //Send message
    int server_socket = Open_clientfd(server_ip, server_port);
    Rio_readinitb(&rio, server_socket);
    Rio_writen(server_socket, &to_send, REQUEST_HEADER_LEN + strlen(to_get));

    //Get response
    char response[MAX_MSG_LEN];
    Rio_readnb(&rio, response, MAX_MSG_LEN);

    //Get header
    char response_header[RESPONSE_HEADER_LEN];
    memcpy(response_header, response, RESPONSE_HEADER_LEN);

    uint32_t payload_length = ntohl(*(uint32_t*)&response_header);
    uint32_t status_code = ntohl(*(uint32_t*)&response_header[4]);
    uint32_t block_number = ntohl(*(uint32_t*)&response_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&response_header[12]);


    //Get first block hash
    hashdata_t block_hash;
    memcpy(block_hash, &response_header[16], SHA256_HASH_SIZE);
    //get total hash.
    hashdata_t total_hash;
    memcpy(total_hash, &response_header[16+SHA256_HASH_SIZE], SHA256_HASH_SIZE);

    //Check status
    if (status_code == 1){
        printf("First Block Status OK\n");
    } else {
        printf("Error: First block status not OK\n");
        exit(1);
    }

    //Check hash for the first block
    hashdata_t hashed_payload;
    get_data_sha(&response[RESPONSE_HEADER_LEN], &hashed_payload, payload_length, SHA256_HASH_SIZE);
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
    {
        if (hashed_payload[i] != block_hash[i])
        {
            printf("First block hash does not match payload hash");
            exit(1);
        }
    }

    //open file.
    FILE *fptr;
    fptr = fopen("test/test6.txt","w");//Hardcode way of choosing destination.

    //insert first block
    fseek(fptr, block_number*MAX_PAYLOAD, SEEK_SET);
    fprintf(fptr,"%s\n", &response[RESPONSE_HEADER_LEN]);

    //Check and process the rest of the blocks.
    for (uint32_t i = 1; i<block_count; i++)
    {
        Rio_readnb(&rio, response, MAX_MSG_LEN);
        memcpy(response_header, response, RESPONSE_HEADER_LEN);

        uint32_t payload_length = ntohl(*(uint32_t*)&response_header);
        uint32_t status_code = ntohl(*(uint32_t*)&response_header[4]);
        uint32_t block_number = ntohl(*(uint32_t*)&response_header[8]);
        uint32_t block_count = ntohl(*(uint32_t*)&response_header[12]);

        memcpy(block_hash, &response_header[16], SHA256_HASH_SIZE);

        //Check status
        if (status_code == 1){
            printf("Block nr:%d status OK\n", i);
        } else {
            printf("Error: Block %d status not OK\n", i);
            exit(1);
        }

        //Check hash for the first block
        get_data_sha(&response[RESPONSE_HEADER_LEN], &hashed_payload, payload_length, SHA256_HASH_SIZE);
        for (int j = 0; j < SHA256_HASH_SIZE; j++)
        {
            if (hashed_payload[j] != block_hash[j])
            {
                printf("Block hash does not match payload hash for block %d\n", i);
                exit(1);
            }
        }

        fseek(fptr, block_number*payload_length, SEEK_SET);
        fprintf(fptr,"%s\n", &response[RESPONSE_HEADER_LEN]);
    }


    hashdata_t client_total_hash;
    get_file_sha("test/test6.txt", client_total_hash, SHA256_HASH_SIZE);
    for (uint32_t i = 0; i < SHA256_HASH_SIZE; i++)
    {
        if (client_total_hash[i] != total_hash[i])
        {
            printf("Total block hash does not match payload hash\n");
            exit(1);
        } else {
            printf("Total block hash matches\n");
        }
    }


    fclose(fptr);
    close(server_socket);
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    // Read in configuration options. Should include a client_directory, 
    // client_ip, client_port, server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = Fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, CLIENT_IP)) {
            memcpy(my_ip, &buffer[strlen(CLIENT_IP)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_IP));
            if (!is_valid_ip(my_ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, CLIENT_PORT)) {
            memcpy(my_port, &buffer[strlen(CLIENT_PORT)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_PORT));
            if (!is_valid_port(my_port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", my_port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_IP)) {
            memcpy(server_ip, &buffer[strlen(SERVER_IP)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_IP));
            if (!is_valid_ip(server_ip)) {
                fprintf(stderr, ">> Invalid server IP: %s\n", server_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_PORT)) {
            memcpy(server_port, &buffer[strlen(SERVER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_PORT));
            if (!is_valid_port(server_port)) {
                fprintf(stderr, ">> Invalid server port: %s\n", server_port);
                exit(EXIT_FAILURE);
            }
        }        
    }
    fclose(fp);

    fprintf(stdout, "Client at: %s:%s\n", my_ip, my_port);
    fprintf(stdout, "Server at: %s:%s\n", server_ip, server_port);

    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN+1];
    
    fprintf(stdout, "Enter a username to proceed: ");
    scanf("%16s", username);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(username); i<USERNAME_LEN; i++)
    {
        username[i] = '\0';
    }
 
    fprintf(stdout, "Enter your password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Note that a random salt should be used, but you may find it easier to
    // repeatedly test the same user credentials by using the hard coded value
    // below instead, and commenting out this randomly generating section.
    for (int i=0; i<SALT_LEN; i++)
    {
        user_salt[i] = 'a' + (random() % 26);
    }
    user_salt[SALT_LEN] = '\0';
    //strncpy(user_salt, 
    //    "0123456789012345678901234567890123456789012345678901234567890123\0", 
    //    SALT_LEN+1);

    fprintf(stdout, "Using salt: %s\n", user_salt);

    // The following function calls have been added as a structure to a 
    // potential solution demonstrating the core functionality. Feel free to 
    // add, remove or otherwise edit. 

    // Register the given user
    register_user(username, password, user_salt);

    // Retrieve the smaller file, that doesn't not require support for blocks
    get_file(username, password, user_salt, "tiny.txt");

    // Retrieve the larger file, that requires support for blocked messages
    //get_file(username, password, user_salt, "hamlet.txt");//Breaker pipen?

    exit(EXIT_SUCCESS);
}
