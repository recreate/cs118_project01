/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "http-request.h"
#include "http-response.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

using namespace std;

char* replace_slashes_with_carets(const char* str);
char* read_socket(int sockfd, bool header_only, uint32_t init_size, size_t *sz);
char* serve_client(int client_fd, unsigned short int client_ip, uint32_t client_port);

// If an error occurs, print out the error message and exit
void check_error(int error, const char* s) {
  if (error == -1) {
    perror(s);
    exit(1);
  }
}

int main (int argc, char *argv[])
{
  int portNum = 14805;
  //int portNum = 13862;
  char port[6];
  sprintf(port, "%d", portNum);
  
  // Set up the listen socket
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  check_error(listen_fd, "socket() error");

  int yes = 1;
  int err = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
  check_error(yes, "setsockopt() error");

  // Specify the need for the IPv4 address
  struct addrinfo hints;  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  struct addrinfo * results;

  // Get the IPv4 address of host lnxsrv.seas.ucla.edu
  err = getaddrinfo(NULL, port, &hints, &results);
  if (err != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
    exit(0);
  }

  // Bind the socket to the IPv4 address
  err = bind(listen_fd, (struct sockaddr*)(results->ai_addr), results->ai_addrlen);
  check_error(err, "bind() error");
  
  // Mark this socket as a listening socket with a queue of 10 connections
  err = listen(listen_fd, 10);
  check_error(err, "listen() error");

  // Accept up to 10 connections
  for (int i = 0; i < 10; i++) {  

    // Accpet a connection from a client
    struct sockaddr_in peerAddr;
    socklen_t peerAddr_size = sizeof(peerAddr);
    int client_fd = accept(listen_fd, (struct sockaddr*)(&peerAddr), &peerAddr_size);
    check_error(client_fd, "accept() error");

    pid_t pid = fork();
    if (pid == 0) { // Child process
      for (int j = 0; true;) {
        char* service = serve_client(client_fd, peerAddr.sin_addr.s_addr, peerAddr.sin_port);

        if (strlen(service) == 0) {
          j++;
          if (j >= 100) {
            free(service);
            close(client_fd);
            close(listen_fd);
            freeaddrinfo(results);
            return 0;
          }
        }
        free(service);
      }
      //exit(0);
    }
  }

  close(listen_fd);
  freeaddrinfo(results);

  return 0;
}

/**
 *  Replace '/'(forward slashes) with '^'(caret)
 *  As per RFC 2396, '^'(carets) are not allowed in URIs unless escaped
 *  Should be safe to use carets in lieu of forward slashes in filenames
 *
 *  @param const char* str    c string to replace slashes with carets
 *                            Should be null terminated
 *
 *  @return char*   c string with all '/' replaced with '^'
 */
char* replace_slashes_with_carets(const char* str) {
  size_t len = strlen(str);
  char* retstr = (char*)malloc(len * sizeof(char));
  size_t i = 0;
  for (; i < len; i++) {
    if (str[i] == '/') {
      retstr[i] = '^';
    } else {
      retstr[i] = str[i];
    }
  }
  retstr[i] = '\0';

  return retstr;
}

/**
 *  Reads data from a specified socket and returns a buffer with read data
 *
 *  @param int sockfd   socket file descriptor to read from
 *  @param bool header_only   only read in the HTTP header (for client request)
 *  @param uint32_t init_size  initial size of buffer
 *  @param size_t *sz   stores the buffer size up to null byte
 *
 *  @return char*   buffer with data read from socket
 */
char* read_socket(int sockfd, bool header_only, uint32_t init_size, size_t *sz) {
  uint32_t read_amt = init_size * sizeof(char) / 2;    // Amount of data to read from each recv() call
  char* buf = (char *)malloc(init_size * sizeof(char));   //Buffer for data
  size_t buf_size = init_size * sizeof(char);    // Total size of buffer
  int bytes_read = 0;   // Number of bytes read from client
  size_t offset = 0 * sizeof(char);     // Multiples of sizeof(char); offset into buf array

  char nm[] = "304 Not Modified";
  char cl[] = "Content-Length:";
  char cl2[] = "Content-length:";
  char endline[] = "\r\n";
  char hdend[] = "\r\n\r\n";
  bool check_header = true;
  bool check_len = true;
  size_t content_len = 0;
  size_t header_len = 0;
  size_t total_size = 0;
  do {
    if (offset + read_amt >= buf_size) {
      buf = (char *)realloc(buf, 2 * buf_size); // Double the size of buffer
      buf_size *= 2;
    }
    bytes_read = recv(sockfd, buf+offset, read_amt, 0);
    check_error(bytes_read, "recv() error");
    offset = offset + (bytes_read * sizeof(char));
    if (header_only && offset >= 4 * sizeof(char) && 
        buf[offset/sizeof(char) - 4] == '\r' &&
        buf[offset/sizeof(char) - 3] == '\n' &&
        buf[offset/sizeof(char) - 2] == '\r' &&
        buf[offset/sizeof(char) - 1] == '\n'  ) {
      break;
    }

    // Check for Content-Length
    char* p = strstr(buf, cl);
    if (check_len && p != NULL) {
      char* e = strstr(p, endline);
      if (e != NULL) {
        int i = e - p;
        char temp[40];
        strncpy(temp, p + 16*sizeof(char), i - 16*sizeof(char));
        content_len = atoi(temp);
        check_len = false;
      }
    }

    p = strstr(buf, cl2);
    if (check_len && p != NULL) {
      char* e = strstr(p, endline);
      if (e != NULL) {
        int i = e - p;
        char temp[40];
        strncpy(temp, p + 16*sizeof(char), i - 16*sizeof(char));
        content_len = atoi(temp);
        check_len = false;
      }
    }

    if (!check_header && offset >= total_size) {
      break;
    }

    // Check for /r/n/r/n after getting Content-Length
    char* header_end = strstr(buf, hdend);
    if (!check_len && check_header && header_end != NULL) {
      header_len = header_end - buf;
      total_size = (content_len + header_len + 4) * sizeof(char);
      check_header = false;
    }

    if (!check_header && offset >= total_size) {
      break;
    }

    // Special case when there is a 304 in the header and no content length
    char* svc = strstr(buf, nm);
    if (header_end != NULL && svc != NULL && check_len) {
      break;
    }

  } while(bytes_read > 0);

  // Null terminate the buffer
  buf[offset/sizeof(char)] = '\0';
  *sz = offset/sizeof(char);
  
  return buf;
}

/**
 * Recieve data from client; check cache; send data back if cache hit;
 * otherwise, send client data to specified remote server; 
 * read data from remote server; send data back to client
 *
 * @param int client_fd   Socket file descriptor for client
 * @param unsigned short int client_ip    IPv4 address of client
 * @param uint32_t client_port    Port number of client
 *
 * @return char*    Data read from remote server or cache
 */
char* serve_client(int client_fd, unsigned short int client_ip, uint32_t client_port) {
  bool conditional_GET = false;

  // Read data from client
  size_t client_buf_size = 0;
  const char* client_buf;
  client_buf = read_socket(client_fd, true, 50, &client_buf_size);

  // Parse HTTP headers from client
  HttpRequest client_http_request;
  try {
    client_http_request.ParseRequest(client_buf, client_buf_size + 1);
  } catch (exception &e) {
    //printf("HTTP request parse error: %s\n", e.what());
    free((void*)client_buf);
    char* empty = (char*)malloc(1 * sizeof(char));
    empty[0] = '\0';
    return empty;
  }
  
  // Format the client request
  size_t formatted_size = client_http_request.GetTotalLength();
  char* formatted_client_buf = (char*)malloc(formatted_size);
  client_http_request.FormatRequest(formatted_client_buf);
  
  // Check if the cache already has the webpage
  // Get address info on host, port pair
  char* rmsrv_host = replace_slashes_with_carets(client_http_request.GetHost().c_str());
  char* rmsrv_path = replace_slashes_with_carets(client_http_request.GetPath().c_str());
  char rmsrv_port[6];
  sprintf(rmsrv_port, "%u", client_http_request.GetPort());

  // Get the filename for the cache file, based on host name and path,
  // with slashes stripped
  size_t host_len = strlen(rmsrv_host);
  size_t path_len = strlen(rmsrv_path);
  char* filename = (char*)malloc(host_len + path_len);
  memcpy(filename, rmsrv_host, host_len);
  memcpy(filename + host_len, rmsrv_path, path_len);

  char* cache_read;
  ssize_t bytes_rd;
  // Search for the header in the cache file
  int cache_fd = open(filename, O_RDONLY, 0666);
  if (cache_fd != -1) { // Cache exists, so return it
    size_t cache_size = 100000; 
    cache_read = (char*)malloc(cache_size * sizeof(char));
    bytes_rd = read(cache_fd, cache_read, cache_size);
    check_error(bytes_rd, "read() error");
    
    // Check the Expiration header
    HttpResponse cache_resp;
    cache_resp.ParseResponse(cache_read, bytes_rd);
    string mod = cache_resp.FindHeader("Expires");
    char* cache_gmt = (char*)malloc(mod.length() * sizeof(char));
    strcpy(cache_gmt, mod.c_str());

    // This will be sent the remote server to check for expiration
    string help = cache_resp.FindHeader("Last-Modified");
    char* help2 = (char*)malloc(help.length() * sizeof(char));
    strcpy(help2, help.c_str());
    
    struct tm cache_tm;
    strptime(cache_gmt, "%a, %d %b %Y %H:%M:%S GMT", &cache_tm);
    time_t cache_gmttime = timegm(&cache_tm);
    time_t currtime = time(0);
    struct tm* curr_tm = gmtime(&currtime);
    time_t curr_gmttime = timegm(curr_tm);

    // If the expiration time is less than the current time, then we need to 
    // send a request to the remote server to update the cache, if necessary
    if (cache_gmttime < curr_gmttime) {
      // Format a conditional GET request to remote server
      //client_http_request.AddHeader("If-Modified-Since", mod);
      client_http_request.AddHeader("If-Modified-Since", help2);
      formatted_size = client_http_request.GetTotalLength();
      formatted_client_buf = (char*)malloc(formatted_size);
      client_http_request.FormatRequest(formatted_client_buf);
      conditional_GET = true;
    } else {
      // Send the cached result back to the client
      ssize_t bytes_sent = send(client_fd, cache_read, bytes_rd, 0);
      check_error(bytes_sent, "send() error");
      return cache_read;
    }
  }

  // Create new socket on the HTTP proxy server to facilitate the connection
  int rmsrv_fd = socket(AF_INET, SOCK_STREAM, 0);
  check_error(rmsrv_fd, "socket() error");

  struct addrinfo rs; memset(&rs, 0, sizeof rs);
  rs.ai_family = AF_INET;
  rs.ai_socktype = SOCK_STREAM;
  rs.ai_flags = AI_PASSIVE;
  rs.ai_protocol = 0;
  rs.ai_canonname = NULL;
  rs.ai_addr = NULL;
  rs.ai_next = NULL;
  struct addrinfo *rmsrv_addr;
  
  const char* hst = client_http_request.GetHost().c_str();
  int err = getaddrinfo(hst, rmsrv_port, &rs, &rmsrv_addr);
  if (err != 0) {
    fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(err));
    close(client_fd);
    exit(0);
  }

  // Try to connect to the host and port specified by the client's HTTP request
  err = connect(rmsrv_fd, (struct sockaddr*)(rmsrv_addr->ai_addr), rmsrv_addr->ai_addrlen);
  check_error(err, "connect() error");

  // Send the client's request to the remote server
  ssize_t bytes_sent = send(rmsrv_fd, formatted_client_buf, formatted_size, 0);
  check_error(bytes_sent, "send() error");
  
  // Get the response from the server
  size_t rmsrv_buf_size = 0;
  char* rmsrv_buf = read_socket(rmsrv_fd, false, 15000, &rmsrv_buf_size);

  // If we sent a conditional GET, then parse the remote server's response
  if (conditional_GET) {
    HttpResponse rmsrv_resp;
    rmsrv_resp.ParseResponse(rmsrv_buf, rmsrv_buf_size);
    string rmsrv_status = rmsrv_resp.GetStatusCode();
    if (rmsrv_status.compare("304") == 0) {
      // Not modified, so send the cached version
      ssize_t bytes_sent = send(client_fd, cache_read, bytes_rd, 0);
      check_error(bytes_sent, "send() error");
      return cache_read;
    }
    // Otherwise update the cache and send the new version to the client
  }
  
  // Create a new cache file and write the server response to it
  cache_fd = open(filename, O_CREAT | O_WRONLY, 0666);
  check_error(cache_fd, "open() error");

  bytes_sent = write(cache_fd, rmsrv_buf, rmsrv_buf_size);
  check_error(bytes_sent, "write() error");

  // Send information back to client
  bytes_sent = send(client_fd, rmsrv_buf, rmsrv_buf_size, 0);
  check_error(bytes_sent, "send() error");

  // Close client connection and exit
  close(rmsrv_fd);
  freeaddrinfo(rmsrv_addr);
  close(cache_fd);
  
  return rmsrv_buf;
}

