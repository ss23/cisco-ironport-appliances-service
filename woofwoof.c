#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>
#include "getopt.h"

#define MAX_BUFFER 128
#define SECRET_PASS "woofwoof"

void usage(char *name);
void to_lower(char *str);
void fuzz_string(char *str);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
  }
  int opt;
  int index;
  char *temp_pass = {0};
  char *serial_no = {0};
  char *secret_pass = SECRET_PASS;
  char service[MAX_BUFFER] = {0};
  unsigned char digest[16] = {0};
  while ((opt = getopt(argc, argv, "p:s:h")) != -1) {
    switch (opt) {
    case 'p':
      temp_pass = optarg;
      break;
    case 's':
      serial_no = optarg;
      break;
    case 'h':
      usage(argv[0]);
      break;
    default:
      printf("Wrong Argument: %s\n", argv[1]);
      break;
    }
  }

  for (index = optind; index < argc; index++) {
    usage(argv[0]);
    exit(0);
  }

  if (temp_pass == NULL || serial_no == NULL) {
    usage(argv[0]);
    exit(0);
  }

  if ((strlen(temp_pass) <= sizeof(service)) &&
      (strlen(serial_no) <= sizeof(service))) {
    to_lower(serial_no);
    fuzz_string(temp_pass);
    strncpy(service, temp_pass, sizeof(service));
    strncat(service, serial_no, sizeof(service));
    strncat(service, secret_pass, sizeof(service));

    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, service, strlen(service));
    MD5_Final(digest, &context);
    printf("Service Password: ");
    for (int i = 0; i < sizeof(digest) - 12; i++)
      printf("%02x", digest[i]);
  }

  return 0;
}

void fuzz_string(char *str) {
  while (*str) {
    switch (*str) {
    case '1':
      *str = 'i';
      break;
    case '0':
      *str = 'o';
      break;
    case '_':
      *str = '-';
      break;
    }
    str++;
  }
}

void to_lower(char *str) {
  while (*str) {
    if (*str >= 'A' && *str <= 'Z') {
      *str += 0x20;
    }
    str++;
  }
}

void usage(char *name) {
  printf("\nUsage: %s -p password -s serial\n", name);
  printf(" -p <password> | Cisco Service Temp Password\n");
  printf(" -s <serial> | Cisco Serial Number\n");
  printf(" -h | This Help Menu\n");
  printf("\n Example: %s -p cisco123 -s 564DDFABBD0AD5F7A2E5-2C6019F508A4\n",
         name);
  exit(0);
}
