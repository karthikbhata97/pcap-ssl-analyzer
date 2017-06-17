#include<stdio.h>
#include<string.h>
#include<stdlib.h>
using namespace std;

void check(u_char *str, int len) {
  for(int i=0;i<len;i++) {
    printf("%x", *str);
  }
  printf("\n");
}

int main(int argc, char const *argv[]) {
  u_char *str;
  scanf("%s\n", str);
  check(str, 32);
  return 0;
}
