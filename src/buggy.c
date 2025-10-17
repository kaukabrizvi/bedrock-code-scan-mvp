// bad examples for testing
#include <stdio.h>
#include <pthread.h>
char buf[8];
void *t(void* p){ for(int i=0;i<1000000;i++) buf[0]++; return NULL; }
int main(){
  sprintf(buf, "%s", "xxxxxxxxxxxxxxxx"); // overflow candidate
  pthread_t a,b; pthread_create(&a,NULL,t,NULL); pthread_create(&b,NULL,t,NULL);
  pthread_join(a,NULL); pthread_join(b,NULL);
  return 0;
}
