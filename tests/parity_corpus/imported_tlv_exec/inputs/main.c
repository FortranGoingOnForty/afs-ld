extern __thread long ext_tls;
int main(void) { return ext_tls == 5 ? 0 : 1; }
