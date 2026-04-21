__thread long ext_tls = 5;
long read_lib_tls(void) { return ext_tls; }
