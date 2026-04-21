extern int ext_data;
int *p = &ext_data;
int main(void) { return *p == 5 ? 0 : 1; }
