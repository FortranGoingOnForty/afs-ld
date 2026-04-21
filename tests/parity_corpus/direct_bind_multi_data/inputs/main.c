extern int ext_data;
extern int more_data;
int *p = &ext_data;
int *q = &more_data;
int main(void) { return (*p == 5 && *q == 9) ? 0 : 1; }
