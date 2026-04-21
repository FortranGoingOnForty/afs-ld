extern int ext_data;
extern int ext_fn(void);
int *p = &ext_data;
int main(void) { return *p + ext_fn() == 11 ? 0 : 1; }
