#include <unwind.h>

static _Unwind_Reason_Code cb(struct _Unwind_Context* ctx, void* arg) {
    (void)ctx;
    int* count = (int*)arg;
    (*count)++;
    return *count >= 8 ? _URC_END_OF_STACK : _URC_NO_REASON;
}

__attribute__((noinline)) int helper(void) {
    int count = 0;
    _Unwind_Backtrace(cb, &count);
    return count;
}

int main(void) {
    return helper() > 1 ? 0 : 1;
}
