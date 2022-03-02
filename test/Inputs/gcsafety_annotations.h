#define GC_SAFETY(x) __attribute((annotate("gc::" #x)))

void gc() GC_SAFETY(may_allocate);

struct Object {
  int i;
} GC_SAFETY(heap_allocated);
