// RUN: %check_clang_tidy %s gcsafe-inherit-heap-class %t -- -- -I %S/Inputs

#include "gcsafety_annotations.h"

struct Type1 : public Object {
  // CHECK-MESSAGES: [[@LINE-1]]:8: warning: a non heap allocated class class Type1 inherits from a heap allocated class
};


struct Type2 : public Object {
  // should not issue a warning since its properly annotated
} GC_SAFETY(heap_allocated);

