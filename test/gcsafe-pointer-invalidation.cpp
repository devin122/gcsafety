// RUN: %check_clang_tidy %s gcsafe-pointer-invalidation %t -- -- -I %S/Inputs

#include "gcsafety_annotations.h"

void use_ptr(Object *o);
Object *get_obj();

void func1(Object *obj) {
  gc();
  use_ptr(obj);
  // CHECK-MESSAGES: [[@LINE-1]]:11:  warning: 'obj' used after a possible GC
}

void func2(Object *obj) {
  gc();
  obj = get_obj();
  use_ptr(obj);
}
