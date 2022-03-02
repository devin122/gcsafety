#ifndef GCSAFETY_GCANNOTATION_H
#define GCSAFETY_GCANNOTATION_H

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/StringRef.h"

namespace gcsafety {

AST_MATCHER(Decl, isHeapAllocated) {
  auto *attr = Node.getAttr<AnnotateAttr>();
  if (attr == nullptr) {
    return false;
  }
  return (attr->getAnnotation() == "gc::heap_allocated");
}

AST_MATCHER(Decl, isHeapPointer) {
  auto *attr = Node.getAttr<AnnotateAttr>();
  if (attr == nullptr) {
    return false;
  }
  return (attr->getAnnotation() == "gc::heap_pointer");
}

AST_MATCHER(Decl, isAllocatingFunction) {
  auto *attr = Node.getAttr<AnnotateAttr>();
  if (attr == nullptr) {
    return false;
  }
  return (attr->getAnnotation() == "gc::may_allocate");
}

} // namespace gcsafety

#endif
