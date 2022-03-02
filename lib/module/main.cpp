namespace clang {
namespace tidy {

int clangTidyMain(int argc, const char **argv);

} // namespace tidy
} // namespace clang

int main(int argc, const char **argv) {
  return clang::tidy::clangTidyMain(argc, argv);
}
