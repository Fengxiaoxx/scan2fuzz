#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <string>

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"

namespace {

std::string csvEscape(llvm::StringRef value) {
  std::string result = "\"";
  for (char character : value) {
    if (character == '"') result += '"';
    result += character;
  }
  result += '"';
  return result;
}

std::string sourcePath(const llvm::DIFile &file) {
  llvm::SmallString<256> path(file.getDirectory());
  if (path.empty() || llvm::sys::path::is_absolute(file.getFilename())) {
    path = file.getFilename();
  } else {
    llvm::sys::path::append(path, file.getFilename());
  }
  llvm::sys::path::remove_dots(path, true);
  return std::string(path);
}

std::string relativeSourcePath(llvm::StringRef path, llvm::StringRef sourceRoot) {
  if (sourceRoot.empty()) return std::string(path);
  llvm::StringRef root = sourceRoot.rtrim("/");
  if (path == root) return ".";
  if (path.startswith(root) && path.size() > root.size() &&
      path[root.size()] == '/') {
    return std::string(path.drop_front(root.size() + 1));
  }
  return std::string(path);
}

std::string stripClone(llvm::StringRef name) {
  const std::size_t dot = name.rfind('.');
  if (dot == llvm::StringRef::npos || dot + 1 == name.size()) {
    return std::string(name);
  }
  const llvm::StringRef suffix = name.drop_front(dot + 1);
  if (!std::all_of(suffix.begin(), suffix.end(), [](char character) {
        return std::isdigit(static_cast<unsigned char>(character));
      })) {
    return std::string(name);
  }
  return std::string(name.take_front(dot));
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3) {
    std::cerr << "usage: extract_function_locations <module.bc> [source-root]\n";
    return 2;
  }

  llvm::LLVMContext context;
  llvm::SMDiagnostic diagnostic;
  std::unique_ptr<llvm::Module> module =
      llvm::parseIRFile(argv[1], diagnostic, context);
  if (!module) {
    diagnostic.print(argv[0], llvm::errs());
    return 1;
  }

  std::string sourceRoot;
  if (argc == 3) {
    llvm::SmallString<256> resolvedRoot;
    if (std::error_code error = llvm::sys::fs::real_path(argv[2], resolvedRoot)) {
      std::cerr << "unable to resolve source root: " << error.message() << '\n';
      return 1;
    }
    sourceRoot = std::string(resolvedRoot);
  }

  std::cout << "name,mangled,file_path,start_line,end_line,anchor_line,anchor_col\n";
  std::size_t emitted = 0;
  for (const llvm::Function &function : *module) {
    if (function.isDeclaration() || function.getName().empty()) continue;
    const llvm::DISubprogram *subprogram = function.getSubprogram();
    if (!subprogram || !subprogram->getFile() || subprogram->getLine() == 0) {
      continue;
    }

    std::uint32_t startLine = subprogram->getLine();
    std::uint32_t endLine = startLine;
    std::uint32_t anchorLine = 0;
    std::uint32_t anchorColumn = 0;
    for (const llvm::BasicBlock &block : function) {
      for (const llvm::Instruction &instruction : block) {
        const llvm::DebugLoc &location = instruction.getDebugLoc();
        if (!location || location.getLine() == 0) continue;
        const auto *scope = llvm::dyn_cast<llvm::DILocalScope>(location.getScope());
        if (!scope || scope->getSubprogram() != subprogram) continue;

        startLine = std::min(startLine, location.getLine());
        endLine = std::max(endLine, location.getLine());
        if (location.getCol() != 0 &&
            (anchorLine == 0 ||
             std::pair(location.getLine(), location.getCol()) <
                 std::pair(anchorLine, anchorColumn))) {
          anchorLine = location.getLine();
          anchorColumn = location.getCol();
        }
      }
    }
    if (anchorLine == 0) continue;

    const std::string path = relativeSourcePath(
        sourcePath(*subprogram->getFile()), sourceRoot);
    std::cout << csvEscape(function.getName()) << ','
              << csvEscape(stripClone(function.getName())) << ','
              << csvEscape(path) << ','
              << startLine << ',' << endLine << ',' << anchorLine << ','
              << anchorColumn << '\n';
    ++emitted;
  }
  std::cerr << "function locations: " << emitted << '\n';
  return emitted == 0 ? 1 : 0;
}
