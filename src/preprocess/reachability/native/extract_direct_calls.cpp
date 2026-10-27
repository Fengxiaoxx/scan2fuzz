#include <iostream>
#include <string>

#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"

namespace {

std::string csvEscape(llvm::StringRef value) {
  std::string result = "\"";
  for (char c : value) {
    if (c == '"') result += '"';
    result += c;
  }
  result += '"';
  return result;
}

const llvm::Function *resolveFunction(const llvm::Value *value) {
  if (!value) return nullptr;
  const llvm::Value *stripped = value->stripPointerCasts();
  if (const auto *function = llvm::dyn_cast<llvm::Function>(stripped)) {
    return function;
  }
  if (const auto *alias = llvm::dyn_cast<llvm::GlobalAlias>(stripped)) {
    return resolveFunction(alias->getAliasee());
  }
  return nullptr;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: extract_direct_calls <module.bc>\n";
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

  std::cout << "caller_name,callee_name\n";
  for (const llvm::Function &caller : *module) {
    if (caller.isDeclaration()) continue;
    for (const llvm::BasicBlock &block : caller) {
      for (const llvm::Instruction &instruction : block) {
        const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (!call || call->isInlineAsm()) continue;
        const auto *callee = resolveFunction(call->getCalledOperand());
        if (!callee || callee->isDeclaration() || callee == &caller) continue;
        std::cout << csvEscape(caller.getName()) << ','
                  << csvEscape(callee->getName()) << '\n';
      }
    }
  }
  return 0;
}
