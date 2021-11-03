// LLVM include
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/CodeGen/ISDOpcodes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <algorithm>
#include <functional>
#include <iterator>
#include <list>

using namespace std;
using namespace llvm;

namespace {
  struct BCFPass : public FunctionPass {
    static char ID;
    BCFPass() : FunctionPass(ID) {}
    bool runOnFunction(Function &F) override {
      if (!isObfuscateable(F)) {
        errs() << "function " << F.getName() << " is not obfuscateable\n";
        return false;
      }

      list<BasicBlock *> blocks;
      for (BasicBlock &block : F) {
        blocks.push_back(&block);
      }

      for (BasicBlock *block : blocks) {
        // 原始块分割为三个基本块：entry、original、terminator
        // 通过两个恒真条件连接
        auto entryBB = block;
        auto originalBB = entryBB->splitBasicBlock(entryBB->getFirstNonPHIOrDbgOrLifetime(), Twine("original"));
        auto terminatorBB = originalBB->splitBasicBlock(--originalBB->end(), Twine("terminator"));

        // 构造伪造块
        // 这一步已经构造好了 altered 跳转 original
        auto alteredBB = createAlteredBB(originalBB, F);

        // 清理 terminator，重新构造跳转关系
        entryBB->getTerminator()->eraseFromParent();
        originalBB->getTerminator()->eraseFromParent();

        // 构造恒真条件，从 entry 跳转到 original
        auto lhs = ConstantInt::get(Type::getInt32Ty(F.getContext()), 1);
        auto rhs = ConstantInt::get(Type::getInt32Ty(F.getContext()), 1);
        auto condition = new ICmpInst(*entryBB, ICmpInst::ICMP_EQ, lhs, rhs, Twine("condition"));
        BranchInst::Create(originalBB, alteredBB, (Value *)condition, entryBB);

        // 构造恒真条件，从 original 跳转到 terminator
        auto lhs2 = ConstantInt::get(Type::getInt32Ty(F.getContext()), 1);
        auto rhs2 = ConstantInt::get(Type::getInt32Ty(F.getContext()), 1);
        auto condition2 = new ICmpInst(*originalBB, ICmpInst::ICMP_EQ, lhs, rhs, Twine("condition2"));
        BranchInst::Create(terminatorBB, alteredBB, (Value *)condition, originalBB);
      }

      return false;
    }

    bool isObfuscateable(const Function &fn) {
      if (fn.isDeclaration()) {
        return false;
      }

      if (fn.hasAvailableExternallyLinkage()) {
        return false;
      }

      if (!isInvoke(fn)) {
        return false;
      }

      return true;
    }

    bool isInvoke(const Function &fn) {
      for (const BasicBlock &bb : fn) {
        if (isa<InvokeInst>(bb.getTerminator())) {
          return false;
        }
      }
      return true;
    }

    BasicBlock *createAlteredBB(BasicBlock *original, Function &F) {
      // 构造伪造块
      ValueToValueMapTy VMap;
      auto altered = CloneBasicBlock(original, VMap, Twine("altered"), &F);

      // 修复伪造块的调试信息和元数据
      // https://bbs.pediy.com/thread-266201.htm
      auto originalInstIt = original->begin();
      for (auto &inst : *altered) {
        // NOTE:
        // 参考链接： https://bbs.pediy.com/thread-266201.htm
        //
        // ... 但是CloneBasicBlock函数进行的克隆并不是完全的克隆，第一他不会对指令的操作数进行替换，比如：
        //
        // ```
        // orig:
        //   %a = ...
        //   %b = fadd %a, ...
        //
        // clone:
        //   %a.clone = ...
        //   %b.clone = fadd %a, ... ; Note that this references the old %a and
        // not %a.clone!
        // ```
        //
        // 在clone出来的基本块中，fadd指令的操作数不是%a.clone，而是%a。
        // 所以之后要通过VMap对所有操作数进行映射，使其恢复正常：
        //
        for (auto opi = inst.op_begin(); opi != inst.op_end(); opi++) {
          Value *v = MapValue(*opi, VMap, RF_None, 0);
          if (v != 0) {
            *opi = v;
          }
        }

        // 第二，它不会对PHI Node进行任何处理，PHI Node的前驱块仍然是原始基本块的前驱块，
        // 但是新克隆出来的基本块并没有任何前驱块，所以我们要对PHI Node的前驱块进行remap：
        if (auto pn = dyn_cast<PHINode>(&inst)) {
          for (unsigned j = 0, e = pn->getNumIncomingValues(); j != e; ++j) {
            Value *v = MapValue(pn->getIncomingBlock(j), VMap, RF_None, 0);
            if (v != 0) {
              pn->setIncomingBlock(j, cast<BasicBlock>(v));
            }
          }
        }

        // 元数据
        SmallVector<pair<unsigned, MDNode *>, 4> MDs;
        inst.getAllMetadata(MDs);

        // 修复调试
        inst.setDebugLoc(originalInstIt->getDebugLoc());
        ++originalInstIt;
      }

      // 清理原来的 terminator，无条件从 altered 跳转到 original
      altered->getTerminator()->eraseFromParent();
      BranchInst::Create(original, altered);

      return altered;
    }
  };
} // namespace

char BCFPass::ID = 0;

static RegisterPass<BCFPass> X("bcf", "simple bogus control flow obfuscation", false, false);

static void loadPass(const PassManagerBuilder &builder, legacy::PassManagerBase &pm) { pm.add(new BCFPass()); }
static RegisterStandardPasses Ox(PassManagerBuilder::EP_OptimizerLast, loadPass);
static RegisterStandardPasses O0(PassManagerBuilder::EP_EnabledOnOptLevel0, loadPass);
