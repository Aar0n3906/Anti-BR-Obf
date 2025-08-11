import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;
import unicorn.UnicornConst;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

// 修改类名以反映新方法
public class DeOllvmBr_TwoEmus {

    // --- 主模拟器实例 ---
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DalvikModule dm;
    private final Module module;

    private final AndroidEmulator tmpEmulator;
    private final VM tmpVm;
    private final Module tmpModule; // 临时模拟器加载的模块

    private static final String INPUT_SO = "D:\\unidbg\\unidbg-android\\src\\test\\resources\\AntiOllvm\\libtprt.so";
    private static final String OUTPUT_SO = "D:\\unidbg\\unidbg-android\\src\\test\\resources\\AntiOllvm\\libtprt-patch.so";
    private static final long START_ADDR = 0x87014L;
    private static final long END_ADDR = 0x88730L;
    private static final long SIMULATION_TIMEOUT_INSTRUCTIONS = 100;

    // --- 动态分析数据结构 ---
    private final Deque<InstructionContext> insStack = new ArrayDeque<>(128);
    private final Map<Long, CselInfo> cselInfoMap = new HashMap<>();
    // --- 新增：存储待模拟的任务 ---
    private final List<SimulationTask> simulationTasks = new ArrayList<>();
    private final List<Patch> patches = new ArrayList<>();
    private final Set<Long> patchedAddresses = new HashSet<>(); // 记录 Patch 应用的相对地址

    // --- Capstone & Keystone 实例 ---
    private final Capstone capstone;
    private final Keystone keystone;

    // --- 模拟控制 ---
    private UnHook mainHook = null; // 主模拟器的 Hook

    public DeOllvmBr_TwoEmus() throws IOException {
        // --- 初始化主模拟器 ---
        System.out.println("[初始化] 创建主模拟器 (emulator)...");
        emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.deobf.main")
                .build(); // 直接调用 build() 并赋值
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setVerbose(false); // 主模拟器可以不那么啰嗦

        // --- 初始化临时模拟器 ---
        System.out.println("[初始化] 创建临时模拟器 (tmpEmulator)...");
        tmpEmulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.example.deobf.tmp")
                .build(); // 直接调用 build() 并赋值
        Memory tmpMemory = tmpEmulator.getMemory();
        // 使用相同的解析器设置，确保环境一致性
        tmpMemory.setLibraryResolver(new AndroidResolver(23));
        tmpVm = tmpEmulator.createDalvikVM();
        tmpVm.setVerbose(false); // 临时模拟器也可以安静点

        // --- 加载 SO 到两个模拟器 ---
        File soFile = new File(INPUT_SO);
        if (!soFile.exists()) {
            throw new IOException("输入 SO 文件未找到: " + INPUT_SO);
        }
        System.out.println("[初始化] 加载 SO 到主模拟器...");
        dm = vm.loadLibrary(soFile, false); // 主 Dalvik 模块
        module = dm.getModule();             // 主模块

        System.out.println("[初始化] 加载 SO 到临时模拟器...");
        // 临时模拟器也需要加载库，但我们不需要它的 DalvikModule 引用，只需要 Module
        // 注意：这里假设两个模拟器会将 SO 加载到相同的基地址。
        // 如果基地址不同，后续地址计算需要考虑 tmpModule.base
        DalvikModule tmpDm = tmpVm.loadLibrary(soFile, false);
        tmpModule = tmpDm.getModule();

        // 验证基地址是否一致（推荐检查）
        if (module.base != tmpModule.base) {
            System.err.printf("[警告] 主模块基址 (0x%x) 与临时模块基址 (0x%x) 不同！地址转换可能需要调整！%n",
                    module.base, tmpModule.base);
            // 如果不同，后续所有传递给 tmpEmulator 的地址都需要从 module.base 转换到 tmpModule.base
            // 例如: tmpAbsAddr = addr - module.base + tmpModule.base
            // 为了简化，以下代码假设基地址相同。
        }

        // --- 初始化工具 ---
        capstone = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
        capstone.setDetail(true);
        keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);

        System.out.printf("[主模块] %s, 基址: 0x%x, 大小: 0x%x%n", module.name, module.base, module.size);
        System.out.printf("[临时模块] %s, 基址: 0x%x, 大小: 0x%x%n", tmpModule.name, tmpModule.base, tmpModule.size);
        System.out.printf("Hook 范围 (主模拟器绝对地址): 0x%x - 0x%x%n", module.base + START_ADDR, module.base + END_ADDR);

        // --- 设置 Hook (仅在主模拟器上) ---
        setupMainEmulatorHooks();
    }

    // 设置主模拟器的 Hook
    private void setupMainEmulatorHooks() {
        if (this.mainHook != null) {
            this.mainHook.unhook();
            this.mainHook = null;
        }
        System.out.println("  [Hook管理] 正在添加主模拟器 Hook...");
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                // 主模拟器的 Hook 逻辑
                long relativeAddr = address - module.base;
                if (relativeAddr >= START_ADDR && relativeAddr <= END_ADDR) {
                    // 检查是否是已 Patch 地址 (基于最终 Patch 目标)
                    if (!patchedAddresses.contains(relativeAddr)) {
                        processInstruction(address, size, backend);
                    }
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("  [Hook管理] 主模拟器 Hook 已附加。");
                DeOllvmBr_TwoEmus.this.mainHook = unHook;
            }

            @Override
            public void detach() {
                System.out.println("  [Hook管理] 主模拟器 Hook 已分离。");
            }
        }, module.base + START_ADDR, module.base + END_ADDR, null);
    }

    // 处理主模拟器中的指令
    private void processInstruction(long absAddress, int size, Backend backend) {
        try {
            long relativeAddr = absAddress - module.base;
            if (patchedAddresses.contains(relativeAddr)) {
                return;
            }

            List<Number> currentRegisters = saveRegisters(backend);
            byte[] code = backend.mem_read(absAddress, size);
            Instruction[] insns = capstone.disasm(code, absAddress, 1);
            if (insns == null || insns.length == 0) return;
            Instruction ins = insns[0];

            InstructionContext context = new InstructionContext(relativeAddr, ins, currentRegisters);
            insStack.push(context);
            if (insStack.size() > 100) insStack.pollLast();

            System.out.printf("[MainEmu 执行] 0x%x (Rel: 0x%x): %s %s%n",
                    ins.getAddress(), relativeAddr, ins.getMnemonic(), ins.getOpStr());

            String mnemonic = ins.getMnemonic().toLowerCase();

            if ("br".equalsIgnoreCase(mnemonic)) {
                // 对br指令只进行记录，不改变执行流程
                backend.reg_write(Arm64Const.UC_ARM64_REG_PC, absAddress + 4);
                handleBranchInstruction(context);
            } else if ("csel".equalsIgnoreCase(mnemonic)) {
                handleConditionalSelect(context);
            } else if (mnemonic.startsWith("b")) {  // 处理所有b开头的指令：b, bl, blr, b.cond等
                // 对所有跳转指令，直接设置PC+4
                backend.reg_write(Arm64Const.UC_ARM64_REG_PC, absAddress + 4);
                System.out.printf("[MainEmu 跳过] %s 指令，继续执行下一条指令 0x%x%n", mnemonic, absAddress + 4);
                return;
            }

        } catch (Exception e) {
            System.err.printf("处理主模拟器指令错误 @ 0x%x: %s%n", absAddress, e.getMessage());
            e.printStackTrace();
        }
    }

    // 处理 CSEL (与之前类似，仅记录信息)
    private void handleConditionalSelect(InstructionContext currentContext) {
        Instruction ins = currentContext.instruction;
        long relativeAddr = currentContext.relativeAddr;
        String opStr = ins.getOpStr();
        String[] ops = opStr.split(",\\s*");
        if (ops.length < 4) return;

        String destReg = ops[0].trim();
        String trueReg = ops[1].trim();
        String falseReg = ops[2].trim();
        String condition = ops[3].trim().toLowerCase();
        List<Number> registersBeforeCsel = currentContext.registers; // CSEL 执行前的状态

        try {
            long trueSourceValue = getRegisterValue(trueReg, registersBeforeCsel);
            long falseSourceValue = getRegisterValue(falseReg, registersBeforeCsel);
            CselInfo info = new CselInfo(relativeAddr, destReg, condition, trueReg, falseReg, trueSourceValue, falseSourceValue);
            cselInfoMap.put(relativeAddr, info);
            System.out.printf("[MainEmu CSEL 发现] @0x%x: %s = %s ? %s(0x%x) : %s(0x%x). Cond: %s%n",
                    relativeAddr, destReg, condition, trueReg, trueSourceValue, falseReg, falseSourceValue, condition);
        } catch (IllegalArgumentException e) {
            System.err.printf("[MainEmu CSEL 错误] @0x%x: %s%n", relativeAddr, e.getMessage());
        }
    }

    // 处理 BR (仅查找匹配 CSEL 并创建任务)
    private void handleBranchInstruction(InstructionContext brContext) {
        Instruction brIns = brContext.instruction;
        long brRelativeAddr = brContext.relativeAddr;
        String brReg = brIns.getOpStr().trim();

        System.out.printf("[MainEmu BR 发现] @0x%x: br %s. 查找匹配 CSEL...%n", brRelativeAddr, brReg);

        int searchDepth = 0;
        int maxSearchDepth = 100;
        Iterator<InstructionContext> it = insStack.iterator();
        if (it.hasNext()) it.next(); // Skip self

        while (it.hasNext() && searchDepth < maxSearchDepth) {
            InstructionContext prevContext = it.next();
            long prevRelativeAddr = prevContext.relativeAddr;

            if (cselInfoMap.containsKey(prevRelativeAddr)) {
                CselInfo cselInfo = cselInfoMap.get(prevRelativeAddr);
                if (cselInfo.destinationRegister.equalsIgnoreCase(brReg)) {
                    System.out.printf("  [MainEmu BR 匹配] CSEL @0x%x. 创建模拟任务...%n", prevRelativeAddr);

                    // --- 关键：获取 CSEL 执行前的状态 ---
                    InstructionContext cselContext = findInstructionContext(prevRelativeAddr);
                    if (cselContext == null) {
                        System.err.printf("  [MainEmu 错误] 无法找到 CSEL @0x%x 的上下文! 跳过任务创建.%n", prevRelativeAddr);
                        return; // 无法获取必要的状态
                    }
                    List<Number> registersBeforeCsel = cselContext.registers;

                    // 创建模拟任务
                    SimulationTask task = new SimulationTask(
                            cselInfo,
                            brRelativeAddr,
                            registersBeforeCsel,
                            module.base + cselInfo.cselAddress, // cselAbsAddr
                            module.base + brRelativeAddr      // brAbsAddr
                    );
                    simulationTasks.add(task);
                    System.out.printf("  [MainEmu 任务已添加] CSEL 0x%x -> BR 0x%x%n", cselInfo.cselAddress, brRelativeAddr);

                    // 可选：从 Map 中移除，防止一个 CSEL 被多个 BR 错误匹配
//                     cselInfoMap.remove(prevRelativeAddr);
                    return; // 找到匹配，停止搜索
                }
            }
            searchDepth++;
        }
//         System.err.printf("[MainEmu BR 警告] @0x%x: 未找到 %s 的匹配 CSEL%n", brRelativeAddr, brReg);
    }

    // --- 新增：在临时模拟器上执行模拟 ---
    /**
     * 使用临时模拟器执行真假两个分支的模拟。
     * @param task 包含 CSEL 信息、BR 地址和 CSEL 前状态的任务
     */
    private void performSimulationsOnTmpEmu(SimulationTask task) {
        System.out.printf("%n[TmpEmu] ===> 开始模拟任务: CSEL 0x%x -> BR 0x%x ===>%n",
                task.cselInfo.cselAddress, task.brRelativeAddr);

        Backend tmpBackend = tmpEmulator.getBackend();

        // --- 模拟真分支 ---
        System.out.println("  [TmpEmu] --- 模拟真分支 (True) ---");
        long b1 = performSingleSimulation(tmpBackend, task, true);
        System.out.printf("  [TmpEmu] --- 真分支结果 b1 = 0x%x ---%n", b1);

        // --- 模拟假分支 ---
        System.out.println("  [TmpEmu] --- 模拟假分支 (False) ---");
        long b2 = performSingleSimulation(tmpBackend, task, false);
        System.out.printf("  [TmpEmu] --- 假分支结果 b2 = 0x%x ---%n", b2);

        // --- 处理结果 ---
        if (b1 != -1 && b2 != -1) { // 检查模拟是否成功
            if (b1 != b2) {
                System.out.printf("  [TmpEmu 成功] 发现不同跳转目标: 真=0x%x, 假=0x%x. 生成 Patch.%n", b1, b2);
                // 注意：generatePatch 需要绝对地址 b1, b2
                generatePatch(task.cselInfo, task.brRelativeAddr, b1, b2);
            } else {
                System.out.printf("  [TmpEmu 注意] 真假分支目标相同 (0x%x). 无需 Patch 或为其他模式.%n", b1);
            }
        } else {
            System.err.printf("  [TmpEmu 失败] 模拟未能确定跳转目标 (b1=0x%x, b2=0x%x).%n", b1, b2);
        }
        System.out.printf("[TmpEmu] <=== 模拟任务结束: CSEL 0x%x -> BR 0x%x <===%n",
                task.cselInfo.cselAddress, task.brRelativeAddr);
    }

    /**
     * 在临时模拟器上执行单次模拟（真或假）。
     * @param tmpBackend 临时模拟器的后端
     * @param task       模拟任务信息
     * @param simulateTrueBranch 是否模拟真分支
     * @return 模拟得到的 BR 寄存器的绝对地址值，失败返回 -1
     */
    private long performSingleSimulation(Backend tmpBackend, SimulationTask task, boolean simulateTrueBranch) {
        long targetAbsAddress = -1;
        final UnHook[] tempHookHolder = { null }; // 用于停止模拟的 Hook

        try {
            // 1. 恢复 tmpEmulator 状态到 CSEL 执行前
            System.out.println("    [TmpEmu] 恢复寄存器状态至 CSEL 之前...");
            restoreRegisters(tmpBackend, task.registersBeforeCsel);

            // 2. 强制修改 CSEL 目标寄存器的值
            long valueToForce = simulateTrueBranch ? task.cselInfo.trueSourceValue : task.cselInfo.falseSourceValue;
            int destRegId = getRegisterId(task.cselInfo.destinationRegister);
            if (destRegId == -1) {
                System.err.printf("    [TmpEmu 错误] 无法识别 CSEL 目标寄存器: %s%n", task.cselInfo.destinationRegister);
                return -1;
            }
            tmpBackend.reg_write(destRegId, valueToForce);
            System.out.printf("    [TmpEmu] 强制设置 %s = 0x%x (%s 分支)%n",
                    task.cselInfo.destinationRegister, valueToForce, simulateTrueBranch ? "真" : "假");

            // 3. 设置起始 PC (CSEL 指令之后)
            // 假设基地址相同，直接使用 task 中的绝对地址
            long startPc = task.cselAbsoluteAddr + 4;
            tmpBackend.reg_write(Arm64Const.UC_ARM64_REG_PC, startPc);
            System.out.printf("    [TmpEmu] 设置起始 PC = 0x%x%n", startPc);

            // 4. 设置临时 Hook 以在 BR 指令处停止
            final long[] resultHolder = {-1L};
            final boolean[] stopped = {false};
            long brAbsAddr = task.brAbsoluteAddr; // 目标停止地址

            tmpBackend.hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    if (address == brAbsAddr) {
                        System.out.printf("      [TmpEmu Hook] 到达目标 BR 地址 0x%x%n", address);
                        try {
                            int brRegId = getRegisterId(task.cselInfo.destinationRegister); // BR 使用的寄存器
                            if (brRegId != -1) {
                                resultHolder[0] = backend.reg_read(brRegId).longValue(); // 读取绝对地址
                            } else {
                                System.err.printf("      [TmpEmu Hook 错误] 无法识别 BR 寄存器: %s%n", task.cselInfo.destinationRegister);
                            }
                        } catch (Exception e) {
                            System.err.printf("      [TmpEmu Hook 错误] 读取 BR 寄存器值时出错: %s%n", e.getMessage());
                        }
                        backend.emu_stop();
                        stopped[0] = true;
                        System.out.printf("      [TmpEmu Hook] 模拟停止. 读取到 %s = 0x%x%n", task.cselInfo.destinationRegister, resultHolder[0]);
                    }
                }
                @Override public void onAttach(UnHook unHook) { tempHookHolder[0] = unHook; }
                @Override public void detach() {}
            }, startPc, brAbsAddr + 4, null); // Hook 范围

            // 5. 开始模拟执行
            System.out.printf("    [TmpEmu] 开始执行从 0x%x 到 0x%x (最多 %d 指令)%n", startPc, brAbsAddr, SIMULATION_TIMEOUT_INSTRUCTIONS);
            try {
                // 运行模拟，结束地址设为 BR 地址之后一点点，超时时间设为 SIMULATION_TIMEOUT_INSTRUCTIONS
                tmpBackend.emu_start(startPc, brAbsAddr + 8, 0, SIMULATION_TIMEOUT_INSTRUCTIONS);
            } catch (Exception emuEx) {
                if (!stopped[0]) { // 如果不是被我们的 Hook 停止的
                    System.err.printf("    [TmpEmu 执行异常] emu_start 失败或超时: %s%n", emuEx.getMessage());
                    try {
                        long currentPc = tmpBackend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                        System.err.printf("    [TmpEmu 执行异常] 模拟停止在 PC=0x%x%n", currentPc);
                    } catch (Exception pcEx) { /* ignore */ }
                } else {
                    System.out.println("    [TmpEmu] emu_start 正常停止 (由 Hook 触发)。");
                }
            }

            // 6. 获取结果 (绝对地址)
            targetAbsAddress = resultHolder[0];

        } catch (Exception e) {
            System.err.printf("    [TmpEmu 模拟严重错误]: %s%n", e.getMessage());
            e.printStackTrace();
            targetAbsAddress = -1;
        } finally {
            // 7. 清理临时 Hook
            if (tempHookHolder[0] != null) {
                tempHookHolder[0].unhook();
            }
        }
        return targetAbsAddress;
    }


    /**
     * 生成 B.cond 和 B 指令的 Patch 信息。
     * B.cond 替换原始 CSEL 指令。
     * B 替换原始 BR 指令。
     * @param cselInfo 匹配到的 CSEL 指令信息
     * @param brRelativeAddr 原始 BR 指令的相对地址
     * @param trueTargetAbsAddress 模拟得到的真分支目标绝对地址 (b1)
     * @param falseTargetAbsAddress 模拟得到的假分支目标绝对地址 (b2)
     */
    private void generatePatch(CselInfo cselInfo, long brRelativeAddr, long trueTargetAbsAddress, long falseTargetAbsAddress) {
        long cselRelativeAddr = cselInfo.cselAddress;

        // 检查地址是否已被 Patch
        if (patchedAddresses.contains(cselRelativeAddr) || patchedAddresses.contains(brRelativeAddr)) {
            System.out.printf("  [Patch 跳过] 地址 0x%x 或 0x%x 已标记 Patch.%n", cselRelativeAddr, brRelativeAddr);
            return;
        }
        if (cselRelativeAddr == brRelativeAddr || Math.abs(cselRelativeAddr - brRelativeAddr) < 4) {
            System.err.printf("  [Patch 错误/警告] CSEL (0x%x) 和 BR (0x%x) 地址相同或重叠.%n", cselRelativeAddr, brRelativeAddr);
            return; // 避免覆盖
        }

        try {
            // 获取绝对地址 (基于主模块)
            long cselAbsoluteAddr = module.base + cselRelativeAddr;
            long brAbsoluteAddr = module.base + brRelativeAddr;

            // Patch 1: 条件跳转 @ CSEL 位置 (b.cond b1)
            long offset1 = trueTargetAbsAddress - cselAbsoluteAddr;
            String condJumpAsm = String.format("b.%s #0x%x", cselInfo.condition.toLowerCase(), offset1);

            // Patch 2: 无条件跳转 @ BR 位置 (b b2)
            long offset2 = falseTargetAbsAddress - brAbsoluteAddr;
            String uncondJumpAsm = String.format("b #0x%x", offset2);

            // 添加 Patch (使用相对地址)
            patches.add(new Patch(cselRelativeAddr, condJumpAsm, trueTargetAbsAddress));
            patches.add(new Patch(brRelativeAddr, uncondJumpAsm, falseTargetAbsAddress));

            // 标记地址已 Patch
            patchedAddresses.add(cselRelativeAddr);
            patchedAddresses.add(brRelativeAddr);

            System.out.printf("    [Patch 已生成] @CSEL 0x%x: %s (目标: 0x%x)%n", cselRelativeAddr, condJumpAsm, trueTargetAbsAddress);
            System.out.printf("                   @BR   0x%x: %s (目标: 0x%x)%n", brRelativeAddr, uncondJumpAsm, falseTargetAbsAddress);

        } catch (Exception e) {
            System.err.printf("  [Patch 生成错误] @CSEL 0x%x -> BR 0x%x: %s%n", cselRelativeAddr, brRelativeAddr, e.getMessage());
            e.printStackTrace();
        }
    }

    // --- 辅助方法 (saveRegisters, restoreRegisters, getRegisterValue, getRegisterId, findInstructionContext, bytesToHex) ---
    // 这些方法基本保持不变，因为它们是通用的状态操作或查找

    private List<Number> saveRegisters(Backend backend) {
        List<Number> regs = new ArrayList<>(32);
        for (int i = Arm64Const.UC_ARM64_REG_X0; i <= Arm64Const.UC_ARM64_REG_X28; i++) regs.add(backend.reg_read(i));
        regs.add(backend.reg_read(Arm64Const.UC_ARM64_REG_FP)); regs.add(backend.reg_read(Arm64Const.UC_ARM64_REG_LR)); regs.add(backend.reg_read(Arm64Const.UC_ARM64_REG_SP));
        return regs;
    }
    private void restoreRegisters(Backend backend, List<Number> regs) {
        if (regs == null || regs.size() < 32) { System.err.println("[错误] 尝试恢复无效的寄存器列表!"); return; }
        for (int i = Arm64Const.UC_ARM64_REG_X0; i <= Arm64Const.UC_ARM64_REG_X28; i++) backend.reg_write(i, regs.get(i - Arm64Const.UC_ARM64_REG_X0));
        backend.reg_write(Arm64Const.UC_ARM64_REG_FP, regs.get(29)); backend.reg_write(Arm64Const.UC_ARM64_REG_LR, regs.get(30)); backend.reg_write(Arm64Const.UC_ARM64_REG_SP, regs.get(31));
    }
    private long getRegisterValue(String reg, List<Number> ctx) { /* ... 不变 ... */
        if (ctx == null || ctx.size() < 32) throw new IllegalArgumentException("无效的寄存器上下文列表");
        reg = reg.toLowerCase().trim();
        if ("xzr".equals(reg) || "wzr".equals(reg)) return 0L;
        int regId = getRegisterId(reg);
        if (regId != -1) {
            int index = -1;
            if (regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) index = regId - Arm64Const.UC_ARM64_REG_X0;
            else if (regId == Arm64Const.UC_ARM64_REG_FP) index = 29;
            else if (regId == Arm64Const.UC_ARM64_REG_LR) index = 30;
            else if (regId == Arm64Const.UC_ARM64_REG_SP) index = 31;
            if (index != -1 && index < ctx.size()) {
                long value = ctx.get(index).longValue();
                if (reg.startsWith("w") && !"wzr".equals(reg) && !"wsp".equals(reg)) return value & 0xFFFFFFFFL;
                return value;
            }
        }
        throw new IllegalArgumentException("不支持或无效的寄存器名称: " + reg);
    }
    private int getRegisterId(String reg) { /* ... 不变 ... */
        reg = reg.toLowerCase().trim();
        switch (reg) {
            case "x0": return Arm64Const.UC_ARM64_REG_X0; case "x1": return Arm64Const.UC_ARM64_REG_X1; case "x2": return Arm64Const.UC_ARM64_REG_X2; case "x3": return Arm64Const.UC_ARM64_REG_X3; case "x4": return Arm64Const.UC_ARM64_REG_X4; case "x5": return Arm64Const.UC_ARM64_REG_X5; case "x6": return Arm64Const.UC_ARM64_REG_X6; case "x7": return Arm64Const.UC_ARM64_REG_X7; case "x8": return Arm64Const.UC_ARM64_REG_X8; case "x9": return Arm64Const.UC_ARM64_REG_X9; case "x10": return Arm64Const.UC_ARM64_REG_X10; case "x11": return Arm64Const.UC_ARM64_REG_X11; case "x12": return Arm64Const.UC_ARM64_REG_X12; case "x13": return Arm64Const.UC_ARM64_REG_X13; case "x14": return Arm64Const.UC_ARM64_REG_X14; case "x15": return Arm64Const.UC_ARM64_REG_X15; case "x16": return Arm64Const.UC_ARM64_REG_X16; case "x17": return Arm64Const.UC_ARM64_REG_X17; case "x18": return Arm64Const.UC_ARM64_REG_X18; case "x19": return Arm64Const.UC_ARM64_REG_X19; case "x20": return Arm64Const.UC_ARM64_REG_X20; case "x21": return Arm64Const.UC_ARM64_REG_X21; case "x22": return Arm64Const.UC_ARM64_REG_X22; case "x23": return Arm64Const.UC_ARM64_REG_X23; case "x24": return Arm64Const.UC_ARM64_REG_X24; case "x25": return Arm64Const.UC_ARM64_REG_X25; case "x26": return Arm64Const.UC_ARM64_REG_X26; case "x27": return Arm64Const.UC_ARM64_REG_X27; case "x28": return Arm64Const.UC_ARM64_REG_X28; case "x29": case "fp": return Arm64Const.UC_ARM64_REG_FP; case "x30": case "lr": return Arm64Const.UC_ARM64_REG_LR; case "sp": return Arm64Const.UC_ARM64_REG_SP; case "pc": return Arm64Const.UC_ARM64_REG_PC; case "xzr": return Arm64Const.UC_ARM64_REG_XZR;
            case "w0": return Arm64Const.UC_ARM64_REG_X0; case "w1": return Arm64Const.UC_ARM64_REG_X1; case "w2": return Arm64Const.UC_ARM64_REG_X2; case "w3": return Arm64Const.UC_ARM64_REG_X3; case "w4": return Arm64Const.UC_ARM64_REG_X4; case "w5": return Arm64Const.UC_ARM64_REG_X5; case "w6": return Arm64Const.UC_ARM64_REG_X6; case "w7": return Arm64Const.UC_ARM64_REG_X7; case "w8": return Arm64Const.UC_ARM64_REG_X8; case "w9": return Arm64Const.UC_ARM64_REG_X9; case "w10": return Arm64Const.UC_ARM64_REG_X10; case "w11": return Arm64Const.UC_ARM64_REG_X11; case "w12": return Arm64Const.UC_ARM64_REG_X12; case "w13": return Arm64Const.UC_ARM64_REG_X13; case "w14": return Arm64Const.UC_ARM64_REG_X14; case "w15": return Arm64Const.UC_ARM64_REG_X15; case "w16": return Arm64Const.UC_ARM64_REG_X16; case "w17": return Arm64Const.UC_ARM64_REG_X17; case "w18": return Arm64Const.UC_ARM64_REG_X18; case "w19": return Arm64Const.UC_ARM64_REG_X19; case "w20": return Arm64Const.UC_ARM64_REG_X20; case "w21": return Arm64Const.UC_ARM64_REG_X21; case "w22": return Arm64Const.UC_ARM64_REG_X22; case "w23": return Arm64Const.UC_ARM64_REG_X23; case "w24": return Arm64Const.UC_ARM64_REG_X24; case "w25": return Arm64Const.UC_ARM64_REG_X25; case "w26": return Arm64Const.UC_ARM64_REG_X26; case "w27": return Arm64Const.UC_ARM64_REG_X27; case "w28": return Arm64Const.UC_ARM64_REG_X28; case "w29": return Arm64Const.UC_ARM64_REG_FP; case "w30": return Arm64Const.UC_ARM64_REG_LR; case "wzr": return Arm64Const.UC_ARM64_REG_WZR;
            default: return -1;
        }
    }
    private InstructionContext findInstructionContext(long relativeAddr) { /* ... 不变 ... */
        for (InstructionContext ctx : insStack) if (ctx.relativeAddr == relativeAddr) return ctx; return null;
    }
    private static String bytesToHex(byte[] bytes) { /* ... 不变 ... */
        if (bytes == null) return "null"; StringBuilder sb = new StringBuilder(); for (byte b : bytes) sb.append(String.format("%02X ", b)); return sb.toString().trim();
    }

    // --- 应用 Patch (不变) ---
    private void applyPatches() {
        if (patches.isEmpty()) { System.out.println("没有生成任何 Patch。"); return; }
        System.out.printf("%n准备应用 %d 个 Patch 到 %s...%n", patches.size(), OUTPUT_SO);
        File inputFile = new File(INPUT_SO); File outputFile = new File(OUTPUT_SO);
        try (FileInputStream fis = new FileInputStream(inputFile); FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] buffer = fis.readAllBytes(); int appliedCount = 0;
            for (Patch p : patches) {
                if (p.address < 0 || p.address + 4 > buffer.length) { System.err.printf("跳过 Patch: 地址 0x%x 超出文件范围 (0x%x)%n", p.address, buffer.length); continue; }
                try {
                    long absPatchAddr = module.base + p.address; // 使用主模块基址计算汇编地址
                    KeystoneEncoded encoded = keystone.assemble(p.instruction); // 提供汇编地址
                    byte[] machineCode = encoded.getMachineCode();
                    if (machineCode == null || machineCode.length != 4) { System.err.printf("Keystone 错误: 汇编 '%s' 失败或长度不正确 (%d bytes) @ 0x%x (Abs: 0x%x)%n", p.instruction, machineCode != null ? machineCode.length : 0, p.address, absPatchAddr); continue; }
                    System.arraycopy(machineCode, 0, buffer, (int) p.address, 4);
                    System.out.printf("  已应用 @0x%x: %s -> %s (模拟目标: 0x%x)%n", p.address, p.instruction, bytesToHex(machineCode), p.targetAddress);
                    appliedCount++;
                } catch (Exception ke) { System.err.printf("Keystone 汇编失败 @0x%x 指令 '%s': %s%n", p.address, p.instruction, ke.getMessage()); }
            }
            fos.write(buffer); System.out.printf("成功应用 %d 个 Patch 到 %s%n", appliedCount, outputFile.getName());
        } catch (IOException e) { System.err.println("应用 Patch 到文件时出错: " + e.getMessage()); e.printStackTrace(); }
        finally { if (keystone != null) keystone.close(); }
    }

    // --- 内部数据结构 ---
    static class InstructionContext { /* ... 不变 ... */
        final long relativeAddr; final Instruction instruction; final List<Number> registers;
        InstructionContext(long addr, Instruction ins, List<Number> regs) { this.relativeAddr = addr; this.instruction = ins; this.registers = regs; }
    }
    static class CselInfo { /* ... 不变 ... */
        final long cselAddress; final String destinationRegister; final String condition; final String trueSourceReg; final String falseSourceReg; final long trueSourceValue; final long falseSourceValue;
        CselInfo(long addr, String destReg, String cond, String trueReg, String falseReg, long tVal, long fVal) { this.cselAddress = addr; this.destinationRegister = destReg; this.condition = cond; this.trueSourceReg = trueReg; this.falseSourceReg = falseReg; this.trueSourceValue = tVal; this.falseSourceValue = fVal; }
    }
    static class Patch { /* ... 不变 ... */
        final long address; final String instruction; final long targetAddress;
        Patch(long addr, String ins, long target) { this.address = addr; this.instruction = ins; this.targetAddress = target; }
    }
    // --- 新增：模拟任务的数据结构 ---
    static class SimulationTask {
        final CselInfo cselInfo;
        final long brRelativeAddr;
        final List<Number> registersBeforeCsel; // CSEL 执行前的寄存器状态
        final long cselAbsoluteAddr;
        final long brAbsoluteAddr;

        SimulationTask(CselInfo cselInfo, long brRelativeAddr, List<Number> registersBeforeCsel, long cselAbsAddr, long brAbsAddr) {
            this.cselInfo = cselInfo;
            this.brRelativeAddr = brRelativeAddr;
            this.registersBeforeCsel = registersBeforeCsel; // 存储状态
            this.cselAbsoluteAddr = cselAbsAddr;
            this.brAbsoluteAddr = brAbsAddr;
        }
    }

    // --- 主执行逻辑 ---
    public static void main(String[] args) {
        System.out.println("启动 DeOllvmBr (双模拟器方法)...");
        DeOllvmBr_TwoEmus deobf = null;

        try {
            // 1. 初始化 (会创建两个模拟器并加载 SO)
            deobf = new DeOllvmBr_TwoEmus();

            // 2. 执行主模拟器代码以收集任务
            System.out.println("\n[阶段 1] 执行主模拟器以查找 CSEL-BR 模式并收集任务...");
            // ==================================================================
            // !!! 重要: 修改这里来调用包含混淆代码的函数 !!!

            deobf.dm.callJNI_OnLoad(deobf.emulator);
            // 例如: deobf.module.callFunction(deobf.emulator, 0xYourFunctionOffset);
            // ==================================================================
            System.out.println("[阶段 1] 主模拟器执行完成。收集到 " + deobf.simulationTasks.size() + " 个模拟任务。");


            // 3. 使用临时模拟器处理收集到的任务
            System.out.println("\n[阶段 2] 使用临时模拟器处理任务并生成 Patch...");
            if (!deobf.simulationTasks.isEmpty()) {
                for (SimulationTask task : deobf.simulationTasks) {
                    deobf.performSimulationsOnTmpEmu(task);
                }
                System.out.println("[阶段 2] 所有模拟任务处理完毕。");
            } else {
                System.out.println("[阶段 2] 没有需要模拟的任务。");
            }

            // 4. 应用生成的 Patch
            System.out.println("\n[阶段 3] 应用生成的 Patch 到文件...");
            deobf.applyPatches();

        } catch (Exception e) {
            System.err.println("在执行或 Patch 过程中发生错误:");
            e.printStackTrace();
        } finally {
            // 5. 清理资源 (关闭两个模拟器)
            if (deobf != null) {
                System.out.println("\n[清理] 关闭模拟器...");
                try {
                    if (deobf.emulator != null) deobf.emulator.close();
                    System.out.println("  主模拟器已关闭。");
                } catch (IOException e) { System.err.println("关闭主模拟器时出错: " + e.getMessage()); }
                try {
                    if (deobf.tmpEmulator != null) deobf.tmpEmulator.close();
                    System.out.println("  临时模拟器已关闭。");
                } catch (IOException e) { System.err.println("关闭临时模拟器时出错: " + e.getMessage()); }

                if (deobf.capstone != null) deobf.capstone.close();
                // Keystone 在 applyPatches 中关闭
            }
        }
        System.out.println("\nDeOllvmBr (双模拟器方法) 执行完毕。");
    }
}