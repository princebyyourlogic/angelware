// For each call to the lobby task factory (arg: its address), prints the task id (li a1),
// the calling function, and that function's callers.
// @category angelware
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TaskMap extends GhidraScript {
    @Override
    public void run() throws Exception {
        long factory = Long.decode(getScriptArgs()[0]);
        for (Reference r : getReferencesTo(toAddr(factory))) {
            if (!r.getReferenceType().isCall()) continue;
            Instruction insn = getInstructionAt(r.getFromAddress());
            Long task = null;
            for (int i = 0; i < 12 && insn != null; i++, insn = insn.getPrevious()) {
                if (insn.getMnemonicString().endsWith("li") || insn.getMnemonicString().equals("addiu")) {
                    if (insn.getNumOperands() >= 2 && insn.getDefaultOperandRepresentation(0).equals("a1")) {
                        task = insn.getScalar(insn.getNumOperands() - 1) == null ? null
                            : insn.getScalar(insn.getNumOperands() - 1).getValue();
                        if (task != null) break;
                    }
                }
            }
            Function f = getFunctionContaining(r.getFromAddress());
            StringBuilder callers = new StringBuilder();
            if (f != null) for (Function c : f.getCallingFunctions(monitor)) callers.append(c.getName(true)).append(' ');
            println(String.format("task %s %s <- %s", task == null ? "?" : "0x" + Long.toHexString(task),
                f == null ? "?" : f.getName(), callers));
        }
    }
}
