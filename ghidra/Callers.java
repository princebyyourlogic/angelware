// Prints callers of functions whose full name contains each argument (or at each 0x address).
// @category angelware
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class Callers extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                boolean hit = a.startsWith("0x") ? f.getEntryPoint().getOffset() == Long.decode(a)
                    : f.getName(true).contains(a);
                if (!hit) continue;
                for (Function c : f.getCallingFunctions(monitor)) {
                    println(f.getName(true) + " <- " + c.getEntryPoint() + " " + c.getName(true));
                }
            }
        }
    }
}
