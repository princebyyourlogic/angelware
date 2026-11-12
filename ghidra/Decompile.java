// Prints decompiled C. Args: addresses (0x...) or name substrings; "refs:STRING" decompiles
// functions referencing strings containing STRING.
// @category angelware
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.app.script.GhidraScript;
import java.util.LinkedHashSet;
import java.util.Set;

public class Decompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<Function> fns = new LinkedHashSet<>();
        for (String a : getScriptArgs()) {
            if (a.startsWith("0x")) {
                Function f = getFunctionContaining(toAddr(Long.decode(a)));
                if (f != null) fns.add(f);
            } else if (a.startsWith("refs:")) {
                String needle = a.substring(5);
                for (Data d : currentProgram.getListing().getDefinedData(true)) {
                    if (!d.hasStringValue() || !String.valueOf(d.getValue()).contains(needle)) continue;
                    for (Reference r : getReferencesTo(d.getAddress())) {
                        Function f = getFunctionContaining(r.getFromAddress());
                        if (f != null) fns.add(f);
                    }
                }
            } else {
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    if (f.getName(true).contains(a)) fns.add(f);
                }
            }
        }
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (Function f : fns) {
            DecompileResults r = d.decompileFunction(f, 60, monitor);
            println("==== " + f.getEntryPoint() + " " + f.getName(true));
            println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : r.getErrorMessage());
        }
        d.dispose();
    }
}
