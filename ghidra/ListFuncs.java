// Lists functions in [start, end): address, size, name, callees. Args: START END
// @category angelware
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.util.stream.Collectors;

public class ListFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        for (Function f : currentProgram.getFunctionManager().getFunctions(
                currentProgram.getAddressFactory().getAddressSet(toAddr(Long.decode(a[0])), toAddr(Long.decode(a[1]))), true)) {
            String callees = f.getCalledFunctions(monitor).stream()
                .map(c -> c.getName(true)).sorted().collect(Collectors.joining(", "));
            println(f.getEntryPoint() + " " + f.getBody().getNumAddresses() + " " + f.getName(true) + " -> " + callees);
        }
    }
}
