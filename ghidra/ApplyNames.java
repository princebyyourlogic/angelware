// Applies hand-assigned names. Arg: TSV of "address<TAB>Namespace::name<TAB>comment".
// @category angelware
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;

public class ApplyNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.split("\t", -1);
            Function fn = getFunctionAt(toAddr(Long.decode(f[0])));
            if (fn == null) fn = createFunction(toAddr(Long.decode(f[0])), null);
            int sep = f[1].lastIndexOf("::");
            Namespace ns = sep < 0 ? currentProgram.getGlobalNamespace()
                : NamespaceUtils.createNamespaceHierarchy(f[1].substring(0, sep), null,
                    currentProgram, SourceType.USER_DEFINED);
            fn.setName(sep < 0 ? f[1] : f[1].substring(sep + 2), SourceType.USER_DEFINED);
            fn.setParentNamespace(ns);
            if (f.length > 2 && !f[2].isEmpty()) fn.setComment(f[2]);
        }
    }
}
