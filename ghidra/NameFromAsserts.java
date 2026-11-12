// Names default-named functions from the "bdClass::method" text of the assert/log strings they use.
// A function is named only when all such strings it references agree on one name.
// @category angelware
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NameFromAsserts extends GhidraScript {
    private static final Pattern NAME =
        Pattern.compile("^((?:bd|nLobbyManager)\\w*(?:<[^>]*>)?(?:::~?\\w+)+)\\s*(?:\\(|,|:| )");

    @Override
    public void run() throws Exception {
        int named = 0, conflicts = 0;
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            if (fn.getSymbol().getSource() != SourceType.DEFAULT) {
                continue;
            }
            Set<String> names = new HashSet<>();
            for (Instruction insn : currentProgram.getListing().getInstructions(fn.getBody(), true)) {
                for (Reference ref : insn.getReferencesFrom()) {
                    Data data = getDataAt(ref.getToAddress());
                    if (data == null || !data.hasStringValue()) {
                        continue;
                    }
                    String s = StringDataInstance.getStringDataInstance(data).getStringValue();
                    Matcher m = s == null ? null : NAME.matcher(s);
                    if (m != null && m.find()) {
                        names.add(m.group(1).replaceAll("<[^>]*>", ""));
                    }
                }
            }
            if (names.size() != 1) {
                conflicts += names.size() > 1 ? 1 : 0;
                continue;
            }
            String path = names.iterator().next();
            int sep = path.lastIndexOf("::");
            Namespace ns = NamespaceUtils.createNamespaceHierarchy(path.substring(0, sep), null,
                currentProgram, SourceType.ANALYSIS);
            fn.setName(path.substring(sep + 2), SourceType.ANALYSIS);
            fn.setParentNamespace(ns);
            named++;
        }
        println("named " + named + " functions, " + conflicts + " with conflicting names");
    }
}
