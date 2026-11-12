// Pre-analysis script: applies tools/snr2.py output to a raw SNR2 overlay import.
// Usage: -preScript ApplySnr2Symbols.java <syms.tsv> <text_end>
// @category angelware
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.NamespaceUtils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class ApplySnr2Symbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        List<String> lines = Files.readAllLines(Path.of(args[0]));
        long textEnd = Long.decode(args[1]);

        // Everything past the code is read-only data and SNR2 tables.
        MemoryBlock main = currentProgram.getMemory().getBlocks()[0];
        currentProgram.getMemory().split(main, toAddr(textEnd));
        MemoryBlock data = currentProgram.getMemory().getBlock(toAddr(textEnd));
        main.setName("text");
        main.setExecute(true);
        data.setName("data");
        data.setExecute(false);

        long externEnd = 0;
        for (String line : lines) {
            String[] f = line.split("\t", -1);
            if (f[1].equals("extern")) {
                externEnd = Math.max(externEnd, Long.decode(f[0]) + 8);
            }
        }
        long externBase = 0x02000000L;
        MemoryBlock ext = currentProgram.getMemory().createUninitializedBlock(
            "EXTERN", toAddr(externBase), externEnd - externBase, false);
        ext.setExecute(true);

        for (String line : lines) {
            String[] f = line.split("\t", -1);
            Address addr = toAddr(Long.decode(f[0]));
            String kind = f[1], mangled = f[2], pretty = f[3], elfAddr = f[4];
            String path = pretty.contains("(") ? pretty.substring(0, pretty.indexOf('(')) : pretty;
            int sep = path.lastIndexOf("::");
            Namespace ns = currentProgram.getGlobalNamespace();
            String name = path;
            if (sep > 0) {
                ns = NamespaceUtils.createNamespaceHierarchy(path.substring(0, sep), null,
                    currentProgram, SourceType.IMPORTED);
                name = path.substring(sep + 2);
            }
            name = name.replace(' ', '_');
            String comment = pretty + "\nmangled: " + mangled
                + (elfAddr.isEmpty() ? "" : "\nmain ELF: " + elfAddr);
            if (kind.equals("data")) {
                createLabel(addr, name, ns, true, SourceType.IMPORTED);
                setPlateComment(addr, comment);
                continue;
            }
            if (!kind.equals("extern")) {
                new DisassembleCommand(addr, null, true).applyTo(currentProgram, monitor);
            }
            Function fn = getFunctionAt(addr);
            if (fn == null) {
                fn = createFunction(addr, null);
            }
            if (fn == null) {
                println("could not create function at " + addr + " " + pretty);
                createLabel(addr, name, ns, true, SourceType.IMPORTED);
                continue;
            }
            if (fn.getSymbol().getSource() == SourceType.IMPORTED) {
                // Overloads and aliases share an address; keep the first, note the rest.
                fn.setComment(fn.getComment() == null ? comment : fn.getComment() + "\n" + comment);
                continue;
            }
            fn.setName(name, SourceType.IMPORTED);
            fn.setParentNamespace(ns);
            fn.setComment(comment);
            if (kind.equals("extern")) {
                setPlateComment(addr, comment);
            }
        }
    }
}
