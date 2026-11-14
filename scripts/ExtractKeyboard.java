// Extract the explicitly selected IL2CPP tag filters and username checks.
// @category IL2CPP.Diagnostics
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.Register;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.math.BigInteger;
import java.util.*;

public class ExtractKeyboard extends GhidraScript {
    private final LinkedHashMap<Address, Function> selected = new LinkedHashMap<>();
    private final Set<Address> seeds = new HashSet<>();
    private final Map<Address, String> labels = new LinkedHashMap<>();
    private final List<String> errors = new ArrayList<>();
    private File output;
    private int successful = 0;
    private int seeded = 0;
    private int seedSuccessful = 0;
    private static final int MAX_FUNCTIONS = 100;
    private static final int MAX_INSTRUCTIONS = 12000;

    private PrintWriter writer(String name) throws IOException {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(output, name)), StandardCharsets.UTF_8));
    }

    private boolean executable(Address at) {
        MemoryBlock block = currentProgram.getMemory().getBlock(at);
        return block != null && block.isInitialized() && block.isExecute();
    }

    private Function resolve(Address at, boolean thumb, String label) throws Exception {
        if (!executable(at)) return null;
        Function f = getFunctionAt(at);
        if (f == null) {
            Function container = getFunctionContaining(at);
            if (container != null) {
                errors.add("Address inside another function: " + label + " @ " + at + " inside " + container.getEntryPoint());
                return null;
            }
        }
        // ELF exports can have placeholder functions but no listing instructions in -noanalysis mode.
        if (getInstructionAt(at) == null) {
            if (currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("ARM")) {
                Register mode = currentProgram.getRegister("TMode");
                if (mode != null) currentProgram.getProgramContext().setValue(mode, at, at, thumb ? BigInteger.ONE : BigInteger.ZERO);
            }
            disassemble(at);
        }
        if (getInstructionAt(at) == null) return null;
        if (f == null) f = createFunction(at, null);
        if (f != null) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        if (f != null && label != null) {
            f.setName("KBD_" + label, SourceType.USER_DEFINED);
        }
        return f;
    }

    private void readTargets(File manifest, PrintWriter report) throws Exception {
        List<String[]> targets = new ArrayList<>();
        for (String line : Files.readAllLines(manifest.toPath(), StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] row = line.split("\t", -1);
            if (row.length < 3) throw new IOException("Malformed targets.tsv row");
            targets.add(row);
            long raw = Long.decode(row[0]);
            Address at = currentProgram.getImageBase().add(raw & ~1L);
            labels.putIfAbsent(at, row[1]);
            if (executable(at)) createLabel(at, "SEED_" + row[1], false, SourceType.USER_DEFINED);
        }
        targets.sort(Comparator.comparingLong(row -> Long.decode(row[0])));
        for (String[] row : targets) {
            monitor.checkCancelled();
            long raw = Long.decode(row[0]);
            Address at = currentProgram.getImageBase().add(raw & ~1L);
            try {
                Function f = resolve(at, (raw & 1) != 0, row[1]);
                report.println(row[0] + "\t" + at + "\t" + row[1] + "\t" + row[2] + "\t" + (f == null ? "UNRESOLVED" : "OK"));
                if (f != null) {
                    selected.put(at, f);
                    seeds.add(at);
                } else errors.add("Unresolved seed: " + row[1] + " @ " + at);
            } catch (Exception e) {
                report.println(row[0] + "\t" + at + "\t" + row[1] + "\t" + row[2] + "\tERROR: " + e);
                errors.add(row[1] + ": " + e);
            }
            report.flush();
        }
        seeded = selected.size();
    }

    private void neighbors() throws Exception {
        // Exactly one hop from original seeds; never recursively expand the whole runtime.
        for (Function f : new ArrayList<>(selected.values())) {
            monitor.checkCancelled();
            int added = 0;
            InstructionIterator instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
            int count = 0;
            while (instructions.hasNext() && count++ < MAX_INSTRUCTIONS) {
                Instruction ins = instructions.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) continue;
                    Address at = ref.getToAddress();
                    if (selected.containsKey(at) || !executable(at)) continue;
                    if (selected.size() >= MAX_FUNCTIONS || added >= 10) break;
                    try {
                        // Context of a disassembled call destination is retained where available.
                        boolean thumb = false;
                        Register mode = currentProgram.getRegister("TMode");
                        if (mode != null) {
                            BigInteger value = currentProgram.getProgramContext().getValue(mode, at, false);
                            thumb = value != null && value.signum() != 0;
                        }
                        Function called = resolve(at, thumb, null);
                        if (called != null) { selected.put(at, called); added++; }
                    } catch (Exception e) { errors.add("Callee " + at + ": " + e); }
                }
            }
            // Broad TMP event callers are not useful; bounded game-filter/username callers only.
            if (labels.getOrDefault(f.getEntryPoint(), "").startsWith("TMP_InputField")) continue;
            ReferenceIterator callers = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            int seen = 0;
            while (callers.hasNext() && seen++ < 1000 && selected.size() < MAX_FUNCTIONS && added < 16) {
                Reference ref = callers.next();
                if (!ref.getReferenceType().isCall()) continue;
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null && !selected.containsKey(caller.getEntryPoint())) {
                    selected.put(caller.getEntryPoint(), caller);
                    added++;
                }
            }
        }
    }

    private void snapshot(Address at, PrintWriter out, String prefix, boolean followPointer) {
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(at);
            if (block == null || !block.isInitialized()) return;
            int length = (int)Math.min(96L, block.getEnd().subtract(at) + 1L);
            byte[] bytes = new byte[length];
            currentProgram.getMemory().getBytes(at, bytes);
            StringBuilder hex = new StringBuilder(), ascii = new StringBuilder();
            for (byte b : bytes) {
                int value = b & 255;
                hex.append(String.format("%02x ", value));
                ascii.append(value >= 32 && value < 127 ? (char)value : '.');
            }
            out.println(prefix + at + " block=" + block.getName());
            out.println("  HEX " + hex);
            out.println("  TXT " + ascii);
            if (followPointer && length >= currentProgram.getDefaultPointerSize()) {
                long value = currentProgram.getDefaultPointerSize() == 8
                    ? currentProgram.getMemory().getLong(at)
                    : Integer.toUnsignedLong(currentProgram.getMemory().getInt(at));
                Address pointed = toAddr(value);
                if (!pointed.equals(at) && currentProgram.getMemory().contains(pointed)) snapshot(pointed, out, "  POINTER -> ", false);
            }
        } catch (Exception e) { out.println("  UNREADABLE: " + e); }
    }

    private void dumpAll() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try (PrintWriter code = writer("keyboard_decompiled.c");
             PrintWriter disassembly = writer("keyboard_disassembly.txt");
             PrintWriter graph = writer("keyboard_callgraph.tsv");
             PrintWriter data = writer("keyboard_data_refs.txt");
             PrintWriter constants = writer("length_constant_candidates.txt")) {
            code.println("/* Approximate Ghidra output; seed labels originate from dump.cs, not verified symbols. */");
            constants.println("# Scalars 3, 25 and 1024 are candidates only; occurrence does not prove a length check.");
            graph.println("from\tinstruction\ttype\tto\tresolved_name");
            if (!decompiler.openProgram(currentProgram)) throw new IOException("Decompiler failed to open program: " + decompiler.getLastMessage());
            for (Function f : selected.values()) {
                monitor.checkCancelled();
                Address entry = f.getEntryPoint();
                boolean seed = seeds.contains(entry);
                String title = (seed ? "SEED " : "NEIGHBOR ") + f.getName(true) + " @ " + entry + " RVA=0x" + Long.toHexString(entry.subtract(currentProgram.getImageBase()));
                code.println("\n/* " + title + " */");
                disassembly.println("\n=== " + title + " ===");
                data.println("\n=== " + title + " ===");
                try {
                    DecompileResults result = decompiler.decompileFunction(f, 45, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        code.println(result.getDecompiledFunction().getC());
                        successful++;
                        if (seed) seedSuccessful++;
                    } else {
                        String message = "DECOMPILE FAILED " + title + ": " + result.getErrorMessage();
                        code.println("/* " + message.replace("*/", "* /") + " */");
                        errors.add(message);
                    }
                } catch (Exception e) {
                    errors.add("Decompiler " + title + ": " + e);
                    code.println("/* DECOMPILE EXCEPTION: " + e + " */");
                }
                code.flush();
                Set<Address> seenData = new HashSet<>();
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                int count = 0;
                while (it.hasNext() && count++ < MAX_INSTRUCTIONS) {
                    Instruction ins = it.next();
                    disassembly.println(ins.getAddress() + "  " + ins);
                    for (int operand = 0; operand < ins.getNumOperands(); operand++) {
                        for (Object object : ins.getOpObjects(operand)) {
                            if (!(object instanceof Scalar)) continue;
                            long value = ((Scalar)object).getUnsignedValue();
                            if (value == 3 || value == 25 || value == 1024) constants.println(title + " | " + ins.getAddress() + " | " + ins + " | scalar=" + value);
                        }
                    }
                    for (Reference ref : ins.getReferencesFrom()) {
                        Address destination = ref.getToAddress();
                        if (ref.getReferenceType().isFlow()) {
                            Function target = getFunctionAt(destination);
                            if (ref.getReferenceType().isCall() || target != null && !destination.equals(entry)) {
                                graph.println(entry + "\t" + ins.getAddress() + "\t" + ref.getReferenceType() + "\t" + destination + "\t" + (target == null ? "?" : target.getName(true)));
                            }
                        } else if (seenData.size() < 48 && seenData.add(destination)) {
                            snapshot(destination, data, ins.getAddress() + " -> ", true);
                        }
                    }
                }
                if (count == 0) errors.add("No listing instructions for " + title);
                if (it.hasNext()) disassembly.println("TRUNCATED: instruction limit " + MAX_INSTRUCTIONS);
                disassembly.flush(); data.flush(); graph.flush(); constants.flush();
                println(title + " completed");
            }
        } finally { decompiler.dispose(); }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Usage: ExtractKeyboard.java OUTPUT_DIR TARGETS_TSV");
        output = new File(args[0]);
        if (!output.isDirectory() && !output.mkdirs()) throw new IOException("Cannot create output directory");
        try (PrintWriter resolution = writer("target_resolution.tsv")) {
            resolution.println("rva\tghidra_address\tlabel\tgroup\tstatus");
            readTargets(new File(args[1]), resolution);
        }
        neighbors();
        dumpAll();
        try (PrintWriter summary = writer("summary.txt")) {
            summary.println("Program: " + currentProgram.getName());
            summary.println("Language: " + currentProgram.getLanguageID());
            summary.println("Ghidra image base: " + currentProgram.getImageBase());
            summary.println("Resolved unique seeds: " + seeded);
            summary.println("Decompiled seeds: " + seedSuccessful);
            summary.println("Selected functions including one-hop neighbors: " + selected.size());
            summary.println("Decompiled total: " + successful);
            summary.println("Default bundled addresses require the original ARM32 game build; a supplied dump.cs must match its binary.");
            summary.println("Native string snapshots do not decode IL2CPP metadata usage automatically.");
            summary.println("Full analysis mode improves callers/data references; targeted mode stays bounded.");
            for (String error : errors) summary.println("WARNING: " + error);
        }
        if (seeded == 0 || seedSuccessful != seeded || !errors.isEmpty()) {
            throw new IOException("Extraction incomplete; inspect summary.txt and target_resolution.tsv. Artifacts are retained.");
        }
        try (PrintWriter success = writer("SUCCESS.json")) {
            success.println("{\"resolved_seeds\":" + seeded + ",\"decompiled_seeds\":" + seedSuccessful + ",\"total_functions\":" + successful + "}");
        }
        println("Keyboard extraction completed: " + output.getAbsolutePath());
    }
}
