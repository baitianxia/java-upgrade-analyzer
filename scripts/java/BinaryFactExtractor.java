/*
 * Versioned ASM raw-fact extractor for the binary-first pipeline.
 *
 * Stdout is reserved for 4-byte big-endian length-prefixed UTF-8 JSON frames.
 * Diagnostics go to stderr. The helper never loads or initializes input classes.
 */
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.Base64;
import org.objectweb.asm.*;

public final class BinaryFactExtractor {
    private static final int MAX_INPUT_FRAME = 64 * 1024 * 1024;
    private static final String PROTOCOL_SCHEMA = "binary-fact-frame-v1";

    private BinaryFactExtractor() {}

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return out.toString();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void digestFrame(MessageDigest digest, byte[] payload) {
        digest.update(new byte[] {
            (byte) (payload.length >>> 24), (byte) (payload.length >>> 16),
            (byte) (payload.length >>> 8), (byte) payload.length
        });
        digest.update(payload);
    }

    private static byte[] nextFrame(DataInputStream in) throws IOException {
        int length;
        try {
            length = in.readInt();
        } catch (EOFException eof) {
            return null;
        }
        if (length < 2 || length > MAX_INPUT_FRAME) {
            throw new IOException("invalid input frame length: " + length);
        }
        byte[] payload = new byte[length];
        in.readFully(payload);
        return payload;
    }

    private static void writeFrame(DataOutputStream out, Map<String, Object> value,
                                   MessageDigest recordDigest, boolean counted) throws Exception {
        byte[] payload = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        if (counted) digestFrame(recordDigest, payload);
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
    }

    private static String requiredString(String json, String key) throws IOException {
        String marker = "\"" + key + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) throw new IOException("missing JSON string field: " + key);
        start += marker.length();
        int end = json.indexOf('"', start);
        if (end < 0) throw new IOException("unterminated JSON string field: " + key);
        return json.substring(start, end);
    }

    private static String decodedString(String json, String key) throws IOException {
        try {
            return new String(Base64.getDecoder().decode(requiredString(json, key)), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException error) {
            throw new IOException("invalid base64 field: " + key, error);
        }
    }

    private static Map<String, Object> linked(Object... values) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            map.put((String) values[index], values[index + 1]);
        }
        return map;
    }

    private static String asmVersion() {
        Package pkg = ClassReader.class.getPackage();
        String version = pkg == null ? null : pkg.getImplementationVersion();
        return version == null ? "unknown" : version;
    }

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("usage: BinaryFactExtractor <parser-identity> <helper-sha256> <max-class-major>");
            System.exit(64);
        }
        try {
            run(args[0], args[1], Integer.parseInt(args[2]));
        } catch (Throwable error) {
            error.printStackTrace(System.err);
            System.exit(2);
        }
    }

    private static void run(String parserIdentity, String helperSha, int maxClassMajor) throws Exception {
        DataInputStream in = new DataInputStream(new BufferedInputStream(System.in));
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(System.out));
        MessageDigest inputDigest = MessageDigest.getInstance("SHA-256");
        MessageDigest outputDigest = MessageDigest.getInstance("SHA-256");
        int inputCount = 0;
        int factCount = 0;
        int failureCount = 0;

        byte[] headerBytes = nextFrame(in);
        if (headerBytes == null) throw new IOException("input header is missing");
        String header = new String(headerBytes, StandardCharsets.UTF_8);
        if (!"input_header".equals(requiredString(header, "frame_type"))) {
            throw new IOException("first input frame must be input_header");
        }
        if (!PROTOCOL_SCHEMA.equals(requiredString(header, "protocol_schema"))) {
            throw new IOException("unsupported protocol schema");
        }
        if (!parserIdentity.equals(requiredString(header, "parser_identity"))) {
            throw new IOException("parser identity argument/header mismatch");
        }
        String expectedInputDigest = requiredString(header, "class_input_digest");
        int expectedInputCount = Integer.parseInt(requiredString(header, "class_input_count"));

        writeFrame(out, linked(
            "frame_type", "output_header",
            "protocol_schema", PROTOCOL_SCHEMA,
            "output_schema", "binary-class-fact-v1",
            "parser_identity", parserIdentity,
            "helper_sha256", helperSha,
            "asm_version", asmVersion(),
            "max_supported_class_major", maxClassMajor
        ), outputDigest, false);

        while (true) {
            byte[] payload = nextFrame(in);
            if (payload == null) throw new IOException("input footer is missing");
            String json = new String(payload, StandardCharsets.UTF_8);
            String frameType = requiredString(json, "frame_type");
            if ("input_footer".equals(frameType)) break;
            if (!"class_input".equals(frameType)) {
                throw new IOException("unexpected input frame type: " + frameType);
            }
            inputCount++;
            digestFrame(inputDigest, payload);
            String artifactIdentity = decodedString(json, "artifact_instance_identity_b64");
            String entry = decodedString(json, "class_entry_b64");
            byte[] classBytes;
            try {
                classBytes = Base64.getDecoder().decode(requiredString(json, "class_bytes_b64"));
            } catch (IllegalArgumentException error) {
                throw new IOException("invalid class_bytes_b64", error);
            }
            Map<String, Object> record;
            try {
                if (classBytes.length < 8) throw new IOException("truncated classfile");
                int major = ((classBytes[6] & 0xff) << 8) | (classBytes[7] & 0xff);
                if (major > maxClassMajor) {
                    throw new UnsupportedClassVersionError("class major " + major + " > " + maxClassMajor);
                }
                ClassFacts visitor = new ClassFacts(artifactIdentity, entry, classBytes);
                new TrackingClassReader(classBytes, visitor).accept(visitor, 0);
                record = visitor.finish();
                factCount++;
            } catch (Throwable error) {
                record = linked(
                    "frame_type", "class_failure",
                    "artifact_instance_identity", artifactIdentity,
                    "class_entry", entry,
                    "class_bytes_sha256", sha256(classBytes),
                    "failure_kind", error.getClass().getSimpleName(),
                    "failure_message", String.valueOf(error.getMessage())
                );
                failureCount++;
            }
            writeFrame(out, record, outputDigest, true);
        }

        if (nextFrame(in) != null) throw new IOException("bytes found after input footer");
        String actualInputDigest = hex(inputDigest.digest());
        if (inputCount != expectedInputCount || !actualInputDigest.equals(expectedInputDigest)) {
            throw new IOException("input count/digest mismatch");
        }
        writeFrame(out, linked(
            "frame_type", "output_footer",
            "input_record_count", inputCount,
            "fact_record_count", factCount,
            "failure_record_count", failureCount,
            "output_record_count", factCount + failureCount,
            "class_input_digest", actualInputDigest,
            "fact_output_digest", hex(outputDigest.digest()),
            "coverage_status", failureCount == 0 ? "complete" : "partial"
        ), MessageDigest.getInstance("SHA-256"), false);
    }

    private static final class TrackingClassReader extends ClassReader {
        private final ClassFacts visitor;
        TrackingClassReader(byte[] bytes, ClassFacts visitor) {
            super(bytes);
            this.visitor = visitor;
        }
        @Override protected void readBytecodeInstructionOffset(int bytecodeOffset) {
            visitor.currentBytecodeOffset = bytecodeOffset;
        }
    }

    private static final class ClassFacts extends ClassVisitor {
        private final String artifactIdentity;
        private final String entry;
        private final byte[] bytes;
        private final Map<String, Object> fact = new LinkedHashMap<>();
        private final List<Object> fields = new ArrayList<>();
        private final List<Object> methods = new ArrayList<>();
        private final List<Object> annotations = new ArrayList<>();
        private final List<Object> innerClasses = new ArrayList<>();
        private final List<Object> recordComponents = new ArrayList<>();
        private final List<Object> permittedSubclasses = new ArrayList<>();
        private int currentBytecodeOffset = -1;

        ClassFacts(String artifactIdentity, String entry, byte[] bytes) {
            super(Opcodes.ASM9);
            this.artifactIdentity = artifactIdentity;
            this.entry = entry;
            this.bytes = bytes;
        }

        @Override public void visit(int version, int access, String name, String signature,
                                    String superName, String[] interfaces) {
            fact.put("class_major", version & 0xffff);
            fact.put("class_access", access);
            fact.put("class_name", name);
            fact.put("class_signature", signature);
            fact.put("super_name", superName);
            fact.put("interfaces", interfaces == null ? List.of() : Arrays.asList(interfaces));
        }

        @Override public void visitSource(String source, String debug) {
            fact.put("source_file", source);
            fact.put("source_debug_sha256", digestNullable(debug));
        }

        @Override public ModuleVisitor visitModule(String name, int access, String version) {
            Map<String, Object> module = linked("name", name, "access", access, "version", version);
            List<Object> directives = new ArrayList<>();
            module.put("directives", directives);
            fact.put("module", module);
            return new ModuleVisitor(Opcodes.ASM9) {
                @Override public void visitMainClass(String mainClass) { directives.add(List.of("main", mainClass)); }
                @Override public void visitPackage(String packaze) { directives.add(List.of("package", packaze)); }
                @Override public void visitRequire(String module, int flags, String ver) { directives.add(Arrays.asList("requires", module, flags, ver)); }
                @Override public void visitExport(String packaze, int flags, String... modules) { directives.add(Arrays.asList("exports", packaze, flags, modules == null ? List.of() : Arrays.asList(modules))); }
                @Override public void visitOpen(String packaze, int flags, String... modules) { directives.add(Arrays.asList("opens", packaze, flags, modules == null ? List.of() : Arrays.asList(modules))); }
                @Override public void visitUse(String service) { directives.add(List.of("uses", service)); }
                @Override public void visitProvide(String service, String... providers) { directives.add(Arrays.asList("provides", service, Arrays.asList(providers))); }
            };
        }

        @Override public void visitNestHost(String nestHost) { fact.put("nest_host", nestHost); }
        @Override public void visitOuterClass(String owner, String name, String descriptor) { fact.put("outer_class", Arrays.asList(owner, name, descriptor)); }
        @Override public void visitNestMember(String nestMember) {
            ((List<Object>) fact.computeIfAbsent("nest_members", ignored -> new ArrayList<>())).add(nestMember);
        }
        @Override public void visitPermittedSubclass(String permittedSubclass) { permittedSubclasses.add(permittedSubclass); }
        @Override public void visitInnerClass(String name, String outerName, String innerName, int access) { innerClasses.add(Arrays.asList(name, outerName, innerName, access)); }

        @Override public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            return annotation(annotations, descriptor, visible);
        }
        @Override public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String descriptor, boolean visible) {
            return annotation(annotations, descriptor + "@" + typeRef + ":" + String.valueOf(typePath), visible);
        }

        @Override public RecordComponentVisitor visitRecordComponent(String name, String descriptor, String signature) {
            Map<String, Object> component = linked("name", name, "descriptor", descriptor, "signature", signature);
            List<Object> componentAnnotations = new ArrayList<>();
            component.put("annotations", componentAnnotations);
            recordComponents.add(component);
            return new RecordComponentVisitor(Opcodes.ASM9) {
                @Override public AnnotationVisitor visitAnnotation(String desc, boolean visible) { return annotation(componentAnnotations, desc, visible); }
                @Override public AnnotationVisitor visitTypeAnnotation(int ref, TypePath path, String desc, boolean visible) { return annotation(componentAnnotations, desc + "@" + ref + ":" + String.valueOf(path), visible); }
            };
        }

        @Override public FieldVisitor visitField(int access, String name, String descriptor,
                                                 String signature, Object value) {
            Map<String, Object> field = linked(
                "access", access, "name", name, "descriptor", descriptor,
                "signature", signature, "constant", constant(value)
            );
            List<Object> fieldAnnotations = new ArrayList<>();
            field.put("annotations", fieldAnnotations);
            fields.add(field);
            return new FieldVisitor(Opcodes.ASM9) {
                @Override public AnnotationVisitor visitAnnotation(String desc, boolean visible) { return annotation(fieldAnnotations, desc, visible); }
                @Override public AnnotationVisitor visitTypeAnnotation(int ref, TypePath path, String desc, boolean visible) { return annotation(fieldAnnotations, desc + "@" + ref + ":" + String.valueOf(path), visible); }
            };
        }

        @Override public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                   String signature, String[] exceptions) {
            MethodFacts method = new MethodFacts(access, name, descriptor, signature, exceptions);
            methods.add(method.fact);
            return method;
        }

        Map<String, Object> finish() throws Exception {
            fact.put("frame_type", "class_fact");
            fact.put("artifact_instance_identity", artifactIdentity);
            fact.put("class_entry", entry);
            fact.put("class_bytes_sha256", sha256(bytes));
            fact.put("class_byte_length", bytes.length);
            fact.put("annotations", annotations);
            fact.put("fields", fields);
            fact.put("methods", methods);
            fact.put("inner_classes", innerClasses);
            fact.put("record_components", recordComponents);
            fact.put("permitted_subclasses", permittedSubclasses);
            List<Object> inventory = AttributeInventory.scan(bytes);
            fact.put("attribute_inventory", inventory);
            fact.put("attribute_inventory_digest", sha256(Json.stringify(inventory).getBytes(StandardCharsets.UTF_8)));
            fact.put("class_contract_digest", sha256(Json.stringify(linked(
                "class_major", fact.get("class_major"), "class_access", fact.get("class_access"),
                "class_name", fact.get("class_name"),
                "class_signature", fact.get("class_signature"), "super_name", fact.get("super_name"),
                "interfaces", fact.get("interfaces"), "annotations", annotations,
                "fields", fields,
                "methods", methods.stream().map(item -> ((Map<?, ?>) item).get("contract")).toList(),
                "record_components", recordComponents, "permitted_subclasses", permittedSubclasses,
                "nest_host", fact.get("nest_host"), "nest_members", fact.get("nest_members"),
                "outer_class", fact.get("outer_class"), "inner_classes", innerClasses,
                "module", fact.get("module")
            )).getBytes(StandardCharsets.UTF_8)));
            return fact;
        }

        private final class MethodFacts extends MethodVisitor {
            final Map<String, Object> fact;
            final Map<String, Object> contract;
            final List<Object> annotations = new ArrayList<>();
            final List<Object> parameters = new ArrayList<>();
            final List<Object> instructions = new ArrayList<>();
            final List<Object> tryCatch = new ArrayList<>();
            final List<Object[]> rawInstructions = new ArrayList<>();
            final List<Object[]> rawTryCatch = new ArrayList<>();
            final IdentityHashMap<Label, Integer> labelPositions = new IdentityHashMap<>();

            MethodFacts(int access, String name, String descriptor, String signature, String[] exceptions) {
                super(Opcodes.ASM9);
                contract = linked(
                    "access", access, "name", name, "descriptor", descriptor,
                    "signature", signature,
                    "exceptions", exceptions == null ? List.of() : Arrays.asList(exceptions),
                    "annotations", annotations, "parameters", parameters
                );
                fact = linked("contract", contract, "instructions", instructions, "try_catch", tryCatch);
            }
            void insn(Object... values) {
                Object[] withOffset = new Object[values.length + 1];
                withOffset[0] = values[0];
                withOffset[1] = currentBytecodeOffset;
                System.arraycopy(values, 1, withOffset, 2, values.length - 1);
                rawInstructions.add(withOffset);
            }
            @Override public AnnotationVisitor visitAnnotation(String desc, boolean visible) { return annotation(annotations, desc, visible); }
            @Override public AnnotationVisitor visitTypeAnnotation(int ref, TypePath path, String desc, boolean visible) { return annotation(annotations, desc + "@" + ref + ":" + String.valueOf(path), visible); }
            @Override public AnnotationVisitor visitParameterAnnotation(int parameter, String desc, boolean visible) { return annotation(annotations, "parameter:" + parameter + ":" + desc, visible); }
            @Override public AnnotationVisitor visitAnnotationDefault() { return annotation(annotations, "<annotation-default>", true); }
            @Override public void visitAnnotableParameterCount(int count, boolean visible) { contract.put(visible ? "visible_annotable_parameter_count" : "invisible_annotable_parameter_count", count); }
            @Override public void visitParameter(String name, int access) { parameters.add(Arrays.asList(name, access)); }
            @Override public void visitInsn(int opcode) { insn("insn", opcode); }
            @Override public void visitIntInsn(int opcode, int operand) { insn("int", opcode, operand); }
            @Override public void visitVarInsn(int opcode, int varIndex) { insn("var", opcode, varIndex); }
            @Override public void visitTypeInsn(int opcode, String type) { insn("type", opcode, type); }
            @Override public void visitFieldInsn(int opcode, String owner, String name, String descriptor) { insn("field", opcode, owner, name, descriptor); }
            @Override public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) { insn("method", opcode, owner, name, descriptor, isInterface); }
            @Override public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrap, Object... args) { insn("invokedynamic", name, descriptor, constant(bootstrap), constants(args)); }
            @Override public void visitJumpInsn(int opcode, Label target) { insn("jump", opcode, target); }
            @Override public void visitLabel(Label value) { labelPositions.put(value, rawInstructions.size()); }
            @Override public void visitLdcInsn(Object value) { insn("ldc", constant(value)); }
            @Override public void visitIincInsn(int varIndex, int increment) { insn("iinc", varIndex, increment); }
            @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... targets) { insn("tableswitch", min, max, dflt, targets); }
            @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] targets) { insn("lookupswitch", dflt, intList(keys), targets); }
            @Override public void visitMultiANewArrayInsn(String descriptor, int dimensions) { insn("multianewarray", descriptor, dimensions); }
            @Override public void visitTryCatchBlock(Label start, Label end, Label handler, String type) { rawTryCatch.add(new Object[] {start, end, handler, type}); }
            @Override public void visitEnd() {
                try {
                    TreeSet<Integer> referencedPositions = new TreeSet<>();
                    for (Object[] item : rawInstructions) collectLabelPositions(item, referencedPositions);
                    for (Object[] item : rawTryCatch) collectLabelPositions(item, referencedPositions);
                    Map<Integer, Integer> positionIds = new HashMap<>();
                    int next = 0;
                    for (Integer position : referencedPositions) positionIds.put(position, next++);
                    for (int index = 0; index <= rawInstructions.size(); index++) {
                        if (positionIds.containsKey(index)) instructions.add(Arrays.asList("label", positionIds.get(index)));
                        if (index < rawInstructions.size()) instructions.add(normalizeLabels(rawInstructions.get(index), positionIds));
                    }
                    for (Object[] item : rawTryCatch) tryCatch.add(normalizeLabels(item, positionIds));
                    fact.put("implementation_digest", sha256(Json.stringify(linked("instructions", instructions, "try_catch", tryCatch)).getBytes(StandardCharsets.UTF_8)));
                } catch (Exception error) { throw new RuntimeException(error); }
            }

            void collectLabelPositions(Object value, Set<Integer> output) throws IOException {
                if (value instanceof Label label) {
                    Integer position = labelPositions.get(label);
                    if (position == null) throw new IOException("semantic label has no bytecode position");
                    output.add(position);
                } else if (value instanceof Object[] array) {
                    for (Object item : array) collectLabelPositions(item, output);
                } else if (value instanceof Iterable<?> values) {
                    for (Object item : values) collectLabelPositions(item, output);
                }
            }

            Object normalizeLabels(Object value, Map<Integer, Integer> positionIds) throws IOException {
                if (value instanceof Label label) {
                    Integer position = labelPositions.get(label);
                    if (position == null || !positionIds.containsKey(position)) throw new IOException("semantic label normalization failed");
                    return positionIds.get(position);
                }
                if (value instanceof Object[] array) {
                    List<Object> output = new ArrayList<>();
                    for (Object item : array) output.add(normalizeLabels(item, positionIds));
                    return output;
                }
                if (value instanceof Iterable<?> values) {
                    List<Object> output = new ArrayList<>();
                    for (Object item : values) output.add(normalizeLabels(item, positionIds));
                    return output;
                }
                return value;
            }
        }
    }

    private static AnnotationVisitor annotation(List<Object> destination, String descriptor, boolean visible) {
        Map<String, Object> annotation = linked("descriptor", descriptor, "visible", visible);
        List<Object> values = new ArrayList<>();
        annotation.put("values", values);
        destination.add(annotation);
        return new AnnotationVisitor(Opcodes.ASM9) {
            @Override public void visit(String name, Object value) { values.add(Arrays.asList(name, constant(value))); }
            @Override public void visitEnum(String name, String desc, String value) { values.add(Arrays.asList(name, "enum", desc, value)); }
            @Override public AnnotationVisitor visitAnnotation(String name, String desc) {
                List<Object> nested = new ArrayList<>(); values.add(Arrays.asList(name, "annotation", desc, nested)); return annotation(nested, desc, true);
            }
            @Override public AnnotationVisitor visitArray(String name) {
                List<Object> nested = new ArrayList<>(); values.add(Arrays.asList(name, "array", nested));
                return new AnnotationVisitor(Opcodes.ASM9) { @Override public void visit(String ignored, Object value) { nested.add(constant(value)); } };
            }
        };
    }

    private static Object constant(Object value) {
        if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean) return value;
        if (value instanceof Type type) return linked("kind", "type", "descriptor", type.getDescriptor());
        if (value instanceof Handle handle) return linked(
            "kind", "handle", "tag", handle.getTag(), "owner", handle.getOwner(),
            "name", handle.getName(), "descriptor", handle.getDesc(), "interface", handle.isInterface()
        );
        if (value instanceof ConstantDynamic dynamic) {
            List<Object> args = new ArrayList<>();
            for (int index = 0; index < dynamic.getBootstrapMethodArgumentCount(); index++) args.add(constant(dynamic.getBootstrapMethodArgument(index)));
            return linked("kind", "constant_dynamic", "name", dynamic.getName(), "descriptor", dynamic.getDescriptor(),
                "bootstrap", constant(dynamic.getBootstrapMethod()), "arguments", args);
        }
        return linked("kind", value.getClass().getName(), "value", String.valueOf(value));
    }

    private static List<Object> constants(Object[] values) { List<Object> result = new ArrayList<>(); for (Object value : values) result.add(constant(value)); return result; }
    private static List<Object> intList(int[] values) { List<Object> result = new ArrayList<>(); for (int value : values) result.add(value); return result; }
    private static String digestNullable(String value) { try { return value == null ? null : sha256(value.getBytes(StandardCharsets.UTF_8)); } catch (Exception error) { throw new RuntimeException(error); } }

    private static final class AttributeInventory {
        final byte[] data;
        final String[] utf8;
        final List<Object> result = new ArrayList<>();
        int cursor;

        AttributeInventory(byte[] data) throws Exception {
            this.data = data;
            if (u4(0) != 0xcafebabeL) throw new IOException("invalid classfile magic");
            int cpCount = u2(8);
            utf8 = new String[cpCount];
            cursor = 10;
            for (int index = 1; index < cpCount; index++) {
                int tag = u1();
                switch (tag) {
                    case 1 -> { int length = u2(); utf8[index] = modifiedUtf8(length); cursor += length; }
                    case 3, 4 -> cursor += 4;
                    case 5, 6 -> { cursor += 8; index++; }
                    case 7, 8, 16, 19, 20 -> cursor += 2;
                    case 9, 10, 11, 12, 17, 18 -> cursor += 4;
                    case 15 -> cursor += 3;
                    default -> throw new IOException("unsupported constant-pool tag " + tag);
                }
                require(cursor <= data.length, "constant pool exceeds classfile");
            }
        }

        static List<Object> scan(byte[] data) throws Exception {
            AttributeInventory inventory = new AttributeInventory(data);
            inventory.parse();
            return inventory.result;
        }

        void parse() throws Exception {
            cursor += 6;
            int interfaceCount = u2(); cursor += interfaceCount * 2;
            int fieldCount = u2();
            for (int index = 0; index < fieldCount; index++) {
                cursor += 2; String owner = utf(u2()); String desc = utf(u2());
                attributes("field", owner + desc, u2());
            }
            int methodCount = u2();
            for (int index = 0; index < methodCount; index++) {
                cursor += 2; String owner = utf(u2()); String desc = utf(u2());
                attributes("method", owner + desc, u2());
            }
            attributes("class", "class", u2());
            require(cursor == data.length, "classfile has trailing or unparsed bytes");
        }

        void attributes(String level, String owner, int count) throws Exception {
            for (int index = 0; index < count; index++) {
                String name = utf(u2());
                long rawLength = u4(cursor); cursor += 4;
                require(rawLength <= Integer.MAX_VALUE, "attribute too large");
                int length = (int) rawLength;
                int start = cursor;
                require(start + length <= data.length, "attribute exceeds classfile");
                String actualLevel = "Module".equals(name) ? "module" : level;
                result.add(linked("level", actualLevel, "owner", owner, "name", name,
                    "length", length, "sha256", sha256(Arrays.copyOfRange(data, start, start + length))));
                if ("Code".equals(name)) parseCode(owner, start, length);
                else if ("Record".equals(name)) parseRecord(start, length);
                cursor = start + length;
            }
        }

        void parseCode(String owner, int start, int length) throws Exception {
            cursor = start + 4;
            long codeLength = u4(cursor); cursor += 4;
            require(codeLength <= Integer.MAX_VALUE, "code too large");
            cursor += (int) codeLength;
            int exceptionCount = u2(); cursor += exceptionCount * 8;
            attributes("code", owner, u2());
            require(cursor == start + length, "malformed Code attribute");
        }

        void parseRecord(int start, int length) throws Exception {
            cursor = start;
            int componentCount = u2();
            for (int index = 0; index < componentCount; index++) {
                String name = utf(u2()); String desc = utf(u2());
                attributes("record", name + desc, u2());
            }
            require(cursor == start + length, "malformed Record attribute");
        }

        int u1() throws IOException { require(cursor < data.length, "truncated classfile"); return data[cursor++] & 0xff; }
        int u2() throws IOException { int value = u2(cursor); cursor += 2; return value; }
        int u2(int offset) throws IOException { require(offset + 2 <= data.length, "truncated u2"); return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff); }
        long u4(int offset) throws IOException { require(offset + 4 <= data.length, "truncated u4"); return ((long)(data[offset] & 0xff) << 24) | ((long)(data[offset+1] & 0xff) << 16) | ((long)(data[offset+2] & 0xff) << 8) | (data[offset+3] & 0xffL); }
        String utf(int index) throws IOException { require(index > 0 && index < utf8.length && utf8[index] != null, "invalid UTF8 index"); return utf8[index]; }
        String modifiedUtf8(int length) throws IOException {
            byte[] value = new byte[length + 2]; value[0] = (byte)(length >>> 8); value[1] = (byte)length;
            System.arraycopy(data, cursor, value, 2, length);
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(value))) { return input.readUTF(); }
        }
        static void require(boolean condition, String message) throws IOException { if (!condition) throw new IOException(message); }
    }

    private static final class Json {
        static String stringify(Object value) {
            StringBuilder out = new StringBuilder(); append(out, value); return out.toString();
        }
        static void append(StringBuilder out, Object value) {
            if (value == null) out.append("null");
            else if (value instanceof String string) quote(out, string);
            else if (value instanceof Number || value instanceof Boolean) out.append(value);
            else if (value instanceof Map<?, ?> map) {
                out.append('{'); boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) out.append(','); first = false; quote(out, String.valueOf(entry.getKey())); out.append(':'); append(out, entry.getValue());
                }
                out.append('}');
            } else if (value instanceof Iterable<?> values) {
                out.append('['); boolean first = true;
                for (Object item : values) { if (!first) out.append(','); first = false; append(out, item); }
                out.append(']');
            } else if (value.getClass().isArray()) {
                out.append('['); int length = java.lang.reflect.Array.getLength(value);
                for (int index = 0; index < length; index++) { if (index > 0) out.append(','); append(out, java.lang.reflect.Array.get(value, index)); }
                out.append(']');
            } else quote(out, String.valueOf(value));
        }
        static void quote(StringBuilder out, String value) {
            out.append('"');
            for (int index = 0; index < value.length(); index++) {
                char ch = value.charAt(index);
                switch (ch) {
                    case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\");
                    case '\b' -> out.append("\\b"); case '\f' -> out.append("\\f");
                    case '\n' -> out.append("\\n"); case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
                    default -> { if (ch < 0x20) out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch)); else out.append(ch); }
                }
            }
            out.append('"');
        }
    }
}
