import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.annotation.Annotation;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** Independent target-JVM provider/definition/hierarchy observation helper. */
public final class RuntimeOutcomeOracle {
    private static final String JVM_TEXT_TRANSPORT_PREFIX = "~jua-utf16-v1~";

    private RuntimeOutcomeOracle() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: <classpath-list-file> <class-list-file>");
        }
        List<String> classpathLines = Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8);
        List<URL> urls = new ArrayList<>();
        for (String line : classpathLines) {
            if (!line.trim().isEmpty()) urls.add(Paths.get(line.trim()).toUri().toURL());
        }
        ClassLoader helperLoader = RuntimeOutcomeOracle.class.getClassLoader();
        ClassLoader platformParent = helperLoader == null ? null : helperLoader.getParent();
        try (URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]), platformParent)) {
            for (String raw : Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8)) {
                if (raw.isEmpty()) continue;
                String name = decodeTransportText(raw).replace('/', '.');
                observe(loader, name);
            }
        }
    }

    private static String decodeTransportText(String value) {
        if (!value.startsWith(JVM_TEXT_TRANSPORT_PREFIX)) return value;
        byte[] bytes = Base64.getUrlDecoder().decode(
            value.substring(JVM_TEXT_TRANSPORT_PREFIX.length())
        );
        if ((bytes.length & 1) != 0) {
            throw new IllegalArgumentException("invalid JVM UTF-16 transport length");
        }
        char[] characters = new char[bytes.length / 2];
        for (int index = 0; index < characters.length; index++) {
            characters[index] = (char) (
                ((bytes[index * 2] & 0xff) << 8)
                | (bytes[index * 2 + 1] & 0xff)
            );
        }
        return new String(characters);
    }

    private static boolean requiresTransport(String value) {
        if (value.startsWith(JVM_TEXT_TRANSPORT_PREFIX)) return true;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(index + 1))) {
                    index++;
                    continue;
                }
                return true;
            }
            if (Character.isLowSurrogate(character)) return true;
        }
        return false;
    }

    private static String encodeTransportText(String value) {
        if (!requiresTransport(value)) return value;
        byte[] bytes = new byte[value.length() * 2];
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            bytes[index * 2] = (byte) (character >>> 8);
            bytes[index * 2 + 1] = (byte) character;
        }
        return JVM_TEXT_TRANSPORT_PREFIX
            + Base64.getUrlEncoder().encodeToString(bytes);
    }

    private static String row(String... values) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < values.length; index++) {
            if (index > 0) result.append('|');
            result.append(encodeTransportText(values[index]));
        }
        return result.toString();
    }

    private static void observe(ClassLoader loader, String binaryName) {
        StringBuilder out = new StringBuilder();
        out.append('{').append(json("class_name")).append(':').append(json(binaryName.replace('.', '/')));
        String resourceName = binaryName.replace('.', '/') + ".class";
        String providerResource = "";
        try {
            URL resource = loader.getResource(resourceName);
            if (resource != null) providerResource = resource.toExternalForm();
        } catch (RuntimeException error) {
            providerResource = "<resource-error:" + error.getClass().getName() + ">";
        }
        out.append(',').append(json("provider_resource_url")).append(':').append(
            json(providerResource)
        );
        boolean classLoaded = false;
        try {
            Class<?> type = Class.forName(binaryName, false, loader);
            classLoaded = true;
            // Preserve the hierarchy as soon as the class itself loads. A later
            // optional member-signature failure must not erase valid subtype
            // evidence used by the independent dispatch reconstruction.
            out.append(',').append(json("provider_url")).append(':').append(json(codeSource(type)));
            out.append(',').append(json("loader_kind")).append(':').append(json(loaderKind(type)));
            out.append(',').append(json("modifiers")).append(':').append(type.getModifiers());
            out.append(',').append(json("super_name")).append(':').append(json(
                type.getSuperclass() == null ? "" : internal(type.getSuperclass())
            ));
            List<String> interfaces = new ArrayList<>();
            for (Class<?> iface : type.getInterfaces()) interfaces.add(internal(iface));
            Collections.sort(interfaces);
            out.append(',').append(json("interfaces")).append(':').append(jsonArray(interfaces));
            // Class-level metadata is independently useful even when a later
            // optional method/field type prevents exhaustive member linkage.
            out.append(',').append(json("class_annotations")).append(':').append(
                jsonArray(annotationDescriptors(type))
            );
            out.append(',').append(json("class_annotation_imports")).append(':').append(
                jsonArray(annotationImports(type))
            );
            out.append(',').append(json("class_annotation_resources")).append(':').append(
                jsonArray(annotationResources(type))
            );
            out.append(',').append(json("class_annotation_values")).append(':').append(
                jsonTransportedArray(annotationValues(type))
            );
            // Reflection metadata resolution forces member descriptors to link
            // but never executes class initialization.
            Method[] methods = type.getDeclaredMethods();
            Field[] fields = type.getDeclaredFields();
            Constructor<?>[] constructors = type.getDeclaredConstructors();
            out.append(',').append(json("status")).append(':').append(json("definition_ready"));
            List<String> memberRows = new ArrayList<>();
            List<String> memberAnnotationRows = new ArrayList<>();
            List<String> memberAnnotationValueRows = new ArrayList<>();
            for (Field field : fields) {
                memberRows.add(row(
                    "field", field.getName(), descriptor(field.getType()),
                    String.valueOf(field.getModifiers())
                ));
            }
            for (Method method : methods) {
                memberRows.add(row(
                    "method", method.getName(), methodDescriptor(method),
                    String.valueOf(method.getModifiers())
                ));
                for (String annotation : annotationDescriptors(method)) {
                    memberAnnotationRows.add(row(
                        method.getName(), methodDescriptor(method), annotation
                    ));
                }
                for (String value : annotationValues(method)) {
                    memberAnnotationValueRows.add(
                        row(method.getName(), methodDescriptor(method)) + "|" + value
                    );
                }
            }
            for (Constructor<?> constructor : constructors) {
                memberRows.add(row(
                    "method", "<init>", constructorDescriptor(constructor),
                    String.valueOf(constructor.getModifiers())
                ));
            }
            Collections.sort(memberRows);
            Collections.sort(memberAnnotationRows);
            Collections.sort(memberAnnotationValueRows);
            out.append(',').append(json("members")).append(':').append(
                jsonTransportedArray(memberRows)
            );
            out.append(',').append(json("member_annotations")).append(':').append(
                jsonTransportedArray(memberAnnotationRows)
            );
            out.append(',').append(json("member_annotation_values")).append(':').append(
                jsonTransportedArray(memberAnnotationValueRows)
            );
        } catch (Throwable error) {
            out.append(',').append(json("status")).append(':').append(json("definition_failed"));
            out.append(',').append(json("failure_phase")).append(':').append(json(
                classLoaded ? "member_linkage" : "class_load"
            ));
            out.append(',').append(json("failure_kind")).append(':').append(json(error.getClass().getName()));
            out.append(',').append(json("failure_message")).append(':').append(json(String.valueOf(error.getMessage())));
        }
        out.append('}');
        System.out.println(out.toString());
    }

    private static String codeSource(Class<?> type) {
        try {
            CodeSource source = type.getProtectionDomain().getCodeSource();
            return source == null || source.getLocation() == null ? "" : source.getLocation().toExternalForm();
        } catch (SecurityException error) {
            return "<security-denied>";
        }
    }

    private static String loaderKind(Class<?> type) {
        ClassLoader loader = type.getClassLoader();
        if (loader == null) return "bootstrap";
        return loader.getClass().getName();
    }

    private static String internal(Class<?> type) { return type.getName().replace('.', '/'); }

    private static List<String> annotationDescriptors(AnnotatedElement element) {
        List<String> result = new ArrayList<>();
        try {
            for (Annotation annotation : element.getDeclaredAnnotations()) {
                result.add("L" + internal(annotation.annotationType()) + ";");
            }
        } catch (RuntimeException | LinkageError error) {
            result.add("<unresolved:" + error.getClass().getName() + ">");
        }
        Collections.sort(result);
        return result;
    }

    private static List<String> annotationImports(AnnotatedElement element) {
        List<String> result = new ArrayList<>();
        try {
            for (Annotation annotation : element.getDeclaredAnnotations()) {
                if (!annotation.annotationType().getName().equals(
                    "org.springframework.context.annotation.Import"
                )) continue;
                try {
                    Object value = annotation.annotationType().getDeclaredMethod("value").invoke(annotation);
                    if (value instanceof Class<?>[]) {
                        for (Class<?> imported : (Class<?>[]) value) result.add(internal(imported));
                    }
                } catch (ReflectiveOperationException | RuntimeException error) {
                    result.add("<unresolved:" + error.getClass().getName() + ">");
                }
            }
        } catch (RuntimeException | LinkageError error) {
            result.add("<unresolved:" + error.getClass().getName() + ">");
        }
        Collections.sort(result);
        return result;
    }

    private static List<String> annotationResources(AnnotatedElement element) {
        List<String> result = new ArrayList<>();
        try {
            for (Annotation annotation : element.getDeclaredAnnotations()) {
                if (!annotation.annotationType().getName().equals(
                    "org.springframework.context.annotation.ImportResource"
                )) continue;
                try {
                    Object value = annotation.annotationType().getDeclaredMethod("locations")
                        .invoke(annotation);
                    if (value instanceof String[]) {
                        result.addAll(Arrays.asList((String[]) value));
                    }
                    Object aliases = annotation.annotationType().getDeclaredMethod("value")
                        .invoke(annotation);
                    if (aliases instanceof String[]) {
                        result.addAll(Arrays.asList((String[]) aliases));
                    }
                } catch (ReflectiveOperationException | RuntimeException error) {
                    result.add("<unresolved:" + error.getClass().getName() + ">");
                }
            }
        } catch (RuntimeException | LinkageError error) {
            result.add("<unresolved:" + error.getClass().getName() + ">");
        }
        Collections.sort(result);
        return result;
    }

    private static List<String> annotationValues(AnnotatedElement element) {
        List<String> result = new ArrayList<>();
        try {
            for (Annotation annotation : element.getDeclaredAnnotations()) {
                String descriptor = "L" + internal(annotation.annotationType()) + ";";
                for (Method attribute : annotation.annotationType().getDeclaredMethods()) {
                    try {
                        Object value = attribute.invoke(annotation);
                        if (value != null && value.getClass().isArray()) {
                            int length = java.lang.reflect.Array.getLength(value);
                            for (int index = 0; index < length; index++) {
                                result.add(row(
                                    descriptor,
                                    attribute.getName(),
                                    annotationValue(java.lang.reflect.Array.get(value, index))
                                ));
                            }
                        } else {
                            result.add(row(
                                descriptor, attribute.getName(), annotationValue(value)
                            ));
                        }
                    } catch (ReflectiveOperationException | RuntimeException error) {
                        result.add(row(
                            descriptor,
                            attribute.getName(),
                            "<unresolved:" + error.getClass().getName() + ">"
                        ));
                    }
                }
            }
        } catch (RuntimeException | LinkageError error) {
            result.add(row(
                "<unresolved>", "<unresolved>", error.getClass().getName()
            ));
        }
        Collections.sort(result);
        return result;
    }

    private static String annotationValue(Object value) {
        if (value == null) return "null";
        if (value instanceof Class<?>) return internal((Class<?>) value);
        if (value instanceof Enum<?>) return ((Enum<?>) value).name();
        return String.valueOf(value);
    }

    private static String methodDescriptor(Method method) {
        StringBuilder value = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) value.append(descriptor(parameter));
        return value.append(')').append(descriptor(method.getReturnType())).toString();
    }

    private static String constructorDescriptor(Constructor<?> constructor) {
        StringBuilder value = new StringBuilder("(");
        for (Class<?> parameter : constructor.getParameterTypes()) value.append(descriptor(parameter));
        return value.append(")V").toString();
    }

    private static String descriptor(Class<?> type) {
        if (type.isArray()) return type.getName().replace('.', '/');
        if (!type.isPrimitive()) return "L" + internal(type) + ";";
        if (type == void.class) return "V";
        if (type == boolean.class) return "Z";
        if (type == byte.class) return "B";
        if (type == char.class) return "C";
        if (type == short.class) return "S";
        if (type == int.class) return "I";
        if (type == long.class) return "J";
        if (type == float.class) return "F";
        if (type == double.class) return "D";
        throw new AssertionError(type);
    }

    private static String jsonArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int index = 0; index < values.size(); index++) {
            if (index > 0) out.append(',');
            out.append(json(values.get(index)));
        }
        return out.append(']').toString();
    }

    private static String jsonTransportedArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int index = 0; index < values.size(); index++) {
            if (index > 0) out.append(',');
            out.append(jsonTransported(values.get(index)));
        }
        return out.append(']').toString();
    }

    private static String json(String value) {
        if (value == null) return "null";
        return jsonTransported(encodeTransportText(value));
    }

    private static String jsonTransported(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            switch (ch) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (ch < 0x20 || Character.isSurrogate(ch)) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                    }
                    else out.append(ch);
            }
        }
        return out.append('"').toString();
    }
}
