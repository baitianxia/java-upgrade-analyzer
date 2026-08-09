import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** Independent target-JVM provider/definition/hierarchy observation helper. */
public final class RuntimeOutcomeOracle {
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
                String name = raw.trim();
                if (name.isEmpty()) continue;
                observe(loader, name);
            }
        }
    }

    private static void observe(ClassLoader loader, String binaryName) {
        StringBuilder out = new StringBuilder();
        out.append('{').append(json("class_name")).append(':').append(json(binaryName.replace('.', '/')));
        try {
            Class<?> type = Class.forName(binaryName, false, loader);
            // Reflection metadata resolution forces descriptors, superclasses and
            // interfaces to link but never executes class initialization.
            Method[] methods = type.getDeclaredMethods();
            Field[] fields = type.getDeclaredFields();
            Constructor<?>[] constructors = type.getDeclaredConstructors();
            out.append(',').append(json("status")).append(':').append(json("definition_ready"));
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
            List<String> memberRows = new ArrayList<>();
            for (Field field : fields) {
                memberRows.add("field|" + field.getName() + "|" + descriptor(field.getType())
                    + "|" + field.getModifiers());
            }
            for (Method method : methods) {
                memberRows.add("method|" + method.getName() + "|" + methodDescriptor(method)
                    + "|" + method.getModifiers());
            }
            for (Constructor<?> constructor : constructors) {
                memberRows.add("method|<init>|" + constructorDescriptor(constructor)
                    + "|" + constructor.getModifiers());
            }
            Collections.sort(memberRows);
            out.append(',').append(json("members")).append(':').append(jsonArray(memberRows));
        } catch (Throwable error) {
            out.append(',').append(json("status")).append(':').append(json("definition_failed"));
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

    private static String json(String value) {
        if (value == null) return "null";
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
                    if (ch < 0x20) out.append(String.format("\\u%04x", (int) ch));
                    else out.append(ch);
            }
        }
        return out.append('"').toString();
    }
}
