package contract;

public final class MethodShapes {
    public MethodShapes() {}

    public MethodShapes(String label) {}

    public static String removedStatic(long value) {
        return Long.toString(value);
    }

    public String removedArray(String[] values, int[][] flags) {
        return Integer.toString(values.length + flags.length);
    }

    public String removedDeep() {
        return "deep";
    }

    public String removedUnreachable() {
        return "unreachable";
    }

    public String stableMethod() {
        return "stable";
    }
}
