package topology.business;

public final class UnrelatedReflection {
    private UnrelatedReflection() {}

    public static Object invoke(String value) throws Exception {
        Class<?> owner = Class.forName("java.lang.String");
        return owner.getMethod("trim").invoke(value);
    }
}
