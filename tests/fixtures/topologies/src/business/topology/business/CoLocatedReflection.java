package topology.business;

public final class CoLocatedReflection {
    private static final String UNRELATED_OWNER = "topology.target.TargetApi";
    private static final String UNRELATED_MEMBER = "changed";

    private CoLocatedReflection() {}

    public static Object invoke(String value) throws Exception {
        Class<?> owner = Class.forName("java.lang.String");
        return owner.getMethod("trim").invoke(value);
    }
}
