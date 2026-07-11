package topology.business;

public final class ReflectiveCaller {
    private ReflectiveCaller() {}

    public static void invoke() throws Exception {
        Class<?> owner = Class.forName("topology.target.TargetApi");
        owner.getMethod("changed").invoke(null);
    }
}
