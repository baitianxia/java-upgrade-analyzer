package topology.business;

public final class AdversarialReflection {
    private AdversarialReflection() {}

    public static Object invoke(String value) throws Exception {
        String unrelatedOwner = "topology.target.TargetApi";
        Class<?> owner = Class.forName("java.lang.String");
        String unrelatedMember = "changed";
        if (unrelatedOwner.equals(unrelatedMember)) {
            throw new AssertionError();
        }
        return owner.getMethod("trim").invoke(value);
    }
}
