package contract;

public class InheritanceApp {
    public static String entry(ChildApi child) {
        return child.inheritedReachable();
    }

    public static String dormant(ChildApi child) {
        return child.inheritedDormant();
    }
}
