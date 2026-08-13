package contract;

public final class FinalClassApp {
    private FinalClassApp() {}

    public static String entry() {
        return new FinalClassChild().stable();
    }
}
