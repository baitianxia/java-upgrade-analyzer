package topology.target;

public class TargetApi {
    public int value;

    public TargetApi() {}

    public static void changed() {}

    public static void overloaded(String value) {}

    public static void overloaded(int value) {}

    public void virtualCall() {}
}
