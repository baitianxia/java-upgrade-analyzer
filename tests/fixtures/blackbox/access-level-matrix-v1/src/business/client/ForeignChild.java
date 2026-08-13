package client;

public class ForeignChild extends lib.AccessApi {
    public static String entryProtectedForeign(
        ForeignChild child, lib.AccessApi other
    ) {
        return child.callProtectedForeign(other);
    }

    public String callProtectedForeign(lib.AccessApi other) {
        return other.protectedForForeignReceiver();
    }
}
