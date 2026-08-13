package client;

public class Child extends lib.AccessApi {
    public static String entryProtected(Child child) {
        return child.callProtected();
    }

    public String callProtected() {
        return super.protectedForSubclass();
    }
}
