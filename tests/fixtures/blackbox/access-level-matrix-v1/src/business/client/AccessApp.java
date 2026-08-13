package client;

public class AccessApp {
    public static String entryPackage(lib.AccessApi api) {
        return api.packageForOutsider();
    }

    public static String entryPrivate(lib.AccessApi api) {
        return api.privateForOutsider();
    }
}
