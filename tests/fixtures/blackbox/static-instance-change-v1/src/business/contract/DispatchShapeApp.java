package contract;

public class DispatchShapeApp {
    public static String entryInstanceMethod() {
        return new DispatchShape().instanceToStatic();
    }

    public static String entryStaticMethod() {
        return DispatchShape.staticToInstance();
    }

    public static int entryInstanceField() {
        return new DispatchShape().instanceFieldToStatic;
    }

    public static int entryStaticField() {
        return DispatchShape.staticFieldToInstance;
    }
}
