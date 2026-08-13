package contract;

public class DispatchShape {
    public String instanceToStatic() { return "instance"; }
    public static String staticToInstance() { return "static"; }
    public int instanceFieldToStatic;
    public static int staticFieldToInstance;
    public String stable() { return "stable"; }
}
