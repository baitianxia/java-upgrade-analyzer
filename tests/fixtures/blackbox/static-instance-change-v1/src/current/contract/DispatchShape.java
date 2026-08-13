package contract;

public class DispatchShape {
    public static String instanceToStatic() { return "instance"; }
    public String staticToInstance() { return "static"; }
    public static int instanceFieldToStatic;
    public int staticFieldToInstance;
    public String stable() { return "stable"; }
}
