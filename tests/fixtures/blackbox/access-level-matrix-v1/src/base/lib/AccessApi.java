package lib;

public class AccessApi {
    public String protectedForSubclass() { return "protected"; }
    public String protectedForForeignReceiver() { return "protected-foreign"; }
    public String packageForOutsider() { return "package"; }
    public String packageForPeer() { return "package-peer"; }
    public String privateForOutsider() { return "private"; }
    public String stable() { return "stable"; }
}
