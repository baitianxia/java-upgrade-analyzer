package topology.business;

import topology.crossjar.CrossJarBridge;
import topology.samecoord.SameCoordinateBridge;
import topology.target.SameJarBridge;
import topology.target.TargetApi;
import topology.target.TargetInterface;

public final class App {
    private App() {}

    public static void main(String[] args) {
        run(new TargetApi(), () -> {});
    }

    public static void run(TargetApi target, TargetInterface contract) {
        TargetApi.changed();
        SameJarBridge.bridge();
        SameCoordinateBridge.bridge();
        CrossJarBridge.bridge();
        TargetApi.overloaded("text");
        TargetApi.overloaded(1);
        new TargetApi();
        target.virtualCall();
        contract.interfaceCall();
        target.value = target.value + 1;
        Runnable callback = TargetApi::changed;
        callback.run();
    }
}
