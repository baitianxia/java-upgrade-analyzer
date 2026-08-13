package oracle;

import org.apache.ibatis.binding.MapperMethod;
import org.apache.ibatis.binding.MapperProxy;

/** Compiled against MyBatis 3.5.10 and executed against both pinned runtimes. */
public final class MyBatisLinkageProbe {
    @FunctionalInterface
    private interface ThrowingCall {
        Object call() throws Throwable;
    }

    private static void expectLinked(String label, ThrowingCall call) {
        try {
            call.call();
            System.out.println(label + "=returned");
        } catch (LinkageError error) {
            System.err.println(label + "=linkage-error:" + error.getClass().getName());
            System.exit(10);
        } catch (Throwable enteredResolvedMethod) {
            System.out.println(
                label + "=linked:" + enteredResolvedMethod.getClass().getName()
            );
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] arguments) {
        expectLinked(
            "MapperProxy.invoke",
            () -> ((MapperProxy<Object>) null).invoke(null, null, null)
        );
        expectLinked(
            "MapperMethod.execute",
            () -> ((MapperMethod) null).execute(null, null)
        );
    }
}
