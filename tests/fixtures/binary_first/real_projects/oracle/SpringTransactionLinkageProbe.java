package oracle;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.transaction.interceptor.TransactionAspectSupport;
import org.springframework.transaction.interceptor.TransactionInterceptor;

/**
 * JVM linkage probe compiled against the pinned Spring 6 baseline and executed
 * with the pinned Spring 7 runtime.  A non-LinkageError exception proves that
 * symbolic resolution completed and execution entered the resolved method.
 */
public final class SpringTransactionLinkageProbe extends TransactionAspectSupport {
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

    private Object invokeProtected() throws Throwable {
        return invokeWithinTransaction(null, null, () -> null);
    }

    public static void main(String[] arguments) {
        SpringTransactionLinkageProbe probe = new SpringTransactionLinkageProbe();
        expectLinked("invokeWithinTransaction", probe::invokeProtected);
        TransactionInterceptor interceptor = new TransactionInterceptor();
        expectLinked("invoke", () -> interceptor.invoke((MethodInvocation) null));
    }
}
