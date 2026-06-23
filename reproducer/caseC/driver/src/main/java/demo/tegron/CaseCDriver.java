package demo.tegron;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Case C reproducer driver — JDBC Appender config RCE (CVE-2021-44832).
 *
 * The precondition is `attacker_controlled_logging_config`: the attacker must be
 * able to supply (or tamper with) the logging configuration. When they can, a
 * JDBC Appender whose ConnectionSource is a DataSource resolved via JNDI can be
 * pointed at an attacker-controlled URI. On 2.17.0 the DataSource lookup resolves
 * the attacker URI -> outbound connection (and, weaponized, RCE). On 2.17.1 the
 * JDBC Appender DataSource is restricted to the java: protocol and JNDI is
 * forbidden for it, so the resolution is refused.
 *
 * The attacker-controlled config is supplied at runtime (log4j2.xml selected by
 * the Dockerfile), pointing its DataSource at the controlled collaborator.
 *
 * EFFECT-ONLY (RFC 0003 / RFC 0001 inv. 8): the observable is the OUTBOUND
 * CONNECTION ATTEMPT to the collaborator-controlled source when log4j initializes
 * the JDBC Appender. NO code is executed and no payload is served -- the
 * collaborator only records the connection.
 */
public final class CaseCDriver {

    private static final Logger LOG = LogManager.getLogger(CaseCDriver.class);

    public static void main(String[] args) throws Exception {
        System.out.println("[caseC] initializing logging with attacker-controlled JDBC Appender config "
                + "(effect-only; observable = outbound connection attempt to collaborator)");

        // Touching the logger triggers log4j to materialize the JDBC Appender's
        // ConnectionSource. On the vulnerable build that resolves the
        // attacker-controlled DataSource -> outbound connection to the
        // collaborator. On the fixed build the resolution is refused.
        LOG.error("driving JDBC appender initialization");

        // Dwell so the connection attempt (and the collaborator's record of it)
        // completes before the JVM exits.
        Thread.sleep(Long.parseLong(envOr("DWELL_MS", "3000")));
        System.out.println("[caseC] done");
    }

    private static String envOr(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }
}
