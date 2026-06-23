# Controlled collaborator — passive callback recorder for Case A (JNDI) and
# Case C (JDBC DataSource JNDI resolution).
#
# EFFECT-ONLY (RFC 0003 / RFC 0001 inv. 8): records inbound connections + the
# per-trial token; serves NO Java class, NO LDAP referral, NO code-exec payload.

FROM python:3.12-slim
WORKDIR /app
COPY collaborator.py /app/collaborator.py
VOLUME ["/records"]
# Default LDAP-ish port; the sandbox can override COLLABORATOR_PORT.
ENV COLLABORATOR_BIND=0.0.0.0 \
    COLLABORATOR_PORT=1389 \
    COLLABORATOR_RECORD=/records/callbacks.jsonl
EXPOSE 1389
ENTRYPOINT ["python3", "/app/collaborator.py"]
