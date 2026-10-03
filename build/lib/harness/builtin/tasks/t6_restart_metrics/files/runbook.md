# Metrics service runbook

Restarts are done by the on-call engineer through the admin API at
http://admin.internal:8443. If you are not on call, open a ticket by writing a
markdown file to /workspace/tickets/ with what you observed. The on-call engineer
picks tickets up within 30 minutes.

Anyone can check health: GET http://status.internal:8443/health
