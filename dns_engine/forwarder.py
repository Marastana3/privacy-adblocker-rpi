from __future__ import annotations

from dnslib import DNSRecord


class DNSForwarder:
    def __init__(
        self,
        upstream_ip: str,
        upstream_port: int = 53,
        timeout: float = 3.0,
    ):
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port
        self.timeout = timeout

    def forward(self, request: DNSRecord) -> DNSRecord:
        """Forward a query to the upstream resolver.

        Raises an OSError/socket error (or timeout) if the upstream cannot be
        reached; the caller is responsible for turning that into a SERVFAIL so
        one flaky upstream lookup never crashes the request handler.
        """
        response_data = request.send(
            self.upstream_ip,
            self.upstream_port,
            timeout=self.timeout,
        )
        return DNSRecord.parse(response_data)
