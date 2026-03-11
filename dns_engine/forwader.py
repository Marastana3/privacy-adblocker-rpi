from __future__ import annotations

from dnslib import DNSRecord


class DNSForwarder:
    def __init__(self, upstream_ip: str, upstream_port: int = 53):
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port

    def forward(self, request: DNSRecord) -> DNSRecord:
        """
        Forward DNS request to upstream resolver and return response.
        """
        # Send raw packet upstream
        response_data = request.send(self.upstream_ip, self.upstream_port)

        # Parse upstream reply
        return DNSRecord.parse(response_data)