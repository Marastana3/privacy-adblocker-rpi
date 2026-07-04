from dnslib import DNSRecord


class DNSForwarder:
    def __init__(self, upstream_ip: str, upstream_port: int = 53):
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port

    def forward(self, request: DNSRecord) -> DNSRecord:
        response_data = request.send(self.upstream_ip, self.upstream_port)
        return DNSRecord.parse(response_data)