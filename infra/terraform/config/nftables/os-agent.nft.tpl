destroy table inet os_agent_egress

table inet os_agent_egress {
  chain output {
    type filter hook output priority filter; policy accept;

    # U1/U2 실험 주체는 loopback과 Unix socket만 사용하며 직접 인터넷에 나가지 않는다.
    meta skuid ${u1_uid} ip daddr 127.0.0.0/8 accept
    meta skuid ${u1_uid} ip6 daddr ::1 accept
    meta skuid ${u1_uid} reject

    meta skuid ${u2_uid} ip daddr 127.0.0.0/8 accept
    meta skuid ${u2_uid} ip6 daddr ::1 accept
    meta skuid ${u2_uid} reject
  }
}
