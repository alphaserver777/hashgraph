from mdrj.config import LinuxIngestConfig
from mdrj.linux_ingest import LinuxAuthLogIngestor


def make_config(log_path: str, state_path: str) -> LinuxIngestConfig:
    return LinuxIngestConfig(
        enabled=True,
        source_type="auth_log_file",
        auth_log_path=log_path,
        poll_interval_sec=1.0,
        host_id="linux-host-1",
        admin_users=["admin"],
        privileged_groups=[],
        state_path=state_path,
    )


def test_linux_ingest_parses_admin_ssh_success(tmp_path):
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    log_path.write_text(
        "Apr  3 10:16:04 linux-host-1 sshd[1003]: Accepted password for admin from 192.0.2.12 port 51246 ssh2\n",
        encoding="utf-8",
    )
    ingestor = LinuxAuthLogIngestor(
        config=make_config(str(log_path), str(state_path)),
        node_id="linux-node-1",
    )

    payloads = ingestor.poll()

    assert len(payloads) == 1
    payload = payloads[0]
    assert payload["event_kind"] == "admin_ssh_login_success"
    assert payload["class"] == "A"
    assert payload["principal"] == "admin"
    assert payload["source_ip"] == "192.0.2.12"
    assert payload["target_service"] == "sshd"
    assert payload["result"] == "success"


def test_linux_ingest_ignores_non_admin_ssh_success(tmp_path):
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    log_path.write_text(
        "Apr  3 10:15:33 linux-host-1 sshd[1002]: Accepted publickey for analyst from 192.0.2.11 port 51245 ssh2\n",
        encoding="utf-8",
    )
    ingestor = LinuxAuthLogIngestor(
        config=make_config(str(log_path), str(state_path)),
        node_id="linux-node-1",
    )

    assert ingestor.poll() == []


def test_linux_ingest_state_prevents_replaying_same_log_lines(tmp_path):
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state.json"
    log_path.write_text(
        "Apr  3 10:15:10 linux-host-1 sshd[1001]: Accepted publickey for root from 192.0.2.10 port 51244 ssh2: RSA SHA256:demo\n",
        encoding="utf-8",
    )
    config = make_config(str(log_path), str(state_path))
    ingestor = LinuxAuthLogIngestor(config=config, node_id="linux-node-1")

    first = ingestor.poll()
    second = LinuxAuthLogIngestor(config=config, node_id="linux-node-1").poll()

    assert len(first) == 1
    assert second == []
