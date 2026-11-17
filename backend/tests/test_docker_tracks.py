"""Real Docker smoke tests for one curriculum room from each non-Red track."""

import pytest

from backend.app.labs.docker_runner import DockerLabRunner


@pytest.mark.parametrize(
    ("room_id", "port", "path", "expected"),
    [
        ("blue-01-blue-team-foundations", 8201, "/api/soc/events", "EVT-1003"),
        ("purple-01-purple-team-foundations", 8301, "/api/purple/scope-rules", "T1059.001"),
        ("detect-01-foundations-as-code", 8401, "/api/detection/foundations/telemetry", "RULE-DAC-104"),
    ],
)
@pytest.mark.asyncio
async def test_real_docker_track_service(room_id, port, path, expected):
    runner = DockerLabRunner()
    if not runner.is_available():
        pytest.skip("Docker daemon is not operational on this host. Skipping Docker room tests.")

    session_id = f"test_track_{room_id.replace('-', '_')}"
    info = await runner.start_session(session_id, room_id, f"op-{room_id}")
    try:
        assert info.status == "RUNNING"
        assert info.runner_mode == "docker"
        assert info.target_port == port
        assert info.open_ports == [port]

        output = await runner.execute_command(
            session_id,
            f"curl -sS http://{info.target_ip}:{port}{path}",
        )
        assert expected in output
    finally:
        await runner.stop_session(session_id)
