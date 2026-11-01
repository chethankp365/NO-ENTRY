import asyncio
import pytest
from backend.app.sim.engine import sim_engine

@pytest.mark.asyncio
async def test_scenarios_loaded():
    assert len(sim_engine.active_scenarios) >= 5
    expected_ids = {"ransomware", "web-breach", "insider", "credential", "exfiltration"}
    loaded_ids = set(sim_engine.active_scenarios.keys())
    assert expected_ids.issubset(loaded_ids)

@pytest.mark.asyncio
async def test_scenario_start_and_stop():
    success = await sim_engine.start_scenario("web-breach")
    assert success is True
    assert sim_engine.active_scenarios["web-breach"].status in ["running", "completed"]

    stopped = sim_engine.stop_scenario("web-breach")
    assert stopped is True
    assert sim_engine.active_scenarios["web-breach"].status == "stopped"

@pytest.mark.asyncio
async def test_scenario_run_fast_execution():
    # Test a fast copy of scenario steps to verify execution flow
    scenario = sim_engine.active_scenarios["credential"]
    # Temporarily set fast delays for testing
    original_delays = [s.delay for s in scenario.steps]
    for s in scenario.steps:
        s.delay = 0.01

    try:
        await sim_engine.start_scenario("credential")
        # Wait for short duration for tasks to step through
        await asyncio.sleep(0.15)
        assert scenario.status in ["running", "completed"]
    finally:
        # Restore delays
        for s, d in zip(scenario.steps, original_delays):
            s.delay = d
        sim_engine.stop_scenario("credential")
