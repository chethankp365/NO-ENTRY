# Academy Functionality Repair Report

## Summary

The existing Academy room UI was kept in place. The repair connected its existing controls and learning surfaces to authoritative lab-session state, corrected terminal/session ownership issues, and made GHOST guidance and hints use room and session data.

## Root causes found

- Lab lifecycle and room status needed to use the backend session as the source of truth. Lifecycle operations also needed serialization and session-scoped resource cleanup to prevent conflicting operations and stale Docker resources.
- The REST operator resolver did not have a FastAPI `Request` type, so lab startup could resolve a default operator while the authenticated terminal WebSocket resolved the logged-in user. This caused session ownership to disagree between REST and WebSocket requests.
- Terminal output was streamed in multiple messages, but affected tests assumed one response; additionally, command output without a final newline could be lost when it preceded the shell sentinel on the same line.
- GHOST guidance was generic rather than tied to the current room and backend-recorded actions. Hint command extraction treated arbitrary backticked text, including non-shell exercise inputs, as terminal commands.
- Some room content used markup-like target placeholders that were not reliably visible, and the SQL injection task rendered an incomplete URL. Room definitions also used `required_skills` while the model expected `required_practical_skills`.
- Some Docker test results came from stale images rather than the current lab image sources; rebuilding those images resolved the discrepancy.

## Changes made

- Lifecycle ownership, serialization, Docker state inspection, target readiness, reset, and scoped cleanup: `backend/app/labs/manager.py`, `backend/app/labs/docker_runner.py`, and `backend/app/labs/base.py`.
- Authenticated operator resolution and Academy/GHOST API behavior: `backend/app/api/auth.py`, `backend/app/api/academy.py`, `backend/app/api/ghost.py`, and `backend/app/ai/ghost.py`.
- Curriculum/model compatibility and visible room content: `backend/app/academy/curriculum.py`, `backend/app/academy/models.py`, `frontend/templates/room_workspace.html`, and `frontend/static/js/screens/roomWorkspace.js`.
- Container terminal and process-runner behavior: `backend/app/labs/terminal.py` and `backend/app/labs/process_runner.py`.
- Regression coverage and streamed-terminal test helpers: `backend/tests/conftest.py`, `backend/tests/test_real_cyber_range_and_ghost.py`, `backend/tests/test_docker_tracks.py`, `backend/tests/test_docker_real.py`, `backend/tests/test_labs.py`, and the Detection/Purple room workflow tests.

## Repaired routes and behavior

- `POST /api/academy/labs/{room_id}/start`
- `POST /api/academy/labs/{room_id}/stop`
- `POST /api/academy/labs/{room_id}/reset`
- `GET /api/academy/labs/{room_id}/status`
- `GET /api/academy/rooms/{room_id}`
- `POST /api/academy/rooms/{room_id}/tasks/{task_id}/submit`
- `GET /api/ghost/room/{room_id}/guide`
- `GET /api/ghost/room/{room_id}/hint?level={level}`
- `WS /ws/academy/{room_id}/terminal`

The existing room controls now display lifecycle state from backend responses rather than simulated success. Terminal access is authenticated and bound to the owning session; commands run through the attacker container. GHOST guide progression is based on backend-recorded actions, and hints use the room and live session context.

## Verification results

### Unit and backend regression tests

- Final focused command: `12 passed` in 65.71 seconds, covering Academy/GHOST, auth, lifecycle, terminal, and process-runner regressions.
- Python compilation and `node --check` for the room workspace JavaScript both completed successfully.

### Process-emulation tests

- The process-runner lifecycle and command-execution test passed. This is process emulation, not Docker verification.

### Real Docker integration tests

- `test_docker_real.py` and `test_docker_tracks.py`: 6 tests passed in the earlier focused run.
- Additional real Docker WebSocket/task workflows passed for representative Detection, Purple, and Blue rooms.
- Docker Desktop created separate attacker and target containers with distinct runtime identities and addresses. The attacker reached the intended isolated target. After the final checks, no `noentry_` containers or networks remained.

### Browser end-to-end verification

One room, `red-09-sqli-fundamentals`, was exercised through the existing browser UI: introductory content before startup, lab start, authenticated terminal connection, `whoami`, a bounded Nmap scan against the isolated target, GHOST guidance, a room-specific hint, backend task submission, reset, and stop. The browser displayed genuine terminal output and backend lifecycle state; reset replaced the container identities, and stop removed the active session resources.

This was a manual browser E2E run, not an automated browser test. The browser test server on port 8765 was stopped afterward.

### Full-suite status

An earlier full backend-suite run reported 378 passed and 16 failures. Several identified causes were corrected and their affected workflows were rerun as focused tests, but the full suite was not rerun after those fixes. The 12-test focused result above is not a substitute for a final full-suite run.

## Remaining limitations

- The terminal is a persistent line-oriented shell, not a full PTY. It does not provide complete interactive input to an already-running program, true remote terminal resizing, or Ctrl+C cancellation of a running command. Stderr is not presented as a separately streamed channel. These behaviors were not verified as supported.
- Browser verification covered one room end to end; focused Docker tests covered representative rooms/tracks, not all 80 rooms. Room-specific environment coverage is not established for every curriculum entry.
- Shared images and emulated scenarios do not constitute genuine Windows hosts, Active Directory domains, cloud environments, or production services. No such infrastructure is claimed here.
- The complete backend suite remains to be rerun to establish a clean post-fix baseline.

## Follow-up: browser-specific session failures

The subsequent Chrome/Edge report exposed an identity mismatch: Academy lab REST endpoints used `resolve_operator`, which falls back to the shared default operator when a browser has no valid login cookie, while the terminal WebSocket requires a valid authenticated operator. The lab lifecycle/status endpoints now require that same authenticated identity, so an unauthenticated browser cannot see another operator's lab as active. The room reports an `/access` sign-in or Guest Access instruction when the status request is unauthorized.

The backend is also started as a separate process and does not reload Python changes automatically. A restart previously discarded in-memory lab sessions even when Docker containers and database records were still running. Startup now restores only unexpired Docker sessions after verifying the session-derived containers, stored identities, internal network, and attacker-to-target reachability.

Follow-up verification: **13 focused tests passed**; Python compilation, JavaScript syntax, and whitespace checks passed. The live backend was restarted with recovery enabled; Red 01 returned `RUNNING` afterward, both original containers remained intact, and an authenticated WebSocket command returned real output from the attacker container. An unauthenticated lab-status request returned `401` as intended.

Each browser profile has its own authentication cookie. Sign in (or choose Guest Access at `/access`) separately in Chrome/Edge, then start the lab in that browser. A lab session belongs to its authenticated operator and room; another browser/operator must start its own session rather than reuse an IP/timer displayed by a stale tab.
