#!/usr/bin/env python3
"""
Unit and integration test suite for the Server-EDR Web Portal and Headless GUI migration.
Validates:
1. JWT token generation, expiration, and cryptographic signature validation.
2. WebPortal initialization, route registration, and middleware authentication.
3. REST API endpoints:
   - POST /api/v1/auth/login (success with token, failure with 401)
   - GET /api/v1/agents (retrieval of registered agents)
   - GET /api/v1/alerts (retrieval & query parameter filtering by severity and subsystem)
   - POST /api/v1/commands/dispatch (command dispatching & validation)
   - GET /api/v1/quarantine (quarantine audit retrieval from agents)
4. WebSocket /ws/live-stream live telemetry & event broadcast.
5. Default C2 port (443) and Web port (8443) configuration compliance.
"""

import asyncio
import json
import os
import sys
import time
import unittest
from datetime import datetime

import aiohttp
from aiohttp import web

# Ensure project root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from Server import (
    DEFAULT_C2_PORT,
    DEFAULT_PORT,
    DEFAULT_WEB_PORT,
    EDRServer,
    Agent,
    ServerConfig,
    WebPortal,
    create_jwt_token,
    verify_jwt_token,
)


class MockSocket:
    def sendall(self, data):
        pass

    def close(self):
        pass


class TestJWTAuthentication(unittest.TestCase):
    """Tests for lightweight HS256 JWT token generation and verification."""

    def setUp(self):
        self.secret = "test-very-secure-secret-key-12345678"

    def test_create_and_verify_valid_token(self):
        payload = {"sub": "admin", "role": "operator"}
        token = create_jwt_token(payload, self.secret, expires_in=3600)
        self.assertIsInstance(token, str)
        self.assertEqual(token.count("."), 2)

        verified = verify_jwt_token(token, self.secret)
        self.assertIsNotNone(verified)
        self.assertEqual(verified["sub"], "admin")
        self.assertEqual(verified["role"], "operator")
        self.assertIn("exp", verified)

    def test_verify_token_invalid_secret(self):
        token = create_jwt_token({"sub": "admin"}, self.secret, expires_in=3600)
        verified = verify_jwt_token(token, "wrong-secret-key")
        self.assertIsNone(verified)

    def test_verify_expired_token(self):
        token = create_jwt_token({"sub": "admin"}, self.secret, expires_in=-600)
        verified = verify_jwt_token(token, self.secret)
        self.assertIsNone(verified)

    def test_verify_malformed_tokens(self):
        self.assertIsNone(verify_jwt_token("not.a.valid.jwt.token", self.secret))
        self.assertIsNone(verify_jwt_token("malformed", self.secret))
        self.assertIsNone(verify_jwt_token("", self.secret))


class TestWebPortalAPI(unittest.IsolatedAsyncioTestCase):
    """Integration tests for WebPortal REST and WebSocket endpoints."""

    async def asyncSetUp(self):
        self.psk = "super-secret-edr-psk-token-2026"
        self.server_config = ServerConfig(
            port=DEFAULT_C2_PORT,
            web_port=DEFAULT_WEB_PORT,
            psk=self.psk
        )

        self.edr_server = EDRServer(
            host="127.0.0.1",
            port=0,
            psk=self.psk,
            tls_context=None
        )

        # Seed mock alerts
        self.edr_server._security_events.extend([
            {
                "id": "alert-1",
                "timestamp": "2026-10-02T12:00:00Z",
                "severity": "CRITICAL",
                "subsystem": "FIM",
                "title": "Critical file modified: /etc/shadow",
                "details": {"path": "/etc/shadow", "action": "modified"}
            },
            {
                "id": "alert-2",
                "timestamp": "2026-10-02T12:01:00Z",
                "severity": "HIGH",
                "subsystem": "DLP",
                "title": "DLP sensitive data detected: CREDIT_CARD",
                "details": {"rule": "CREDIT_CARD", "severity": "CRITICAL"}
            },
            {
                "id": "alert-3",
                "timestamp": "2026-10-02T12:02:00Z",
                "severity": "LOW",
                "subsystem": "MALWARE",
                "title": "Routine scan completed",
                "details": {}
            }
        ])

        # Add mock agent
        self.mock_agent = Agent(conn=MockSocket(), addr=("192.168.1.50", 54321))
        self.mock_agent.id = "agent-007"
        self.mock_agent.hostname = "WIN-SEC-01"
        self.mock_agent.username = "analyst"
        self.mock_agent.os = "Windows 11"
        self.mock_agent.defense_caps = ["malware_prevention", "fim", "dlp", "openedr"]
        self.mock_agent.attestation_status = "Verified"
        self.mock_agent.attestation_details = {"hash": "abcdef0123456789"}
        self.mock_agent.send_command = lambda cmd, args=None, **kw: ("mid-123", True)
        self.mock_agent.wait_response = lambda mid, timeout: {
            "status": "ok",
            "output": json.dumps([
                {
                    "quarantine_file": "malware.exe",
                    "original_path": "C:\\temp\\malware.exe",
                    "quarantine_time": 1727870400,
                    "hash": "abcdef1234567890abcdef1234567890"
                }
            ])
        }
        self.edr_server._agents["agent-007"] = self.mock_agent

        # Initialize WebPortal
        self.portal = WebPortal(
            server=self.edr_server,
            host="127.0.0.1",
            port=0,
            config=self.server_config,
            tls_context=None
        )

        # Build application runner without HTTPS for fast local loopback testing
        self.runner = web.AppRunner(self.portal.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()

        # Find assigned port
        names = self.site._server.sockets
        self.port = names[0].getsockname()[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.auth_token = create_jwt_token({"sub": "admin"}, self.psk, expires_in=3600)
        self.headers = {"Authorization": f"Bearer {self.auth_token}"}

    async def asyncTearDown(self):
        await self.runner.cleanup()

    async def test_root_serves_spa_html(self):
        """GET / returns HTML single page application with all 5 defense console tabs."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/") as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.content_type, "text/html")
                text = await resp.text()
                self.assertIn("Server-EDR", text)
                self.assertIn("Security Alerts", text)
                self.assertIn("Malware & Quarantine", text)
                self.assertIn("FIM", text)
                self.assertIn("DLP", text)
                self.assertIn("OpenEDR & Host Containment", text)

    async def test_auth_login_success_and_failure(self):
        """POST /api/v1/auth/login validates credentials and issues JWT token."""
        async with aiohttp.ClientSession() as session:
            # Valid login with password
            async with session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"password": self.psk}
            ) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertIn("token", data)
                self.assertEqual(data["status"], "ok")
                verified = verify_jwt_token(data["token"], self.psk)
                self.assertIsNotNone(verified)

            # Valid login with secret
            async with session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"secret": self.psk}
            ) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertIn("token", data)

            # Invalid login
            async with session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"password": "wrong-secret"}
            ) as resp:
                self.assertEqual(resp.status, 401)
                data = await resp.json()
                self.assertEqual(data["status"], "error")

    async def test_unauthorized_access_rejected(self):
        """Protected routes reject requests without a valid Bearer token."""
        async with aiohttp.ClientSession() as session:
            # No token
            async with session.get(f"{self.base_url}/api/v1/agents") as resp:
                self.assertEqual(resp.status, 401)

            # Invalid token
            bad_headers = {"Authorization": "Bearer invalid.token.value"}
            async with session.get(f"{self.base_url}/api/v1/agents", headers=bad_headers) as resp:
                self.assertEqual(resp.status, 401)

    async def test_get_agents(self):
        """GET /api/v1/agents returns connected and registered agents."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/api/v1/agents", headers=self.headers) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["status"], "ok")
                agents = data["agents"]
                self.assertEqual(len(agents), 1)
                agent = agents[0]
                self.assertEqual(agent["id"], "agent-007")
                self.assertEqual(agent["hostname"], "WIN-SEC-01")
                self.assertEqual(agent["username"], "analyst")
                self.assertEqual(agent["os"], "Windows 11")
                self.assertEqual(agent["attestation_status"], "Verified")
                self.assertIn("malware_prevention", agent["defense_capabilities"])

    async def test_get_alerts_and_filtering(self):
        """GET /api/v1/alerts returns alerts with query parameter filtering."""
        async with aiohttp.ClientSession() as session:
            # All alerts
            async with session.get(f"{self.base_url}/api/v1/alerts", headers=self.headers) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["total"], 3)

            # Filter by severity
            async with session.get(f"{self.base_url}/api/v1/alerts?severity=CRITICAL", headers=self.headers) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["total"], 1)
                self.assertEqual(data["alerts"][0]["severity"], "CRITICAL")

            # Filter by subsystem
            async with session.get(f"{self.base_url}/api/v1/alerts?subsystem=DLP", headers=self.headers) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["total"], 1)
                self.assertEqual(data["alerts"][0]["subsystem"], "DLP")

    async def test_command_dispatch_validation(self):
        """POST /api/v1/commands/dispatch validates payload and dispatches commands."""
        async with aiohttp.ClientSession() as session:
            # Missing command
            async with session.post(
                f"{self.base_url}/api/v1/commands/dispatch",
                headers=self.headers,
                json={"agent_id": "agent-007"}
            ) as resp:
                self.assertEqual(resp.status, 400)

            # Nonexistent agent
            async with session.post(
                f"{self.base_url}/api/v1/commands/dispatch",
                headers=self.headers,
                json={"agent_id": "nonexistent", "command": "ping"}
            ) as resp:
                self.assertEqual(resp.status, 404)

            # Successful dispatch
            async with session.post(
                f"{self.base_url}/api/v1/commands/dispatch",
                headers=self.headers,
                json={"agent_id": "agent-007", "command": "ping", "args": {}}
            ) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["status"], "ok")
                self.assertEqual(data["agent_id"], "agent-007")

    async def test_get_quarantine(self):
        """GET /api/v1/quarantine queries connected agents and returns quarantine records."""
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/api/v1/quarantine", headers=self.headers) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["status"], "ok")
                self.assertEqual(data["count"], 1)
                item = data["quarantine"][0]
                self.assertEqual(item["agent_id"], "agent-007")
                self.assertEqual(item["quarantine_file"], "malware.exe")
                self.assertEqual(item["original_path"], "C:\\temp\\malware.exe")

    async def test_websocket_live_stream_broadcast(self):
        """WS /ws/live-stream connects and receives broadcast events."""
        async with aiohttp.ClientSession() as session:
            ws_url = f"ws://127.0.0.1:{self.port}/ws/live-stream?token={self.auth_token}"
            async with session.ws_connect(ws_url) as ws:
                # Receive initial init status message
                msg = await ws.receive_json(timeout=5.0)
                self.assertEqual(msg.get("type"), "init")

                # Test event broadcast
                test_event = {
                    "type": "security_event",
                    "agent_id": "agent-007",
                    "hostname": "WIN-SEC-01",
                    "alert": {
                        "severity": "CRITICAL",
                        "title": "Real-time alert",
                        "subsystem": "FIM"
                    },
                    "timestamp": datetime.now().isoformat()
                }
                self.portal.broadcast_event(test_event)

                received = await ws.receive_json(timeout=5.0)
                self.assertEqual(received["type"], "security_event")
                self.assertEqual(received["alert"]["title"], "Real-time alert")

                # Test ping message
                await ws.send_json({"action": "ping"})
                pong = await ws.receive_json(timeout=5.0)
                self.assertEqual(pong.get("type"), "pong")


class TestPortConfigurationCompliance(unittest.TestCase):
    """Validates that C2 port 443 and Web port 8443 are properly defaulted and aligned."""

    def test_default_ports(self):
        self.assertEqual(DEFAULT_C2_PORT, 443, "C2 default port must be 443")
        self.assertEqual(DEFAULT_PORT, 443, "DEFAULT_PORT alias must be 443")
        self.assertEqual(DEFAULT_WEB_PORT, 8443, "Web portal default port must be 8443")


if __name__ == "__main__":
    unittest.main()
