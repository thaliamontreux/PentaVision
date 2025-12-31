"""
Home Assistant Video Tunnel Server

A standalone HTTP server that provides:
- API key authentication for Home Assistant integration
- Camera stream proxying (MJPEG, HLS, RTSP-over-HTTP)
- Bidirectional command protocol
- WebSocket support for real-time communication
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Set

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout

logger = logging.getLogger("pentavision.plugins.home-assistant.tunnel")

# Session configuration
SESSION_TOKEN_LENGTH = 64  # bytes
SESSION_EXPIRY_HOURS = 24
CHALLENGE_LENGTH = 32  # bytes
NONCE_EXPIRY_SECONDS = 300  # 5 minutes


@dataclass
class Session:
    """Represents an authenticated session."""
    session_id: str
    property_id: int
    token: str
    token_hash: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    client_info: dict = field(default_factory=dict)
    nonces_used: Set[str] = field(default_factory=set)

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        return not self.is_expired()

    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()

    def verify_nonce(self, nonce: str) -> bool:
        """Verify nonce hasn't been used (replay protection)."""
        if nonce in self.nonces_used:
            return False
        self.nonces_used.add(nonce)
        # Clean old nonces periodically
        if len(self.nonces_used) > 1000:
            self.nonces_used.clear()
        return True


class SessionManager:
    """Manages authenticated sessions with secure handshake."""

    def __init__(self):
        self.sessions: Dict[str, Session] = {}  # session_id -> Session
        self.token_to_session: Dict[str, str] = {}  # token_hash -> session_id
        self.pending_challenges: Dict[str, dict] = {}  # challenge -> {property_id, expires}
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start background cleanup task."""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """Stop background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self):
        """Periodically clean up expired sessions and challenges."""
        while True:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

    def _cleanup_expired(self):
        """Remove expired sessions and challenges."""
        now = datetime.utcnow()

        # Clean expired sessions
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if session.is_expired()
        ]
        for sid in expired_sessions:
            session = self.sessions.pop(sid, None)
            if session:
                self.token_to_session.pop(session.token_hash, None)
                logger.info(f"Cleaned up expired session {sid[:8]}...")

        # Clean expired challenges
        expired_challenges = [
            challenge for challenge, data in self.pending_challenges.items()
            if data["expires"] < now
        ]
        for challenge in expired_challenges:
            self.pending_challenges.pop(challenge, None)

    def create_challenge(self, property_id: int) -> dict:
        """
        Create a challenge for the handshake.
        Returns challenge data to send to client.
        """
        challenge = secrets.token_hex(CHALLENGE_LENGTH)
        server_nonce = secrets.token_hex(16)
        expires = datetime.utcnow() + timedelta(seconds=NONCE_EXPIRY_SECONDS)

        self.pending_challenges[challenge] = {
            "property_id": property_id,
            "server_nonce": server_nonce,
            "expires": expires,
            "created": datetime.utcnow(),
        }

        return {
            "challenge": challenge,
            "server_nonce": server_nonce,
            "expires_in": NONCE_EXPIRY_SECONDS,
        }

    def complete_handshake(
        self,
        challenge: str,
        client_response: str,
        api_key: str,
        client_nonce: str,
        client_info: Optional[dict] = None
    ) -> Optional[Session]:
        """
        Complete the handshake and create a session.

        The client_response should be:
        HMAC-SHA256(api_key, challenge + server_nonce + client_nonce)

        Returns Session if successful, None if failed.
        """
        # Verify challenge exists and not expired
        challenge_data = self.pending_challenges.get(challenge)
        if not challenge_data:
            logger.warning("Handshake failed: invalid challenge")
            return None

        if challenge_data["expires"] < datetime.utcnow():
            self.pending_challenges.pop(challenge, None)
            logger.warning("Handshake failed: challenge expired")
            return None

        property_id = challenge_data["property_id"]
        server_nonce = challenge_data["server_nonce"]

        # Compute expected response
        message = f"{challenge}{server_nonce}{client_nonce}"
        expected_response = hmac.new(
            api_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # Verify response (constant-time comparison)
        if not hmac.compare_digest(client_response, expected_response):
            logger.warning(f"Handshake failed: invalid response for property {property_id}")
            return None

        # Remove used challenge
        self.pending_challenges.pop(challenge, None)

        # Create session
        session = self._create_session(property_id, client_info or {})
        logger.info(f"Handshake successful for property {property_id}, session {session.session_id[:8]}...")

        return session

    def _create_session(self, property_id: int, client_info: dict) -> Session:
        """Create a new authenticated session."""
        session_id = secrets.token_hex(32)
        token = secrets.token_hex(SESSION_TOKEN_LENGTH)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        now = datetime.utcnow()
        session = Session(
            session_id=session_id,
            property_id=property_id,
            token=token,
            token_hash=token_hash,
            created_at=now,
            expires_at=now + timedelta(hours=SESSION_EXPIRY_HOURS),
            last_activity=now,
            client_info=client_info,
        )

        self.sessions[session_id] = session
        self.token_to_session[token_hash] = session_id

        return session

    def validate_session_token(self, token: str) -> Optional[Session]:
        """Validate a session token and return the session if valid."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session_id = self.token_to_session.get(token_hash)

        if not session_id:
            return None

        session = self.sessions.get(session_id)
        if not session or not session.is_valid():
            # Clean up invalid session
            if session_id in self.sessions:
                self.sessions.pop(session_id)
            self.token_to_session.pop(token_hash, None)
            return None

        session.touch()
        return session

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session."""
        session = self.sessions.pop(session_id, None)
        if session:
            self.token_to_session.pop(session.token_hash, None)
            logger.info(f"Session {session_id[:8]}... revoked")
            return True
        return False

    def revoke_all_sessions(self, property_id: int) -> int:
        """Revoke all sessions for a property."""
        to_revoke = [
            sid for sid, session in self.sessions.items()
            if session.property_id == property_id
        ]
        for sid in to_revoke:
            self.revoke_session(sid)
        return len(to_revoke)

    def get_active_sessions(self, property_id: Optional[int] = None) -> list:
        """Get list of active sessions."""
        sessions = []
        for session in self.sessions.values():
            if session.is_valid():
                if property_id is None or session.property_id == property_id:
                    sessions.append({
                        "session_id": session.session_id[:8] + "...",
                        "property_id": session.property_id,
                        "created_at": session.created_at.isoformat(),
                        "expires_at": session.expires_at.isoformat(),
                        "last_activity": session.last_activity.isoformat(),
                        "client_info": session.client_info,
                    })
        return sessions


class VideoTunnelServer:
    """
    HTTP server for Home Assistant video tunnel.
    
    Provides authenticated access to PentaVision camera streams
    for Home Assistant integration.
    """

    def __init__(self, bind_address: str = "0.0.0.0", port: int = 8473):
        self.bind_address = bind_address
        self.port = port
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None

        # Session manager for secure handshake
        self.session_manager = SessionManager()

        # API keys: property_id -> api_key (plaintext for HMAC verification)
        self.api_keys: Dict[int, str] = {}
        # API key hashes for initial validation: hash -> property_id
        self.api_key_hashes: Dict[str, int] = {}

        # Active streams: stream_id -> stream_info
        self.active_streams: Dict[str, dict] = {}

        # WebSocket connections for real-time communication
        self.websockets: Set[web.WebSocketResponse] = set()

        # Statistics
        self.stats = {
            "requests_total": 0,
            "requests_authenticated": 0,
            "requests_rejected": 0,
            "handshakes_completed": 0,
            "handshakes_failed": 0,
            "streams_served": 0,
            "bytes_transferred": 0,
            "start_time": None,
        }

        # PentaVision API base URL (internal)
        self.pv_api_base = os.environ.get("PENTAVISION_API_URL", "http://127.0.0.1:5000")

        # HTTP client session
        self.http_session: Optional[ClientSession] = None

    async def start(self):
        """Start the video tunnel server."""
        logger.info(f"Starting Video Tunnel Server on {self.bind_address}:{self.port}")

        self.stats["start_time"] = datetime.utcnow().isoformat()

        # Start session manager
        await self.session_manager.start()

        # Load API keys from database
        await self._load_api_keys()

        # Create HTTP client session
        self.http_session = ClientSession(
            timeout=ClientTimeout(total=30, connect=10)
        )

        # Create web application
        self.app = web.Application(middlewares=[self._auth_middleware])
        self._setup_routes()

        # Start server
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(self.runner, self.bind_address, self.port)
        await self.site.start()

        logger.info(f"Video Tunnel Server listening on {self.bind_address}:{self.port}")

    async def stop(self):
        """Stop the video tunnel server."""
        logger.info("Stopping Video Tunnel Server...")

        # Stop session manager
        await self.session_manager.stop()

        # Close all WebSocket connections
        for ws in list(self.websockets):
            await ws.close()

        # Close HTTP session
        if self.http_session:
            await self.http_session.close()

        # Stop server
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

        logger.info("Video Tunnel Server stopped")

    def _setup_routes(self):
        """Setup HTTP routes."""
        self.app.router.add_get("/", self._handle_root)
        self.app.router.add_get("/health", self._handle_health)
        self.app.router.add_get("/api/status", self._handle_status)

        # Handshake endpoints (for secure session establishment)
        self.app.router.add_post("/api/auth/handshake/init", self._handle_handshake_init)
        self.app.router.add_post("/api/auth/handshake/complete", self._handle_handshake_complete)
        self.app.router.add_post("/api/auth/session/revoke", self._handle_session_revoke)
        self.app.router.add_get("/api/auth/sessions", self._handle_list_sessions)

        # Camera endpoints
        self.app.router.add_get("/api/cameras", self._handle_list_cameras)
        self.app.router.add_get("/api/cameras/{camera_id}", self._handle_camera_info)
        self.app.router.add_get("/api/cameras/{camera_id}/stream", self._handle_camera_stream)
        self.app.router.add_get("/api/cameras/{camera_id}/snapshot", self._handle_camera_snapshot)

        # Stream proxy endpoints
        self.app.router.add_get("/stream/mjpeg/{camera_id}", self._handle_mjpeg_stream)
        self.app.router.add_get("/stream/hls/{camera_id}/index.m3u8", self._handle_hls_playlist)
        self.app.router.add_get("/stream/hls/{camera_id}/{segment}", self._handle_hls_segment)

        # Command endpoints
        self.app.router.add_post("/api/command", self._handle_command)
        self.app.router.add_post("/api/cameras/{camera_id}/ptz", self._handle_ptz_command)

        # WebSocket for real-time communication
        self.app.router.add_get("/ws", self._handle_websocket)

        # Events endpoint (for HA to receive events)
        self.app.router.add_get("/api/events", self._handle_events_stream)

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler):
        """Authentication middleware supporting both API key and session token."""
        self.stats["requests_total"] += 1

        # Skip auth for health check, root, and handshake init
        if request.path in ("/", "/health", "/api/auth/handshake/init"):
            return await handler(request)

        # Try session token first (preferred after handshake)
        session_token = request.headers.get("X-Session-Token") or request.query.get("session_token")
        if session_token:
            session = self.session_manager.validate_session_token(session_token)
            if session:
                request["property_id"] = session.property_id
                request["session"] = session
                self.stats["requests_authenticated"] += 1
                return await handler(request)
            else:
                self.stats["requests_rejected"] += 1
                return web.json_response(
                    {"error": "Invalid or expired session", "code": "SESSION_INVALID"},
                    status=401
                )

        # Fall back to API key (for handshake complete and legacy)
        api_key = request.headers.get("X-API-Key") or request.query.get("api_key")

        if not api_key:
            self.stats["requests_rejected"] += 1
            return web.json_response(
                {"error": "Authentication required (session token or API key)", "code": "AUTH_REQUIRED"},
                status=401
            )

        # Validate API key
        property_id = self._validate_api_key(api_key)
        if property_id is None:
            self.stats["requests_rejected"] += 1
            return web.json_response(
                {"error": "Invalid API key", "code": "AUTH_FAILED"},
                status=403
            )

        # Store property_id and api_key in request for handlers
        request["property_id"] = property_id
        request["api_key"] = api_key
        self.stats["requests_authenticated"] += 1

        return await handler(request)

    def _validate_api_key(self, api_key: str) -> Optional[int]:
        """Validate API key and return property_id if valid."""
        # Check against stored key hashes
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return self.api_key_hashes.get(key_hash)

    async def _load_api_keys(self):
        """Load API keys from database (supports MySQL and SQLite)."""
        try:
            # Try MySQL first (production)
            mysql_loaded = await self._load_api_keys_mysql()
            if mysql_loaded:
                return

            # Fall back to SQLite
            await self._load_api_keys_sqlite()

        except Exception as e:
            logger.error(f"Failed to load API keys: {e}")

    async def _load_api_keys_mysql(self) -> bool:
        """Load API keys from MySQL database."""
        try:
            import pymysql
            
            # Read database config from environment or config file
            db_host = os.environ.get("DB_HOST", "localhost")
            db_user = os.environ.get("DB_USER", "pentavision")
            db_pass = os.environ.get("DB_PASSWORD", "")
            db_name = os.environ.get("DB_NAME", "pentavision")
            
            # Try to read from .env file if exists
            env_path = Path("/opt/pentavision/app/.env")
            if env_path.exists():
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key == "DATABASE_URL" and value.startswith("mysql"):
                                # Parse mysql://user:pass@host/dbname
                                import re
                                match = re.match(r'mysql(?:\+pymysql)?://([^:]+):([^@]+)@([^/]+)/(.+)', value)
                                if match:
                                    db_user, db_pass, db_host, db_name = match.groups()
                                    # Handle host:port
                                    if ':' in db_host:
                                        db_host = db_host.split(':')[0]

            conn = pymysql.connect(
                host=db_host,
                user=db_user,
                password=db_pass,
                database=db_name,
                cursorclass=pymysql.cursors.DictCursor
            )
            
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT property_id, api_key_hash
                    FROM plugin_property_assignments
                    WHERE plugin_key = 'home-assistant'
                    AND api_key_hash IS NOT NULL
                    AND status = 'enabled'
                """)
                
                for row in cursor.fetchall():
                    if row['api_key_hash']:
                        self.api_key_hashes[row['api_key_hash']] = row['property_id']
            
            conn.close()
            logger.info(f"Loaded {len(self.api_key_hashes)} API keys from MySQL")
            return True
            
        except ImportError:
            logger.debug("pymysql not available, trying SQLite")
            return False
        except Exception as e:
            logger.debug(f"MySQL connection failed: {e}, trying SQLite")
            return False

    async def _load_api_keys_sqlite(self):
        """Load API keys from SQLite database."""
        db_path = Path("/opt/pentavision/data/pentavision.db")
        if not db_path.exists():
            db_path = Path(__file__).parent.parent.parent / "data" / "pentavision.db"

        if db_path.exists():
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT property_id, api_key_hash
                FROM plugin_property_assignments
                WHERE plugin_key = 'home-assistant'
                AND api_key_hash IS NOT NULL
                AND status = 'enabled'
            """)

            for row in cursor.fetchall():
                property_id, key_hash = row
                if key_hash:
                    self.api_key_hashes[key_hash] = property_id

            conn.close()
            logger.info(f"Loaded {len(self.api_key_hashes)} API keys from SQLite")
        else:
            logger.warning("No database found, no API keys loaded")

    async def reload_api_keys(self):
        """Reload API keys from database."""
        self.api_key_hashes.clear()
        await self._load_api_keys()

    # ========================================================================
    # Request Handlers
    # ========================================================================

    async def _handle_root(self, request: web.Request) -> web.Response:
        """Root endpoint - server info."""
        return web.json_response({
            "service": "PentaVision Home Assistant Video Tunnel",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "health": "/health",
                "status": "/api/status",
                "cameras": "/api/cameras",
                "stream_mjpeg": "/stream/mjpeg/{camera_id}",
                "stream_hls": "/stream/hls/{camera_id}/index.m3u8",
                "websocket": "/ws",
            }
        })

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _handle_status(self, request: web.Request) -> web.Response:
        """Server status endpoint."""
        uptime = None
        if self.stats["start_time"]:
            start = datetime.fromisoformat(self.stats["start_time"])
            uptime = (datetime.utcnow() - start).total_seconds()

        return web.json_response({
            "status": "running",
            "bind_address": self.bind_address,
            "port": self.port,
            "uptime_seconds": uptime,
            "stats": self.stats,
            "active_streams": len(self.active_streams),
            "websocket_connections": len(self.websockets),
            "active_sessions": len(self.session_manager.sessions),
            "api_keys_loaded": len(self.api_key_hashes),
        })

    # ========================================================================
    # Handshake Endpoints
    # ========================================================================

    async def _handle_handshake_init(self, request: web.Request) -> web.Response:
        """
        Initialize handshake - Step 1.

        Client sends: { "api_key": "..." }
        Server returns: { "challenge": "...", "server_nonce": "...", "expires_in": 300 }
        """
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        api_key = payload.get("api_key")
        if not api_key:
            return web.json_response(
                {"error": "api_key required", "code": "MISSING_API_KEY"},
                status=400
            )

        # Validate API key
        property_id = self._validate_api_key(api_key)
        if property_id is None:
            self.stats["handshakes_failed"] += 1
            return web.json_response(
                {"error": "Invalid API key", "code": "AUTH_FAILED"},
                status=403
            )

        # Create challenge
        challenge_data = self.session_manager.create_challenge(property_id)

        return web.json_response({
            "status": "challenge_issued",
            "challenge": challenge_data["challenge"],
            "server_nonce": challenge_data["server_nonce"],
            "expires_in": challenge_data["expires_in"],
            "instructions": "Compute HMAC-SHA256(api_key, challenge + server_nonce + client_nonce) and POST to /api/auth/handshake/complete"
        })

    async def _handle_handshake_complete(self, request: web.Request) -> web.Response:
        """
        Complete handshake - Step 2.

        Client sends: {
            "challenge": "...",
            "client_nonce": "...",
            "response": "HMAC-SHA256(api_key, challenge + server_nonce + client_nonce)",
            "client_info": { "name": "Home Assistant", "version": "..." }  // optional
        }
        Server returns: { "session_token": "...", "expires_at": "..." }
        """
        # Get API key from request (set by middleware)
        api_key = request.get("api_key")
        if not api_key:
            return web.json_response(
                {"error": "API key required for handshake completion", "code": "AUTH_REQUIRED"},
                status=401
            )

        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        challenge = payload.get("challenge")
        client_nonce = payload.get("client_nonce")
        client_response = payload.get("response")
        client_info = payload.get("client_info", {})

        if not all([challenge, client_nonce, client_response]):
            return web.json_response(
                {"error": "Missing required fields: challenge, client_nonce, response"},
                status=400
            )

        # Complete handshake
        session = self.session_manager.complete_handshake(
            challenge=challenge,
            client_response=client_response,
            api_key=api_key,
            client_nonce=client_nonce,
            client_info=client_info
        )

        if session is None:
            self.stats["handshakes_failed"] += 1
            return web.json_response(
                {"error": "Handshake failed - invalid challenge or response", "code": "HANDSHAKE_FAILED"},
                status=403
            )

        self.stats["handshakes_completed"] += 1

        return web.json_response({
            "status": "authenticated",
            "session_token": session.token,
            "session_id": session.session_id[:8] + "...",
            "property_id": session.property_id,
            "expires_at": session.expires_at.isoformat(),
            "message": "Use X-Session-Token header for subsequent requests"
        })

    async def _handle_session_revoke(self, request: web.Request) -> web.Response:
        """Revoke a session."""
        session = request.get("session")
        if not session:
            return web.json_response(
                {"error": "Session token required"},
                status=401
            )

        try:
            payload = await request.json()
        except Exception:
            payload = {}

        # Revoke current session or specified session
        session_id = payload.get("session_id") or session.session_id

        # Only allow revoking own sessions (unless admin)
        if session_id != session.session_id:
            target_session = self.session_manager.sessions.get(session_id)
            if target_session and target_session.property_id != session.property_id:
                return web.json_response(
                    {"error": "Cannot revoke sessions from other properties"},
                    status=403
                )

        success = self.session_manager.revoke_session(session_id)

        return web.json_response({
            "status": "revoked" if success else "not_found",
            "session_id": session_id[:8] + "..." if len(session_id) > 8 else session_id
        })

    async def _handle_list_sessions(self, request: web.Request) -> web.Response:
        """List active sessions for the property."""
        session = request.get("session")
        property_id = request.get("property_id")

        sessions = self.session_manager.get_active_sessions(property_id)

        return web.json_response({
            "sessions": sessions,
            "count": len(sessions)
        })

    # ========================================================================
    # Camera Endpoints
    # ========================================================================

    async def _handle_list_cameras(self, request: web.Request) -> web.Response:
        """List available cameras for the property."""
        property_id = request.get("property_id")
        
        try:
            # Fetch cameras from PentaVision API
            async with self.http_session.get(
                f"{self.pv_api_base}/api/cameras",
                params={"property_id": property_id}
            ) as resp:
                if resp.status == 200:
                    cameras = await resp.json()
                    return web.json_response({"cameras": cameras})
                else:
                    return web.json_response(
                        {"error": "Failed to fetch cameras"},
                        status=502
                    )
        except Exception as e:
            logger.error(f"Error fetching cameras: {e}")
            return web.json_response(
                {"error": "Internal error", "details": str(e)},
                status=500
            )

    async def _handle_camera_info(self, request: web.Request) -> web.Response:
        """Get camera information."""
        camera_id = request.match_info["camera_id"]
        property_id = request.get("property_id")
        
        try:
            async with self.http_session.get(
                f"{self.pv_api_base}/api/cameras/{camera_id}"
            ) as resp:
                if resp.status == 200:
                    camera = await resp.json()
                    return web.json_response(camera)
                else:
                    return web.json_response(
                        {"error": "Camera not found"},
                        status=404
                    )
        except Exception as e:
            logger.error(f"Error fetching camera info: {e}")
            return web.json_response(
                {"error": "Internal error"},
                status=500
            )

    async def _handle_camera_stream(self, request: web.Request) -> web.Response:
        """Get stream URL for a camera."""
        camera_id = request.match_info["camera_id"]
        stream_type = request.query.get("type", "mjpeg")
        
        # Build stream URL
        if stream_type == "mjpeg":
            stream_url = f"/stream/mjpeg/{camera_id}"
        elif stream_type == "hls":
            stream_url = f"/stream/hls/{camera_id}/index.m3u8"
        else:
            return web.json_response(
                {"error": f"Unknown stream type: {stream_type}"},
                status=400
            )
        
        return web.json_response({
            "camera_id": camera_id,
            "stream_type": stream_type,
            "stream_url": stream_url,
        })

    async def _handle_camera_snapshot(self, request: web.Request) -> web.Response:
        """Get a snapshot from a camera."""
        camera_id = request.match_info["camera_id"]
        
        try:
            # Fetch snapshot from PentaVision
            async with self.http_session.get(
                f"{self.pv_api_base}/api/cameras/{camera_id}/snapshot"
            ) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    self.stats["bytes_transferred"] += len(data)
                    return web.Response(
                        body=data,
                        content_type=resp.content_type or "image/jpeg"
                    )
                else:
                    return web.json_response(
                        {"error": "Failed to get snapshot"},
                        status=502
                    )
        except Exception as e:
            logger.error(f"Error fetching snapshot: {e}")
            return web.json_response(
                {"error": "Internal error"},
                status=500
            )

    async def _handle_mjpeg_stream(self, request: web.Request) -> web.StreamResponse:
        """Proxy MJPEG stream from camera."""
        camera_id = request.match_info["camera_id"]
        property_id = request.get("property_id")
        
        stream_id = f"mjpeg-{camera_id}-{time.time()}"
        self.active_streams[stream_id] = {
            "camera_id": camera_id,
            "property_id": property_id,
            "type": "mjpeg",
            "started": datetime.utcnow().isoformat(),
        }
        self.stats["streams_served"] += 1
        
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "multipart/x-mixed-replace; boundary=frame",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )
        await response.prepare(request)
        
        try:
            # Connect to PentaVision MJPEG stream
            async with self.http_session.get(
                f"{self.pv_api_base}/api/cameras/{camera_id}/mjpeg",
                timeout=ClientTimeout(total=None, sock_read=30)
            ) as upstream:
                if upstream.status != 200:
                    logger.error(f"Upstream returned {upstream.status}")
                    return response
                
                # Proxy the stream
                async for chunk in upstream.content.iter_any():
                    await response.write(chunk)
                    self.stats["bytes_transferred"] += len(chunk)
                    
        except asyncio.CancelledError:
            logger.info(f"MJPEG stream {stream_id} cancelled")
        except Exception as e:
            logger.error(f"Error in MJPEG stream: {e}")
        finally:
            self.active_streams.pop(stream_id, None)
        
        return response

    async def _handle_hls_playlist(self, request: web.Request) -> web.Response:
        """Proxy HLS playlist."""
        camera_id = request.match_info["camera_id"]
        
        try:
            async with self.http_session.get(
                f"{self.pv_api_base}/api/cameras/{camera_id}/hls/index.m3u8"
            ) as resp:
                if resp.status == 200:
                    playlist = await resp.text()
                    return web.Response(
                        text=playlist,
                        content_type="application/vnd.apple.mpegurl"
                    )
                else:
                    return web.json_response(
                        {"error": "HLS not available"},
                        status=404
                    )
        except Exception as e:
            logger.error(f"Error fetching HLS playlist: {e}")
            return web.json_response(
                {"error": "Internal error"},
                status=500
            )

    async def _handle_hls_segment(self, request: web.Request) -> web.Response:
        """Proxy HLS segment."""
        camera_id = request.match_info["camera_id"]
        segment = request.match_info["segment"]
        
        try:
            async with self.http_session.get(
                f"{self.pv_api_base}/api/cameras/{camera_id}/hls/{segment}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    self.stats["bytes_transferred"] += len(data)
                    return web.Response(
                        body=data,
                        content_type="video/mp2t"
                    )
                else:
                    return web.json_response(
                        {"error": "Segment not found"},
                        status=404
                    )
        except Exception as e:
            logger.error(f"Error fetching HLS segment: {e}")
            return web.json_response(
                {"error": "Internal error"},
                status=500
            )

    async def _handle_command(self, request: web.Request) -> web.Response:
        """Handle command from Home Assistant."""
        property_id = request.get("property_id")
        
        try:
            payload = await request.json()
        except Exception:
            return web.json_response(
                {"error": "Invalid JSON"},
                status=400
            )
        
        command = payload.get("command")
        params = payload.get("params", {})
        
        logger.info(f"Command from property {property_id}: {command}")
        
        # Handle different commands
        if command == "trigger_recording":
            return await self._cmd_trigger_recording(property_id, params)
        elif command == "arm_camera":
            return await self._cmd_arm_camera(property_id, params)
        elif command == "disarm_camera":
            return await self._cmd_disarm_camera(property_id, params)
        elif command == "reload_keys":
            await self.reload_api_keys()
            return web.json_response({"status": "ok", "keys_loaded": len(self.api_keys)})
        else:
            return web.json_response(
                {"error": f"Unknown command: {command}"},
                status=400
            )

    async def _handle_ptz_command(self, request: web.Request) -> web.Response:
        """Handle PTZ command for a camera."""
        camera_id = request.match_info["camera_id"]
        
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        
        action = payload.get("action")  # pan, tilt, zoom, preset
        value = payload.get("value")
        
        logger.info(f"PTZ command for camera {camera_id}: {action}={value}")
        
        # Forward to PentaVision
        try:
            async with self.http_session.post(
                f"{self.pv_api_base}/api/cameras/{camera_id}/ptz",
                json={"action": action, "value": value}
            ) as resp:
                result = await resp.json()
                return web.json_response(result, status=resp.status)
        except Exception as e:
            logger.error(f"PTZ command failed: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connection for real-time communication."""
        property_id = request.get("property_id")
        
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        self.websockets.add(ws)
        logger.info(f"WebSocket connected from property {property_id}")
        
        try:
            # Send welcome message
            await ws.send_json({
                "type": "connected",
                "property_id": property_id,
                "timestamp": datetime.utcnow().isoformat(),
            })
            
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        response = await self._handle_ws_message(property_id, data)
                        await ws.send_json(response)
                    except Exception as e:
                        await ws.send_json({"error": str(e)})
                        
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
                    
        finally:
            self.websockets.discard(ws)
            logger.info(f"WebSocket disconnected from property {property_id}")
        
        return ws

    async def _handle_ws_message(self, property_id: int, data: dict) -> dict:
        """Handle incoming WebSocket message."""
        msg_type = data.get("type")
        
        if msg_type == "ping":
            return {"type": "pong", "timestamp": datetime.utcnow().isoformat()}
        
        elif msg_type == "subscribe":
            # Subscribe to camera events
            camera_id = data.get("camera_id")
            return {"type": "subscribed", "camera_id": camera_id}
        
        elif msg_type == "command":
            # Execute command
            command = data.get("command")
            params = data.get("params", {})
            # Process command...
            return {"type": "command_result", "command": command, "status": "ok"}
        
        else:
            return {"type": "error", "message": f"Unknown message type: {msg_type}"}

    async def _handle_events_stream(self, request: web.Request) -> web.StreamResponse:
        """Server-Sent Events stream for real-time events."""
        property_id = request.get("property_id")
        
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            }
        )
        await response.prepare(request)
        
        try:
            # Send initial connection event
            await response.write(
                f"event: connected\ndata: {json.dumps({'property_id': property_id})}\n\n".encode()
            )
            
            # Keep connection alive with heartbeats
            while True:
                await asyncio.sleep(30)
                await response.write(b": heartbeat\n\n")
                
        except asyncio.CancelledError:
            pass
        
        return response

    # ========================================================================
    # Command Handlers
    # ========================================================================

    async def _cmd_trigger_recording(self, property_id: int, params: dict) -> web.Response:
        """Trigger recording on a camera."""
        camera_id = params.get("camera_id")
        duration = params.get("duration", 60)
        
        try:
            async with self.http_session.post(
                f"{self.pv_api_base}/api/cameras/{camera_id}/record",
                json={"duration": duration}
            ) as resp:
                result = await resp.json()
                return web.json_response(result, status=resp.status)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def _cmd_arm_camera(self, property_id: int, params: dict) -> web.Response:
        """Arm a camera for motion detection."""
        camera_id = params.get("camera_id")
        
        try:
            async with self.http_session.post(
                f"{self.pv_api_base}/api/cameras/{camera_id}/arm"
            ) as resp:
                result = await resp.json()
                return web.json_response(result, status=resp.status)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def _cmd_disarm_camera(self, property_id: int, params: dict) -> web.Response:
        """Disarm a camera."""
        camera_id = params.get("camera_id")
        
        try:
            async with self.http_session.post(
                f"{self.pv_api_base}/api/cameras/{camera_id}/disarm"
            ) as resp:
                result = await resp.json()
                return web.json_response(result, status=resp.status)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def broadcast_event(self, event_type: str, data: dict):
        """Broadcast event to all connected WebSocket clients."""
        message = {
            "type": "event",
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        for ws in list(self.websockets):
            try:
                await ws.send_json(message)
            except Exception:
                self.websockets.discard(ws)


def load_config() -> dict:
    """Load configuration from definition.json."""
    config = {
        "bind_address": "0.0.0.0",
        "port": 8473,
    }
    
    # Try to load from definition.json
    definition_paths = [
        Path("/opt/pentavision/plugins/home-assistant/definition.json"),
        Path(__file__).parent / "definition.json",
    ]
    
    for path in definition_paths:
        if path.exists():
            try:
                with open(path) as f:
                    definition = json.load(f)
                    props = definition.get("config_schema", {}).get("properties", {})
                    
                    if "api_bind_address" in props:
                        config["bind_address"] = props["api_bind_address"].get("default", "0.0.0.0")
                    if "api_port" in props:
                        config["port"] = props["api_port"].get("default", 8473)
                    
                    logger.info(f"Loaded config from {path}")
                    break
            except Exception as e:
                logger.warning(f"Failed to load config from {path}: {e}")
    
    return config


async def main():
    """Main entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    
    config = load_config()
    server = VideoTunnelServer(
        bind_address=config["bind_address"],
        port=config["port"]
    )
    
    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(server.stop())
        loop.stop()
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)
    
    await server.start()
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
