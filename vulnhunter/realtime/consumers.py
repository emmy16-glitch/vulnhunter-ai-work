from __future__ import annotations

import asyncio

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.core import signing
from django.core.exceptions import ObjectDoesNotExist

from vulnhunter.api.views import decode_realtime_ticket
from vulnhunter.product import ProductServiceError
from vulnhunter.web.conversational_views import _conversation_stream_payload
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    product_service,
    run_visible_to_actor,
)


class AssessmentEventsConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.assessment_id = ""
        self.route_assessment_id = str(
            self.scope.get("url_route", {}).get("kwargs", {}).get("assessment_id") or ""
        )
        self.actor = None
        self.ticket_payload = None
        self.cursor = 0
        self._watch_task = None
        await self.accept()
        await self.send_json({"type": "realtime.ticket_required"})

    async def receive_json(self, content, **kwargs):
        if not isinstance(content, dict):
            await self.close(code=4400)
            return
        ticket = content.get("ticket")
        if not isinstance(ticket, str) or not ticket:
            await self.close(code=4401)
            return
        if self.assessment_id:
            await self.close(code=4401)
            return
        try:
            payload = decode_realtime_ticket(ticket)
            assessment_id = str(payload.get("assessment_id") or "")
            user_id = str(payload.get("user_id") or "")
            current_user = self.scope.get("user")
            if (
                not assessment_id
                or assessment_id != self.route_assessment_id
                or user_id != str(getattr(current_user, "pk", ""))
            ):
                raise signing.BadSignature("ticket subject mismatch")
            actor, visible = await self._authorized_visibility(assessment_id)
            if not visible:
                raise signing.BadSignature("assessment is not visible")
        except (KeyError, TypeError, ValueError, signing.BadSignature, signing.SignatureExpired):
            await self.close(code=4403)
            return
        self.actor = actor
        self.assessment_id = assessment_id
        self.ticket_payload = payload
        try:
            self.cursor = max(0, int(content.get("after_sequence", 0)))
        except (TypeError, ValueError):
            self.cursor = 0
        snapshot = await self._snapshot(after_sequence=self.cursor)
        await self.send_json(snapshot)
        self.cursor = int(snapshot.get("last_sequence", self.cursor))
        if not snapshot.get("terminal"):
            self._watch_task = asyncio.create_task(self._watch_persisted_activity())

    @sync_to_async
    def _authorized_visibility(self, assessment_id: str):
        user = self.scope.get("user")
        if user is None or not user.is_authenticated:
            return None, False
        try:
            actor = authorized_actor(user, required_actions=("scan.read",))
            run = product_service().get_agent_run(assessment_id)
        except (
            ObjectDoesNotExist,
            OSError,
            ProductServiceError,
            RuntimeError,
            ValueError,
            WebPermissionDenied,
        ):
            return None, False
        return actor, run_visible_to_actor(run, actor)

    @sync_to_async
    def _payload(self, after_sequence: int):
        run = product_service().get_agent_run(self.assessment_id)
        return _conversation_stream_payload(run, after_sequence=after_sequence)

    async def _watch_persisted_activity(self):
        try:
            while self.assessment_id:
                await asyncio.sleep(0.75)
                snapshot = await self._snapshot(after_sequence=self.cursor)
                last_sequence = int(snapshot.get("last_sequence", self.cursor))
                if last_sequence > self.cursor or snapshot.get("terminal"):
                    await self.send_json(snapshot)
                    self.cursor = last_sequence
                if snapshot.get("terminal"):
                    return
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError, ProductServiceError, RuntimeError, ValueError):
            # The durable stream remains authoritative; the client can reconnect and catch up.
            return

    async def disconnect(self, close_code):
        if self._watch_task is not None:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None
        self.assessment_id = ""

    async def _snapshot(self, after_sequence):
        try:
            cursor = max(0, int(after_sequence))
        except (TypeError, ValueError):
            cursor = 0
        payload = await self._payload(cursor)
        return {
            "type": "assessment.snapshot",
            "assessment_id": self.assessment_id,
            "events": payload.get("events", []),
            "last_sequence": int(payload.get("last_sequence", cursor)),
            "run_state": payload.get("run_state"),
            "terminal": bool(payload.get("terminal", False)),
            "activity_tree": payload.get("activity_tree")
            or {
                "schema_version": "1.0",
                "task_id": self.assessment_id,
                "status": "running",
                "last_sequence": int(payload.get("last_sequence", cursor)),
                "nodes": [],
            },
        }
