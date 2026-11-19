# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Illustrative, event-driven advisory journey for the desktop Run check page."""

from __future__ import annotations

import math
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QWidget


class RunJourneyWidget(QWidget):
    """Animate the current workflow phase without inventing scan percentages."""

    TURN_FRAMES = 12
    MOVE_FRAMES = 18
    FAIRY_MAX_SIZE = 62.0
    ANIMATION_MODES = frozenset({"full", "reduced", "disabled"})
    INPUT_PHASES = frozenset({
        "candidate-intake", "sources", "projects", "routing", "release-metadata",
        "evidence", "preflight",
    })
    PHASE_ASSETS = {
        "routing": "fairy-routing.png",
        "release-metadata": "fairy-sources.png",
        "sources": "fairy-sources.png",
        "candidate-intake": "fairy-sources.png",
        "evidence": "fairy-evidence.png",
        "staging": "fairy-consolidation.png",
        "consolidation": "fairy-consolidation.png",
        "report-staging": "fairy-validation.png",
        "candidate-ledger": "fairy-validation.png",
        "coverage-receipt": "fairy-validation.png",
        "validation": "fairy-validation.png",
        "correction": "fairy-correction.png",
        "promotion": "fairy-correction.png",
        "archive-followups": "fairy-correction.png",
        "state-update": "fairy-validation.png",
    }
    PHASE_LABELS = {
        "idle": "Ready", "preflight": "Preflight", "projects": "Inventory",
        "sources": "Sources", "routing": "Routing", "release-metadata": "Release data",
        "evidence": "Project evidence", "candidate-intake": "Candidate intake",
        "staging": "Private staging", "consolidation": "Consolidation",
        "report-staging": "Staged reports", "candidate-ledger": "Candidate ledger",
        "coverage-receipt": "Coverage receipt", "validation": "Guard rail gate",
        "correction": "Correction", "promotion": "Publishing",
        "archive-followups": "Follow-up archive", "state-update": "Checkpoints",
        "complete": "Complete",
    }
    MAIN_STATIONS = (
        ("preflight", "Prepare", "project"),
        ("release-metadata", "Release data", "source"),
        ("routing", "Route projects", "project"),
        ("evidence", "Project dossiers", "project"),
        ("candidate-intake", "Candidate intake", "source"),
        ("staging", "Private staging", "matching"),
        ("consolidation", "Correlate", "matching"),
        ("report-staging", "Staged reports", "validation"),
        ("candidate-ledger", "Candidate ledger", "validation"),
        ("coverage-receipt", "Coverage receipt", "validation"),
        ("validation", "Guard rail gate", "validation"),
        ("promotion", "Publish reports", "reports"),
        ("archive-followups", "Archive follow-up", "reports"),
        ("state-update", "Checkpoints", "reports"),
        ("complete", "Complete", "reports"),
    )
    STATION_COLORS = {
        "source": QColor("#4bd8eb"),
        "project": QColor("#a98bff"),
        "matching": QColor("#58cde0"),
        "validation": QColor("#71b9ff"),
        "correction": QColor("#e5bb62"),
        "reports": QColor("#7ad99a"),
    }
    PHASE_POSITIONS = {
        "idle": (.06, 0), "preflight": (.06, 0),
        "release-metadata": (.185, 0), "routing": (.31, 0),
        "evidence": (.435, 0), "candidate-intake": (.56, 0),
        "staging": (.685, 0), "consolidation": (.81, 0),
        "report-staging": (.935, 0), "candidate-ledger": (.935, 1),
        "coverage-receipt": (.79, 1), "validation": (.645, 1),
        "correction": (.645, .50), "promotion": (.50, 1),
        "archive-followups": (.355, 1), "state-update": (.21, 1),
        "complete": (.065, 1),
        "sources": (.56, 0), "projects": (.435, 0),
    }
    PHASE_ALIASES = {"sources": "candidate-intake", "projects": "evidence"}

    def __init__(
        self, icon_path: Path, parent: QWidget | None = None,
        *, animation_mode: str = "full",
    ) -> None:
        super().__init__(parent)
        self.setMinimumHeight(320)
        self.setAccessibleName("Security check activity animation")
        self.setToolTip(
            "The connected stations follow real process milestones. In full mode fAIry "
            "moves between the station associated with each phase."
        )
        self.icon = QPixmap(str(icon_path))
        self.phase_icons = {
            phase: QPixmap(str(icon_path.parent / filename))
            for phase, filename in self.PHASE_ASSETS.items()
        }
        self.idle_sprite = QPixmap(str(icon_path.parent / "fairy-idle-sprite.png"))
        self.animation_mode = (
            animation_mode if animation_mode in self.ANIMATION_MODES else "full"
        )
        self.state = "idle"
        self.phase = "idle"
        self.agent = ""
        self.message = "Ready for a security check"
        self.detail = "Waiting for a real process event"
        self.completed = 0
        self.total = 0
        self.attempt = 0
        self.max_attempts = 0
        self.frame = 0
        self.turn_from = 1.0
        self.turn_to = 1.0
        self.turn_started = 0
        self.position_from = self.PHASE_POSITIONS["idle"]
        self.position_to = self.PHASE_POSITIONS["idle"]
        self.move_started = 0
        self.travel_from_phase = "preflight"
        self.visited_phases: set[str] = set()
        self.phase_states: dict[str, str] = {}
        self.pending_events: list[dict[str, object]] = []
        self.finish_requested = False
        self.timer = QTimer(self)
        self.timer.setInterval(70 if self.animation_mode == "full" else 240)
        self.timer.timeout.connect(self._advance)
        self._update_accessibility()
        self._sync_timer()

    def set_animation_mode(self, mode: str) -> None:
        if mode not in self.ANIMATION_MODES:
            raise ValueError(f"Unsupported animation mode: {mode}")
        self.animation_mode = mode
        if mode != "full":
            while self.pending_events:
                self._apply_progress_event(self.pending_events.pop(0))
            if self.finish_requested and self.phase == "complete":
                self._complete_finish()
        self._sync_timer()
        self._update_accessibility()
        self.update()

    def _sync_timer(self) -> None:
        if self.state not in {"idle", "running"} or self.animation_mode == "disabled":
            self.timer.stop()
            return
        self.timer.setInterval(70 if self.animation_mode == "full" else 240)
        self.timer.start()

    def start(self, action: str) -> None:
        self.state = "running"
        next_phase = {
            "ai-check": "preflight", "sources": "candidate-intake", "refresh": "evidence",
            "prerequisites": "preflight", "validate": "preflight",
            "prepublish": "preflight",
        }.get(action, "preflight")
        self.phase = next_phase
        self.agent = ""
        self.message = {
            "ai-check": "Preparing advisory analysis",
            "sources": "Checking advisory sources",
            "refresh": "Scanning configured project paths",
            "prerequisites": "Checking prerequisites",
            "validate": "Validating configuration",
            "prepublish": "Running publication checks",
        }.get(action, "Running check")
        self.detail = "Waiting for the next process milestone"
        self.completed = 0
        self.total = 0
        self.attempt = 0
        self.max_attempts = 0
        self.frame = 0
        self.position_from = self.PHASE_POSITIONS["idle"]
        self.position_to = self.PHASE_POSITIONS[next_phase]
        self.move_started = 0
        self.travel_from_phase = "preflight"
        self.visited_phases = set()
        self.phase_states = {next_phase: "running"}
        self.pending_events = []
        self.finish_requested = False
        self.turn_to = -1.0 if self.phase in self.INPUT_PHASES else 1.0
        self.turn_from = self.turn_to
        self.turn_started = 0
        self._sync_timer()
        self._update_accessibility()
        self.update()

    def progress(self, event: dict[str, object]) -> None:
        phase = str(event.get("phase") or "").casefold()
        phase = self.PHASE_ALIASES.get(phase, phase)
        status = str(event.get("status") or "running").casefold()
        next_phase = phase if phase in self.PHASE_LABELS else self.phase
        if status != "failed" and (
            self.animation_mode == "full" and self.state == "running"
            and next_phase != self.phase and (self._is_moving() or self.pending_events)
        ):
            self.pending_events.append(dict(event))
            self._sync_timer()
            return
        self._apply_progress_event(event)

    def _apply_progress_event(self, event: dict[str, object]) -> None:
        phase = str(event.get("phase") or "").casefold()
        phase = self.PHASE_ALIASES.get(phase, phase)
        status = str(event.get("status") or "running").casefold()
        facing_before = self._face_scale()
        next_phase = phase if phase in self.PHASE_LABELS else self.phase
        if next_phase != self.phase:
            self.travel_from_phase = self.phase
            self.position_from = self._position_ratio()
            self.position_to = self.PHASE_POSITIONS[next_phase]
            self.move_started = self.frame
        self.phase = next_phase
        if status in {"completed", "completed-with-limitations"}:
            self.phase_states[next_phase] = "completed"
            self.visited_phases.add(next_phase)
        elif status in {"failed", "rejected"}:
            self.phase_states[next_phase] = status
            self.visited_phases.discard(next_phase)
        else:
            self.phase_states[next_phase] = "running"
        facing_after = -1.0 if self.phase in self.INPUT_PHASES else 1.0
        if facing_after != self.turn_to:
            self.turn_from = facing_before
            self.turn_to = facing_after
            self.turn_started = self.frame
        self.agent = str(event.get("provider") or "").title()
        self.message = str(event.get("message") or self.message)
        self.detail = str(event.get("detail") or self.detail)
        try:
            self.completed = max(0, int(event.get("completed") or 0))
            self.total = max(0, int(event.get("total") or 0))
            self.attempt = max(0, int(event.get("attempt") or 0))
            self.max_attempts = max(0, int(event.get("max_attempts") or 0))
        except (TypeError, ValueError):
            self.completed = 0
            self.total = 0
            self.attempt = 0
            self.max_attempts = 0
        if status == "failed":
            self.position_from = self.position_to = self.PHASE_POSITIONS[self.phase]
            self.finish(False)
        elif status in {"completed", "completed-with-limitations"} and phase == "complete":
            self.finish_requested = True
            if self.animation_mode != "full" or not self._is_moving():
                self._complete_finish()
        else:
            self._sync_timer()
            self._update_accessibility()
            self.update()

    def finish(self, success: bool) -> None:
        if not success:
            self.pending_events.clear()
            self.finish_requested = False
            self.state = "failed"
            self.message = "Check failed — review the log"
            self.timer.stop()
            self._update_accessibility()
            self.update()
            return
        if self.animation_mode == "full" and self.state == "running" and (
            self._is_moving() or self.pending_events or self.phase != "complete"
        ):
            self.finish_requested = True
            if not any(
                str(item.get("phase", "")).casefold() == "complete"
                for item in self.pending_events
            ) and self.phase != "complete":
                self.pending_events.append({
                    "phase": "complete", "status": "completed",
                    "message": "Check complete",
                })
            self._sync_timer()
            return
        self._complete_finish()

    def _complete_finish(self) -> None:
        self.state = "completed"
        self.phase = "complete"
        self.message = "Check complete"
        self.phase_states["complete"] = "completed"
        self.visited_phases.add("complete")
        self.finish_requested = False
        self.turn_from = self.turn_to = 1.0
        self.position_from = self.position_to = self.PHASE_POSITIONS["complete"]
        self.timer.stop()
        self._update_accessibility()
        self.update()

    def _update_accessibility(self) -> None:
        detail = f"{self.agent}: {self.message}" if self.agent else self.message
        if self.detail:
            detail += f". {self.detail}"
        if self.total:
            detail += f". {self.completed} of {self.total} projects completed"
        if self.max_attempts:
            detail += f". Attempt {self.attempt} of {self.max_attempts}"
        detail += f". Animation mode {self.animation_mode}"
        self.setAccessibleDescription(detail)

    def _advance(self) -> None:
        self.frame += 1
        if not self._is_moving() and self.pending_events:
            self._apply_progress_event(self.pending_events.pop(0))
        if (
            self.finish_requested and not self.pending_events
            and self.phase == "complete" and not self._is_moving()
        ):
            self._complete_finish()
        self.update()

    def _is_moving(self) -> bool:
        return (
            self.animation_mode == "full"
            and self.position_from != self.position_to
            and self.frame - self.move_started < self.MOVE_FRAMES
        )

    def _face_scale(self) -> float:
        if self.animation_mode != "full":
            return self.turn_to
        elapsed = min(1.0, (self.frame - self.turn_started) / self.TURN_FRAMES)
        easing = (1.0 - math.cos(math.pi * elapsed)) / 2.0
        return self.turn_from + (self.turn_to - self.turn_from) * easing

    def _position_ratio(self) -> tuple[float, float]:
        """Return the current eased position inside the workflow graph."""
        if self.animation_mode != "full":
            return self.position_to
        elapsed = min(1.0, max(0.0, (self.frame - self.move_started) / self.MOVE_FRAMES))
        easing = (1.0 - math.cos(math.pi * elapsed)) / 2.0
        return (
            self.position_from[0] + (self.position_to[0] - self.position_from[0]) * easing,
            self.position_from[1] + (self.position_to[1] - self.position_from[1]) * easing,
        )

    def _fairy_position(
        self, width: float, top_y: float, bottom_y: float,
    ) -> QPointF:
        """Map the workflow-relative position to the current widget geometry."""
        ratio_x, ratio_y = self._position_ratio()
        x = 20.0 + (width - 40.0) * ratio_x
        y = top_y + (bottom_y - top_y) * ratio_y
        if self.phase == "correction":
            x += 72.0
        elif ratio_y <= .2:
            y += 46.0
        elif ratio_y >= .8:
            y -= 46.0
            if self.phase == "validation":
                x -= 72.0
        if self.state == "running" and self.animation_mode == "full":
            y += 2.5 * math.cos(self.frame * .13)
        elif self.state == "running" and self.animation_mode == "reduced":
            y += .8 * math.sin(self.frame * .18)
        return QPointF(x, y)

    def _wand_angle(self) -> float:
        if (
            self.animation_mode == "full" and self.state == "running"
            and self.phase in {"consolidation", "correction"}
        ):
            return 9.0 * math.sin(self.frame * .28)
        return 0.0

    def _phase_icon(self) -> QPixmap:
        selected = self.phase_icons.get(self.phase)
        return selected if selected is not None and not selected.isNull() else self.icon

    def _phase_pixmap(self) -> tuple[QPixmap, QRectF]:
        if self.state == "idle" and not self.idle_sprite.isNull():
            frame_delay = 8 if self.animation_mode == "full" else 5
            index = 0 if self.animation_mode == "disabled" else (self.frame // frame_delay) % 4
            frame_width = self.idle_sprite.width() / 2
            frame_height = self.idle_sprite.height() / 2
            return self.idle_sprite, QRectF(
                (index % 2) * frame_width, (index // 2) * frame_height,
                frame_width, frame_height,
            )
        icon = self._phase_icon()
        return icon, QRectF(icon.rect())

    def _active_edges(self) -> set[str]:
        return {self.phase} if self.state in {"running", "completed"} else set()

    def _station_rectangles(
        self, width: float, graph_top: float, graph_bottom: float,
    ) -> dict[str, QRectF]:
        """Lay out the real workflow as a two-row snake plus correction branch."""
        gap = 8.0
        node_width = min(116.0, max(66.0, (width - 36.0 - gap * 7) / 8.0))
        node_height = 34.0
        left = 18.0
        right = max(left, width - 18.0 - node_width)
        top_step = (right - left) / 7.0 if right > left else 0.0
        bottom_step = (right - left) / 6.0 if right > left else 0.0
        rectangles: dict[str, QRectF] = {}
        for index, (phase, _label, _category) in enumerate(self.MAIN_STATIONS[:8]):
            rectangles[phase] = QRectF(
                left + top_step * index, graph_top, node_width, node_height,
            )
        for index, (phase, _label, _category) in enumerate(self.MAIN_STATIONS[8:]):
            rectangles[phase] = QRectF(
                right - bottom_step * index, graph_bottom, node_width, node_height,
            )
        validation = rectangles["validation"]
        rectangles["correction"] = QRectF(
            validation.x(), (graph_top + graph_bottom) / 2.0,
            node_width, node_height,
        )
        return rectangles

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width, height = float(self.width()), float(self.height())
        painter.setPen(QPen(QColor("#31516e"), 1))
        painter.setBrush(QColor("#10243d"))
        painter.drawRoundedRect(QRectF(0.5, 0.5, width - 1, height - 1), 12, 12)

        painter.setPen(QColor("#e8f2ff"))
        painter.setFont(QFont("Sans Serif", 12, QFont.Weight.Bold))
        painter.drawText(QRectF(18, 12, width - 170, 25), "fAIry at work")
        status_color = {
            "idle": QColor("#8fa8bf"), "running": QColor("#4bd8eb"),
            "completed": QColor("#7ad99a"), "failed": QColor("#e88484"),
        }[self.state]
        painter.setBrush(status_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(width - 125, 24), 5, 5)
        painter.setPen(status_color)
        painter.setFont(QFont("Sans Serif", 9, QFont.Weight.Bold))
        painter.drawText(QRectF(width - 113, 13, 100, 22), self.state.title())

        subtitle = f"{self.agent} · {self.message}" if self.agent else self.message
        painter.setPen(QColor("#b9d3e7"))
        painter.setFont(QFont("Sans Serif", 10))
        painter.drawText(QRectF(18, 37, width - 36, 26),
                         Qt.AlignmentFlag.AlignVCenter, subtitle)

        badges = [self.PHASE_LABELS.get(self.phase, self.phase.title())]
        if self.agent:
            badges.append(self.agent)
        if self.total:
            badges.append(f"Projects {self.completed}/{self.total}")
        if self.max_attempts:
            badges.append(f"Attempt {self.attempt}/{self.max_attempts}")
        badge_x = 18.0
        for badge in badges:
            badge_x = self._badge(painter, badge_x, 66.0, badge)
            if badge_x > width - 90:
                break
        painter.setPen(QColor("#90abc2"))
        painter.setFont(QFont("Sans Serif", 8))
        painter.drawText(
            QRectF(18, 88, width - 36, 20),
            Qt.AlignmentFlag.AlignVCenter, self.detail,
        )

        graph_top = max(116.0, min(145.0, height * .36))
        graph_bottom = min(height - 58.0, graph_top + 126.0)
        stations = self._station_rectangles(width, graph_top, graph_bottom)
        top_center = stations["preflight"].center().y()
        bottom_center = stations["complete"].center().y()
        fairy_point = self._fairy_position(
            width, top_center, bottom_center,
        )
        fairy_x, fairy_y = fairy_point.x(), fairy_point.y()
        fairy_size = min(self.FAIRY_MAX_SIZE, max(46.0, height * .17))

        main_phases = [phase for phase, _label, _category in self.MAIN_STATIONS]
        connections = list(zip(main_phases, main_phases[1:])) + [
            ("validation", "correction"), ("correction", "report-staging"),
        ]
        station_categories = {
            phase: category for phase, _label, category in self.MAIN_STATIONS
        } | {"correction": "correction"}
        active_connection = (self.travel_from_phase, self.phase)
        for start_phase, end_phase in connections:
            start_rect, end_rect = stations[start_phase], stations[end_phase]
            if start_rect.center().y() == end_rect.center().y():
                if start_rect.center().x() < end_rect.center().x():
                    start = QPointF(start_rect.right(), start_rect.center().y())
                    end = QPointF(end_rect.left(), end_rect.center().y())
                else:
                    start = QPointF(start_rect.left(), start_rect.center().y())
                    end = QPointF(end_rect.right(), end_rect.center().y())
            else:
                start, end = start_rect.center(), end_rect.center()
            path = self._curve(start, end)
            color = self.STATION_COLORS[station_categories[end_phase]]
            inactive = QColor(color)
            visited = start_phase in self.visited_phases and end_phase in self.visited_phases
            inactive.setAlpha(135 if visited else 42)
            is_active = active_connection == (start_phase, end_phase)
            painter.setPen(QPen(color if is_active else inactive, 2.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)
            if (
                self.state == "running" and is_active
                and self.animation_mode == "full"
            ):
                self._particles(painter, path, color)
        for phase, label, category in self.MAIN_STATIONS:
            self._node(
                painter, stations[phase], label, phase == self.phase,
                phase in self.visited_phases, self.STATION_COLORS[category],
            )
        self._node(
            painter, stations["correction"], "Correction", self.phase == "correction",
            "correction" in self.visited_phases, self.STATION_COLORS["correction"],
        )
        spell_target = (
            stations["report-staging"].center()
            if self.phase == "correction" else stations["consolidation"].center()
        )

        wand_tip = None
        phase_icon, phase_source = self._phase_pixmap()
        if not phase_icon.isNull():
            if self.state == "running" and self.animation_mode == "full":
                pulse = 1.0 + 0.025 * math.sin(self.frame * .20)
            elif self.state == "running" and self.animation_mode == "reduced":
                pulse = 1.0 + 0.006 * math.sin(self.frame * .18)
            else:
                pulse = 1.0
            size = fairy_size * pulse
            painter.save()
            painter.translate(fairy_x, fairy_y)
            painter.scale(self._face_scale(), 1.0)
            painter.rotate(self._wand_angle())
            wand_tip = painter.transform().map(QPointF(size * .39, -size * .40))
            painter.drawPixmap(
                QRectF(-size / 2, -size / 2, size, size),
                phase_icon,
                phase_source,
            )
            painter.restore()
        if (wand_tip is not None and self.state == "running"
                and self.animation_mode == "full"
                and self.phase in {"consolidation", "correction"}
                and self._face_scale() > .5):
            self._spell(
                painter, wand_tip, spell_target,
            )
        if self.state == "running" and self.animation_mode == "full":
            self._sparkles(painter, fairy_x, fairy_y, fairy_size)

        if height >= 250:
            painter.setPen(QColor("#829eb6"))
            painter.setFont(QFont("Sans Serif", 8))
            painter.drawText(
                QRectF(18, height - 25, width - 36, 18),
                Qt.AlignmentFlag.AlignVCenter,
                f"Real process milestones · animation: {self.animation_mode}",
            )
        painter.end()

    @staticmethod
    def _badge(painter: QPainter, x: float, y: float, text: str) -> float:
        width = max(55.0, min(150.0, 16.0 + len(text) * 6.2))
        rect = QRectF(x, y, width, 18)
        painter.setPen(QPen(QColor("#315b78"), 1))
        painter.setBrush(QColor("#112f49"))
        painter.drawRoundedRect(rect, 8, 8)
        painter.setPen(QColor("#bfe7f3"))
        painter.setFont(QFont("Sans Serif", 7, QFont.Weight.Bold))
        painter.drawText(rect.adjusted(6, 0, -6, 0), Qt.AlignmentFlag.AlignCenter, text)
        return x + width + 7

    @staticmethod
    def _curve(start: QPointF, end: QPointF) -> QPainterPath:
        path = QPainterPath(start)
        distance = (end.x() - start.x()) * .45
        path.cubicTo(
            QPointF(start.x() + distance, start.y()),
            QPointF(end.x() - distance, end.y()), end,
        )
        return path

    def _particles(self, painter: QPainter, path: QPainterPath, color: QColor) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        for offset in (0.0, .34, .68):
            position = path.pointAtPercent(((self.frame / 25) + offset) % 1)
            glow = QColor(color)
            glow.setAlpha(65)
            painter.setBrush(glow)
            painter.drawEllipse(position, 7, 7)
            painter.setBrush(color)
            painter.drawEllipse(position, 3, 3)

    def _spell(self, painter: QPainter, tip: QPointF, target: QPointF) -> None:
        """Cast a moving sparkle trail from the rotated wand to the matching node."""
        trail = self._curve(tip, target)
        glow = QColor("#a98bff")
        glow.setAlpha(100)
        painter.setPen(QPen(glow, 2.4))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(trail)
        painter.setPen(Qt.PenStyle.NoPen)
        for offset in (0.0, .25, .5, .75):
            point = trail.pointAtPercent(((self.frame / 24) + offset) % 1)
            color = QColor("#d6b6ff") if offset < .5 else QColor("#76e8ff")
            painter.setBrush(color)
            painter.drawEllipse(point, 3.5, 3.5)
        painter.setPen(QPen(QColor("#e7d1ff"), 1.8))
        radius = 3.0 + 2.0 * abs(math.sin(self.frame * .28))
        painter.drawLine(QPointF(tip.x() - radius, tip.y()), QPointF(tip.x() + radius, tip.y()))
        painter.drawLine(QPointF(tip.x(), tip.y() - radius), QPointF(tip.x(), tip.y() + radius))

    def _sparkles(self, painter: QPainter, x: float, y: float, size: float) -> None:
        color = QColor("#d8aaff")
        painter.setPen(QPen(color, 1.4))
        for index, (dx, dy) in enumerate(((-.56, -.35), (.54, -.45), (.48, .46), (-.48, .52))):
            if (self.frame + index * 7) % 22 > 14:
                continue
            px, py = x + dx * size, y + dy * size
            radius = 2.5 + ((self.frame + index * 7) % 11) / 5
            painter.drawLine(QPointF(px - radius, py), QPointF(px + radius, py))
            painter.drawLine(QPointF(px, py - radius), QPointF(px, py + radius))

    @staticmethod
    def _node(
        painter: QPainter, rect: QRectF, label: str, active: bool,
        visited: bool, color: QColor,
    ) -> None:
        border = QColor(color)
        border.setAlpha(230 if active else 145 if visited else 65)
        painter.setPen(QPen(border, 1.5))
        painter.setBrush(
            QColor("#12304a") if active
            else QColor("#10253a") if visited else QColor("#0b1b31")
        )
        painter.drawRoundedRect(rect, 8, 8)
        painter.setPen(
            QColor("#f2f8ff") if active
            else QColor("#bfd5e5") if visited else QColor("#829bb1")
        )
        font_size = 7 if rect.width() < 90 else 8
        painter.setFont(QFont("Sans Serif", font_size, QFont.Weight.Bold))
        painter.drawText(rect.adjusted(4, 2, -4, -2), Qt.AlignmentFlag.AlignCenter, label)
