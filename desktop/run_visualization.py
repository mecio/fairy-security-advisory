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
    FAIRY_MAX_SIZE = 74.0
    ANIMATION_MODES = frozenset({"full", "reduced", "disabled"})
    INPUT_PHASES = frozenset({
        "sources", "projects", "routing", "release-metadata", "evidence", "preflight",
    })
    PHASE_ASSETS = {
        "routing": "fairy-routing.png",
        "release-metadata": "fairy-sources.png",
        "sources": "fairy-sources.png",
        "evidence": "fairy-evidence.png",
        "consolidation": "fairy-consolidation.png",
        "validation": "fairy-validation.png",
        "correction": "fairy-correction.png",
        "promotion": "fairy-correction.png",
        "state-update": "fairy-validation.png",
    }
    PHASE_LABELS = {
        "idle": "Ready", "preflight": "Preflight", "projects": "Inventory",
        "sources": "Sources", "routing": "Routing", "release-metadata": "Release data",
        "evidence": "Evidence", "consolidation": "Consolidation",
        "validation": "Validation", "correction": "Correction",
        "promotion": "Publishing", "state-update": "Checkpoints", "complete": "Complete",
    }
    COLORS = {
        "source-intake": QColor("#4bd8eb"),
        "project-intake": QColor("#a98bff"),
        "source-match": QColor("#48c8dc"),
        "project-match": QColor("#9c86ee"),
        "validation": QColor("#71b9ff"),
        "reports": QColor("#7ad99a"),
    }
    PHASE_POSITIONS = {
        "idle": (.39, .50),
        "preflight": (.11, .50),
        "sources": (.16, .04),
        "release-metadata": (.40, .04),
        "projects": (.16, .96),
        "routing": (.17, .96),
        "evidence": (.40, .96),
        "consolidation": (.43, .50),
        "validation": (.625, .50),
        "correction": (.625, .50),
        "promotion": (.82, .50),
        "state-update": (.88, .50),
        "complete": (.91, .50),
    }

    def __init__(
        self, icon_path: Path, parent: QWidget | None = None,
        *, animation_mode: str = "full",
    ) -> None:
        super().__init__(parent)
        self.setMinimumHeight(260)
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
        self.timer = QTimer(self)
        self.timer.setInterval(70 if self.animation_mode == "full" else 240)
        self.timer.timeout.connect(self._advance)
        self._update_accessibility()
        self._sync_timer()

    def set_animation_mode(self, mode: str) -> None:
        if mode not in self.ANIMATION_MODES:
            raise ValueError(f"Unsupported animation mode: {mode}")
        self.animation_mode = mode
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
            "ai-check": "routing", "sources": "sources", "refresh": "projects",
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
        self.turn_to = -1.0 if self.phase in self.INPUT_PHASES else 1.0
        self.turn_from = self.turn_to
        self.turn_started = 0
        self._sync_timer()
        self._update_accessibility()
        self.update()

    def progress(self, event: dict[str, object]) -> None:
        phase = str(event.get("phase") or "").casefold()
        status = str(event.get("status") or "running").casefold()
        facing_before = self._face_scale()
        next_phase = phase if phase in self.PHASE_LABELS else self.phase
        if next_phase != self.phase:
            self.position_from = self._position_ratio()
            self.position_to = self.PHASE_POSITIONS[next_phase]
            self.move_started = self.frame
        self.phase = next_phase
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
            self.finish(False)
        elif status in {"completed", "completed-with-limitations"} and phase == "complete":
            self.finish(True)
        else:
            self._sync_timer()
            self._update_accessibility()
            self.update()

    def finish(self, success: bool) -> None:
        self.state = "completed" if success else "failed"
        self.phase = "complete" if success else self.phase
        self.message = "Check complete" if success else "Check failed — review the log"
        if success:
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
        self.update()

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
        if self.state == "completed":
            return set(self.COLORS)
        if self.state != "running":
            return set()
        return {
            "sources": {"source-intake"},
            "projects": {"project-intake"},
            "routing": {"project-intake"},
            "release-metadata": {"source-intake", "source-match"},
            "evidence": {"project-intake", "project-match"},
            "consolidation": {"source-match", "project-match"},
            "validation": {"validation"},
            "correction": {"validation"},
            "promotion": {"reports"},
            "state-update": {"reports"},
            "preflight": {"source-intake", "project-intake"},
        }.get(self.phase, set())

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

        y_top = max(116.0, min(145.0, height * .39))
        y_bottom = max(184.0, min(242.0, height * .66))
        center_y = (y_top + y_bottom) / 2
        node_width = min(126.0, max(84.0, width * .13))
        node_height = 36.0
        source_x = 18.0
        release_x = max(source_x + node_width + 28.0, width * .22)
        match_x = max(release_x + node_width + 38.0, width * .46)
        validate_x = max(match_x + node_width + 25.0, width * .65)
        report_x = width - node_width - 18.0
        if validate_x + node_width + 22.0 > report_x:
            validate_x = report_x - node_width - 22.0
        fairy_point = self._fairy_position(
            width, y_top + node_height / 2, y_bottom + node_height / 2,
        )
        fairy_x, fairy_y = fairy_point.x(), fairy_point.y()
        fairy_size = min(self.FAIRY_MAX_SIZE, max(52.0, height * .20))

        paths = {
            "source-intake": self._curve(
                QPointF(source_x + node_width, y_top + node_height / 2),
                QPointF(release_x, y_top + node_height / 2),
            ),
            "project-intake": self._curve(
                QPointF(source_x + node_width, y_bottom + node_height / 2),
                QPointF(release_x, y_bottom + node_height / 2),
            ),
            "source-match": self._curve(
                QPointF(release_x + node_width, y_top + node_height / 2),
                QPointF(match_x, center_y + node_height / 2),
            ),
            "project-match": self._curve(
                QPointF(release_x + node_width, y_bottom + node_height / 2),
                QPointF(match_x, center_y + node_height / 2),
            ),
            "validation": self._curve(
                QPointF(match_x + node_width, center_y + node_height / 2),
                QPointF(validate_x, center_y + node_height / 2),
            ),
            "reports": self._curve(
                QPointF(validate_x + node_width, center_y + node_height / 2),
                QPointF(report_x, center_y + node_height / 2),
            ),
        }
        active = self._active_edges()
        for name, path in paths.items():
            color = self.COLORS[name]
            inactive = QColor(color)
            inactive.setAlpha(65)
            painter.setPen(QPen(color if name in active else inactive, 2.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)
            if (
                self.state == "running" and name in active
                and self.animation_mode == "full"
            ):
                self._particles(painter, path, color)

        self._node(painter, QRectF(source_x, y_top, node_width, node_height),
                   "Advisory sources", "source-intake" in active,
                   self.COLORS["source-intake"])
        self._node(painter, QRectF(release_x, y_top, node_width, node_height),
                   "Release metadata", bool(active & {"source-intake", "source-match"}),
                   self.COLORS["source-match"])
        self._node(painter, QRectF(source_x, y_bottom, node_width, node_height),
                   "Local projects", "project-intake" in active,
                   self.COLORS["project-intake"])
        self._node(painter, QRectF(release_x, y_bottom, node_width, node_height),
                   "Project evidence", bool(active & {"project-intake", "project-match"}),
                   self.COLORS["project-match"])
        self._node(painter, QRectF(match_x, center_y, node_width, node_height),
                   "Match & consolidate", bool(active & {"source-match", "project-match"}),
                   self.COLORS["validation"])
        self._node(painter, QRectF(validate_x, center_y, node_width, node_height),
                   "Validate", "validation" in active, self.COLORS["validation"])
        self._node(painter, QRectF(report_x, center_y, node_width, node_height),
                   "Report", "reports" in active, self.COLORS["reports"])

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
                painter, wand_tip,
                QPointF(match_x + node_width * .18, center_y + node_height / 2),
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
        painter: QPainter, rect: QRectF, label: str, active: bool, color: QColor,
    ) -> None:
        border = QColor(color)
        border.setAlpha(230 if active else 85)
        painter.setPen(QPen(border, 1.5))
        painter.setBrush(QColor("#12304a") if active else QColor("#0b1b31"))
        painter.drawRoundedRect(rect, 8, 8)
        painter.setPen(QColor("#f2f8ff") if active else QColor("#9fb4c8"))
        painter.setFont(QFont("Sans Serif", 9, QFont.Weight.Bold))
        painter.drawText(rect.adjusted(4, 2, -4, -2), Qt.AlignmentFlag.AlignCenter, label)
