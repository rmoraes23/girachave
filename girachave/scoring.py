"""Score de exposição do tenant (0–100, quanto maior, melhor)."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from .models import Finding, Severity


@dataclass
class Score:
    value: int
    grade: str
    label: str
    by_severity: dict[str, int]


GRADES = [
    (85, "A", "Controlado"),
    (70, "B", "Atenção"),
    (50, "C", "Exposto"),
    (30, "D", "Alto risco"),
    (0, "E", "Crítico"),
]


def compute(findings: list[Finding]) -> Score:
    penalty = sum(f.severity.weight for f in findings)
    # Decaimento exponencial: cada achado pesa, mas o score nunca fica negativo
    value = round(100 * math.exp(-penalty / 250))
    grade, label = next((g, l) for t, g, l in GRADES if value >= t)
    counts = Counter(f.severity.value for f in findings)
    return Score(value, grade, label, {s.value: counts.get(s.value, 0) for s in Severity})
