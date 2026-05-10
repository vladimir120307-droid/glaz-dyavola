"""Shannon entropy — base-2, в битах на символ. Используется для фильтрации
ложных срабатываний секрет-сканера на структурированных строках вроде имён
переменных, путей и URL-фрагментов."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Возвращает энтропию строки в битах/символ (0 для пустой строки)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Пороги (эмпирические, согласованы с truffleHog / detect-secrets):
ENTROPY_BASE64 = 4.5  # base64-подобные строки
ENTROPY_HEX = 3.0     # hex-строки (алфавит беднее → ниже энтропия)
