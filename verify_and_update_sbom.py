"""
verify_and_update_sbom.py

Верификация и автообновление ЛИЦЕНЗИЙ в SBOM.

ВАЖНО: version / purl / cpe не меняются - версии зафиксированы в проекте и
поднимаются централизованно. Состав библиотек и их версии сохраняются как есть.
Для каждой (зафиксированной) версии скрипт:
  - сверяет лицензию с PyPI и исправляет только при настоящем расхождении
    (одинаковая семья лицензий и нераспознанные значения не затираются);
  - проверяет ссылку license_link и чинит битую под ту же версию.

Запуск
    python verify_and_update_sbom.py            # проверка + отчеты (dry-run)
    python verify_and_update_sbom.py --apply    # + перезаписать SBOM

Зависимости: requests  (pip install requests)
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import logging
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

import requests  # обязательная зависимость

# настройки

TIMEOUT = 12
MAX_WORKERS = 8
HEADERS = {"User-Agent": "SBOM-License-Verifier/3.0 (+python-requests)"}

# SPDX-идентификаторы, на которые ссылаемся
SPDX_PROPRIETARY = "Proprietary"

# Результат проверки URL - три честных состояния, а не bool
# Важно отличать «битая ссылка» от «не смогли проверить»: иначе на сетевой
# ошибке/таймауте рабочая ссылка будет ошибочно объявлена битой
URL_OK = "ok"
URL_BROKEN = "broken"
URL_ERROR = "error"

# порядок полей в каждом компоненте
FIELD_ORDER = [
    "name", "version", "purl", "source_url", "attack_surface",
    "security_functions", "usage", "cpe", "description", "description_rus",
    "license", "license_link", "commercial", "explicit",
]

# имена файлов лицензии, которые проверяем на гите
LICENSE_FILENAMES = ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "LICENSE.rst"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sbom")

# нормализация лицензий к SPDX

_SPDX_ALIASES: Dict[str, str] = {
    "mit": "MIT", "mit license": "MIT", "expat": "MIT",
    "apache 2": "Apache-2.0", "apache 2 0": "Apache-2.0", "apache-2 0": "Apache-2.0",
    "apache 2.0": "Apache-2.0", "apache-2.0": "Apache-2.0",
    "apache license 2 0": "Apache-2.0", "apache license version 2 0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "bsd 3 clause": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause", "new bsd": "BSD-3-Clause", "modified bsd": "BSD-3-Clause",
    "bsd 2 clause": "BSD-2-Clause", "bsd-2-clause": "BSD-2-Clause", "simplified bsd": "BSD-2-Clause",
    "isc": "ISC", "isc license iscl": "ISC", "isc license": "ISC",
    "mpl 2 0": "MPL-2.0", "mpl-2.0": "MPL-2.0", "mozilla public license 2 0": "MPL-2.0",
    "psf": "PSF-2.0", "psf 2 0": "PSF-2.0", "psf-2.0": "PSF-2.0",
    "python software foundation license": "PSF-2.0", "python 2 0": "PSF-2.0",
    "lgplv2": "LGPL-2.1", "lgpl 2 1": "LGPL-2.1", "lgpl-2.1": "LGPL-2.1",
    "lgplv2+": "LGPL-2.1-or-later", "lgpl 2 1 or later": "LGPL-2.1-or-later",
    "lgpl-2.1-or-later": "LGPL-2.1-or-later",
    "lgpl 3 0": "LGPL-3.0", "lgpl-3.0": "LGPL-3.0", "lgpl-3.0-only": "LGPL-3.0", "lgplv3": "LGPL-3.0",
    "lgpl 3 0 or later": "LGPL-3.0-or-later", "lgpl-3.0-or-later": "LGPL-3.0-or-later", "lgplv3+": "LGPL-3.0-or-later",
    "gpl 2 0": "GPL-2.0", "gpl-2.0": "GPL-2.0",
    "gpl 2 0 or later": "GPL-2.0-or-later", "gpl-2.0-or-later": "GPL-2.0-or-later", "gplv2+": "GPL-2.0-or-later",
    "gpl 3 0": "GPL-3.0", "gpl-3.0": "GPL-3.0",
    "gpl 3 0 or later": "GPL-3.0-or-later", "gpl-3.0-or-later": "GPL-3.0-or-later",
    "unlicense": "Unlicense", "the unlicense": "Unlicense",
    "cc0 1 0": "CC0-1.0", "cc0-1.0": "CC0-1.0",
    "zlib": "Zlib", "boost": "BSL-1.0", "boost software license 1 0": "BSL-1.0", "bsl-1.0": "BSL-1.0",
}

# Маркеры проприетарной/закрытой лицензии (подстрока в нижнем регистре)
_PROPRIETARY_MARKERS = ("proprietary", "commercial", "all rights reserved")


def _slug(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9+]+", " ", text.lower())).strip()


def _regex_spdx(slug: str) -> Optional[str]:
    """Обобщённое распознавание лицензии по структуре строки.

    Дополняет точный словарь _SPDX_ALIASES: ловит варианты написания, которых
    в словаре нет (его нельзя расширить на всё, что встретится). Возвращает один
    SPDX-идентификатор или None. slug - уже нормализованная строка из _slug().
    """
    s = slug
    or_later = bool(re.search(r"\bor later\b|\bplus\b", s) or s.rstrip().endswith("+"))

    if re.search(r"\bmit\b|\bexpat\b", s):
        return "MIT"
    if re.search(r"\bisc\b", s):
        return "ISC"
    if re.search(r"\bzlib\b", s):
        return "Zlib"
    if re.search(r"\bunlicense\b", s):
        return "Unlicense"
    if re.search(r"\bcc0\b", s):
        return "CC0-1.0"
    if re.search(r"\bbsl\b|\bboost\b", s):
        return "BSL-1.0"
    if re.search(r"\bmpl\b|\bmozilla\b", s):
        return "MPL-2.0"
    if re.search(r"\bpsf\b|python software foundation|\bpython 2\b", s):
        return "PSF-2.0"
    if re.search(r"\bapache\b", s):
        return "Apache-2.0"
    if re.search(r"\bbsd\b", s):
        if re.search(r"\b2\b|\btwo\b|simplified|freebsd", s):
            return "BSD-2-Clause"
        return "BSD-3-Clause"
    
    fam = re.search(r"\b(l|a)?gpl", s)
    if fam:
        nums = re.findall(r"\d+", s)
        if nums and nums[0] == "3":
            ver = "3.0"
        elif nums[:2] == ["2", "1"] or nums[:1] == ["21"]:
            ver = "2.1"
        elif nums and nums[0] == "2":
            ver = "2.0"
        else:
            ver = ""
        if ver:
            base = f"{fam.group(0).upper()}-{ver}"
            return base + ("-or-later" if or_later else "")
    return None


def canonicalize(raw: Any) -> Set[str]:
    """Произвольная строка лицензии -> набор SPDX-идентификаторов"""
    if not raw:
        return set()
    if isinstance(raw, (list, tuple)):
        out: Set[str] = set()
        for item in raw:
            out |= canonicalize(item)
        return out
    s = str(raw).strip()
    if not s:
        return set()
    if any(marker in s.lower() for marker in _PROPRIETARY_MARKERS):
        return {SPDX_PROPRIETARY}
    # делим составную лицензию ("MIT or Apache-2.0"), но не режется "or later"
    parts = re.split(r"\s+and\s+|\s+or\s+(?!later\b)|/|;|,", s, flags=re.IGNORECASE)
    found: Set[str] = set()
    for part in parts:
        slug = _slug(part)
        if not slug:
            continue
        spdx = _SPDX_ALIASES.get(slug) or _regex_spdx(slug)
        if spdx:
            found.add(spdx)
    return found


def license_family(spdx_set: Set[str]) -> Set[str]:
    """Семейство лицензии без уточнения редакции/версии

    BSD-3-Clause -> BSD, LGPL-2.1-or-later -> LGPL, GPL-2.0 -> GPL.
    Нужно, чтобы отличать настоящую смену лицензии (MIT -> Apache) от
    уточнения той же лицензии (BSD-2 vs BSD-3, GPL vs GPL-or-later)
    """
    return {re.split(r"[-]", s, maxsplit=1)[0] for s in spdx_set}


def classifiers_to_spdx(classifiers: List[str]) -> Set[str]:
    found: Set[str] = set()
    for c in classifiers or []:
        if not c.lower().startswith("license"):
            continue
        found |= canonicalize(c.split("::")[-1].strip())
    return found

# сеть

def http_get(url: str, allow_redirects: bool = True):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=allow_redirects)
    except requests.exceptions.RequestException:
        return None


def check_url(url: str) -> str:
    """Честная проверка ссылки: URL_OK / URL_BROKEN / URL_ERROR.

    URL_ERROR (таймаут, сетевой сбой, нет requests, 5xx) принципиально отличается
    от URL_BROKEN (404/410): «не смог проверить» - это НЕ «ссылка битая».
    """
    r = http_get(url)
    if r is None:
        return URL_ERROR
    if r.status_code == 200:
        return URL_OK
    if r.status_code in (404, 410):
        return URL_BROKEN
    return URL_ERROR


def parse_github_repo(source_url: str) -> Optional[str]:
    if not source_url or "github.com" not in source_url:
        return None
    m = re.search(r"github\.com/([^/]+/[^/#?]+)", source_url)
    if not m:
        return None
    return m.group(1).rstrip("/").removesuffix(".git")


def fetch_pypi_license(name: str, version: str) -> Set[str]:
    if not name:
        return set()
    for url in (f"https://pypi.org/pypi/{name}/{version}/json",
                f"https://pypi.org/pypi/{name}/json"):
        r = http_get(url)
        if r is None or r.status_code != 200:
            continue
        try:
            info = r.json().get("info", {})
        except Exception:
            continue
        spdx = canonicalize((info.get("license_expression") or "").strip())
        if not spdx:
            spdx = classifiers_to_spdx(info.get("classifiers", []))
        if not spdx:
            spdx = canonicalize((info.get("license") or "").strip())
        return spdx
    return set()


# обработка одного компонента

def process_component(comp: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Возвращает (новый_компонент, лог_изменений)
    version / purl / cpe не меняются
    """
    name = str(comp.get("name", "")).strip()
    version = str(comp.get("version", "")).strip()
    source_url = str(comp.get("source_url", "")).strip()
    declared_raw = comp.get("license", "")
    old_link = str(comp.get("license_link", "")).strip()
    old_purl = str(comp.get("purl", "")).strip()

    new = copy.deepcopy(comp)
    changed: List[str] = []
    notes: List[str] = []

    repo = parse_github_repo(source_url)

    # 1 лицензия, которая уточняется из pypi
    declared = canonicalize(declared_raw)
    pypi_name = old_purl[len("pkg:pypi/"):].split("@")[0] if old_purl.startswith("pkg:pypi/") else name
    upstream = fetch_pypi_license(pypi_name, version)

    final_license = declared_raw
    change_kind = ""
    if upstream:
        up_str = ", ".join(sorted(upstream))
        if declared and declared == upstream:
            final_license = declared_raw
        else:
            # достоверная из pypi, пометка на полном переходе лицензий
            final_license = up_str
            if not str(declared_raw).strip():
                change_kind = "filled"            # лицензии не было
            elif not declared:
                change_kind = "unrecognized"      # было непусто, но не распознало (HPND и тп)
            elif declared & upstream:
                change_kind = "partial"           # пересечение есть, но набор отличается
            elif license_family(declared) == license_family(upstream):
                change_kind = "variant"           # та же семья, но другая редакция (BSD-2 vs BSD-3)
            else:
                change_kind = "cross-family"      # полная смена (MIT -> Apache-2.0)
            notes.append(f"license-changed[{change_kind}]: {declared_raw} -> {up_str}")
    else:
        notes.append("license-unverified")        # pypi не дал лицензию - оставляем как было
    new["license"] = final_license

    # 2 ссылка на LICENSE для текущей версии
    new_link = old_link
    has_link = old_link.startswith(("http://", "https://"))
    status = check_url(old_link) if has_link else URL_BROKEN
    if status == URL_OK:
        pass  # рабочая - не трогаем
    elif status == URL_ERROR:
        # не смогли проверить (таймаут/сеть/5xx) - не засчитывется как битая ссылка
        notes.append("link-unchecked")
    elif repo:
        # ссылки нет или она 404 - подбираем под зафиксированную версию ('1.2.3'/'v1.2.3')
        chosen = ""
        for tag in (version, f"v{version}"):
            for fn in LICENSE_FILENAMES:
                raw = f"https://raw.githubusercontent.com/{repo}/{tag}/{fn}"
                if check_url(raw) == URL_OK:
                    chosen = f"https://github.com/{repo}/blob/{tag}/{fn}"
                    break
            if chosen:
                break
        if chosen:
            new_link = chosen
            notes.append("link-fixed")
        else:
            notes.append("link-broken-unresolved")
    else:
        notes.append("link-broken-non-github")
    new["license_link"] = new_link

    # учет изменений
    for field in ("license", "license_link"):
        if str(comp.get(field, "")) != str(new.get(field, "")):
            changed.append(field)

    # пересборка строго по шаблону
    ordered: Dict[str, Any] = {}
    for k in FIELD_ORDER:
        ordered[k] = new.get(k, comp.get(k, ""))
    for k, v in new.items():  # на случай нестандартных ключей - не теряем их
        if k not in ordered:
            ordered[k] = v

    logrow = {
        "name": name,
        "version": version,
        "license_match": bool(declared and upstream and (declared & upstream)),
        "old_license": str(declared_raw),
        "new_license": str(final_license),
        "license_changed": str(declared_raw) != str(final_license),
        "change_kind": change_kind,
        "old_link": old_link,
        "new_link": new_link,
        "link_changed": old_link != new_link,
        "changed_fields": ",".join(changed),
        "notes": "; ".join(notes),
    }
    return ordered, logrow

# главный конвейер

def load_sbom(path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    comps = data.get("thirdparty", {}).get("components")
    if comps is None:
        raise ValueError("Не найдена структура thirdparty -> components")
    return data, comps


def write_csv(path: str, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="Верификация и автообновление SBOM")
    ap.add_argument("--input", default="sbom_extra.json")
    ap.add_argument("--output", default="sbom_extra_updated.json")
    ap.add_argument("--report", default="license_report.csv")
    ap.add_argument("--problems", default="license_problems.csv")
    ap.add_argument("--apply", action="store_true",
                    help="перезаписать обновлённый SBOM (иначе только отчеты)")
    ap.add_argument("--inplace", action="store_true",
                    help="писать результат поверх --input (вместе с --apply)")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS)
    args = ap.parse_args()

    log.info("loading SBOM: %s", args.input)
    sbom, components = load_sbom(args.input)
    log.info("components: %d", len(components))

    results: List[Tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(process_component, c): idx
                for idx, c in enumerate(components)}
        done = 0
        for fut in as_completed(futs):
            idx = futs[fut]
            comp, logrow = fut.result()
            results.append((idx, comp, logrow))
            done += 1
            if done % 25 == 0 or done == len(components):
                log.info("processed %d/%d", done, len(components))

    # вернуть исходный порядок
    results.sort(key=lambda t: t[0])
    new_components = [comp for _, comp, _ in results]
    logs = [logrow for _, _, logrow in results]

    # статистика
    relicensed = sum(1 for l in logs if l["license_changed"])
    links_fixed = sum(1 for l in logs if l["link_changed"])
    verified = sum(1 for l in logs if l["license_match"])
    kinds = Counter(l["change_kind"] for l in logs if l["license_changed"])
    log.info("licenses confirmed: %d | changed: %d | links fixed: %d",
             verified, relicensed, links_fixed)
    log.info("changes by kind: %s", dict(kinds))

    # отчеты
    fields = ["name", "version", "license_match",
              "old_license", "new_license", "license_changed", "change_kind",
              "old_link", "new_link", "link_changed",
              "changed_fields", "notes"]
    write_csv(args.report, logs, fields)
    log.info("report: %s", args.report)

    problems = [l for l in logs if l["notes"] or l["license_changed"]]
    write_csv(args.problems, problems, fields)
    log.info("needs review: %d -> %s", len(problems), args.problems)

    # запись SBOM

    if args.apply:
        out_sbom = copy.deepcopy(sbom)
        out_sbom["thirdparty"]["components"] = new_components
        out_path = args.input if args.inplace else args.output
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out_sbom, f, ensure_ascii=False, indent=2)
        log.info("SBOM written: %s", out_path)
    else:
        log.info("dry-run (no --apply): SBOM not modified")

if __name__ == "__main__":
    main()