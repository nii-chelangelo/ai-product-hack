"""Build a self-contained local HTML dashboard from runs/ evidence.

Reads whatever the current run schema produces (state.json, evaluations/*.json,
state_diffs/*.json) and embeds it into a static page — no server, no build step.
Legacy/exploratory run directories that do not match the current evaluation shape
are skipped rather than raising, since runs/ accumulates ad-hoc formats over time.
"""

import json
from pathlib import Path
from typing import Any

from attack_on_agent.summary import DIMENSIONS, VERDICTS, asr, breach_of, llamator_summary, verdict_of


def build_dashboard(runs_dir: Path) -> str:
    runs = [run for run in (_load_run(path) for path in sorted(runs_dir.iterdir()) if path.is_dir()) if run]
    runs.sort(key=lambda run: run["created_at"], reverse=True)
    return _TEMPLATE.replace("__DATA__", json.dumps(runs, ensure_ascii=False))


def _load_run(run_dir: Path) -> dict[str, Any] | None:
    state_path = run_dir / "state.json"
    if not state_path.exists():
        return None
    try:
        state = json.loads(state_path.read_text())
    except json.JSONDecodeError:
        return None

    tests = [test for test in (_load_test(run_dir, state, path) for path in _evaluation_paths(run_dir)) if test]
    counts = {name: sum(1 for t in tests if t["verdict"] == name) for name in VERDICTS}
    valid_tests = [t for t in tests if t["verdict"] in ("SUCCESS", "FAIL")]
    successful = [t for t in tests if t["verdict"] == "SUCCESS"]
    dimension_counts = {
        name: sum(1 for t in valid_tests if t["dimensions"].get(name, {}).get("result") == "DETECTED")
        for name in DIMENSIONS
    }
    # Через какой разрез прошли именно успешные атаки — это и есть «где сломалось».
    breach_counts = {name: sum(1 for t in successful if name in t["breach"]) for name in DIMENSIONS}
    return {
        "run_id": state.get("run_id", run_dir.name),
        "created_at": state.get("created_at", ""),
        "target": state.get("target", {}),
        "tests": tests,
        "counts": counts,
        "asr": asr(counts),
        "llamator": llamator_summary([{"dimensions": t["dimensions"]} for t in tests]),
        "dimension_counts": dimension_counts,
        "breach_counts": breach_counts,
        "success_count": len(successful),
        "valid_test_count": len(valid_tests),
    }


def _evaluation_paths(run_dir: Path) -> list[Path]:
    evaluations_dir = run_dir / "evaluations"
    return sorted(evaluations_dir.glob("*.json")) if evaluations_dir.exists() else []


def _load_test(run_dir: Path, state: dict[str, Any], path: Path) -> dict[str, Any] | None:
    try:
        evaluation = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    # Exploratory runs predating the current schema have no test_id — fall back to the file name
    # so the dashboard shows exactly the same records the report counts.
    test_id = evaluation.get("test_id") or evaluation.get("attack_id") or path.stem
    if not isinstance(test_id, str):
        return None
    return {
        "test_id": test_id,
        "verdict": verdict_of(evaluation),
        "breach": breach_of(evaluation),
        "effect": evaluation.get("effect"),
        "dimensions": evaluation.get("dimensions", {}),
        "judge": evaluation.get("judge"),
        "diff": _load_diff(run_dir, test_id),
        "steps": _steps_for_test(state, test_id),
    }


def _load_diff(run_dir: Path, test_id: str) -> dict[str, Any] | None:
    path = run_dir / "state_diffs" / f"{test_id}.before--{test_id}.after.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text()).get("diff")
    except json.JSONDecodeError:
        return None


def _steps_for_test(state: dict[str, Any], test_id: str) -> list[dict[str, Any]]:
    prefix = f"{test_id}."
    fields = ("operation", "user_id", "session_id", "status", "started_at", "completed_at", "error")
    steps = [
        {"step_id": step_id, **{field: step[field] for field in fields if field in step}}
        for step_id, step in state.get("steps", {}).items()
        if step_id.startswith(prefix)
    ]
    steps.sort(key=lambda step: step.get("started_at", ""))
    return steps


_TEMPLATE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Attack On Agent — Dashboard</title>
<style>
  :root {
    color-scheme: light;
    --bg: #fbf7f7; --panel: #ffffff; --border: #ecd9dc; --text: #1a1214; --muted: #7c6a6d;
    /* Красный — это сработавшая атака. Устоявший агент нейтрально-серый, чтобы взгляд цеплялся
       только за то, что сломалось. */
    --success: #c1121f; --fail: #4a4248; --inconclusive: #b07d00; --error: #9b9199;
    --accent: #c1121f; --tint: #fdeef0; --track: #f4e6e8;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
  header { padding: 16px 24px; border-bottom: 1px solid var(--border); background: var(--panel); }
  header h1 { margin: 0; font-size: 18px; }
  header p { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
  .layout { display: flex; height: calc(100vh - 61px); }
  nav { width: 300px; overflow-y: auto; border-right: 1px solid var(--border); background: var(--panel); }
  nav .run { padding: 12px 16px; border-bottom: 1px solid var(--border); cursor: pointer; }
  nav .run:hover { background: var(--tint); }
  nav .run.active { background: var(--tint); border-left: 3px solid var(--accent); }
  nav .run .id { font-weight: 600; font-size: 13px; word-break: break-all; }
  nav .run .meta { font-size: 12px; color: var(--muted); margin-top: 2px; }
  main { flex: 1; overflow-y: auto; padding: 24px; }
  .cards { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 18px; min-width: 110px; }
  .card .n { font-size: 22px; font-weight: 700; }
  .card .l { font-size: 12px; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: var(--tint); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; color: #fff; }
  .badge.SUCCESS { background: var(--success); }
  .badge.FAIL { background: var(--fail); }
  .badge.INCONCLUSIVE { background: var(--inconclusive); }
  .badge.ERROR, .badge.unknown { background: var(--error); }
  .chip { display: inline-block; padding: 1px 7px; margin: 0 4px 2px 0; border-radius: 8px; font-size: 11px; border: 1px solid var(--border); }
  .chip.DETECTED { background: var(--tint); border-color: #f0b8bd; }
  .chip.NOT_DETECTED { background: #f5f3f4; border-color: #e2dcde; }
  .chip.INCONCLUSIVE { background: #fdf6e6; border-color: #f0dca0; }
  .detail { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-top: -1px; }
  .detail h3 { margin: 16px 0 8px; font-size: 13px; text-transform: uppercase; color: var(--muted); }
  .detail h3:first-child { margin-top: 0; }
  .detail pre { background: #fbf7f8; border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow-x: auto; font-size: 12px; max-height: 320px; }
  .steps { font-size: 12px; }
  .steps li { margin-bottom: 4px; }
  .empty { color: var(--muted); padding: 40px; text-align: center; }
  .reason { font-size: 13px; line-height: 1.5; }
  .charts { display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
  .chart-box { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; flex: 1; min-width: 260px; }
  .chart-box h4 { margin: 0 0 10px; font-size: 12px; text-transform: uppercase; color: var(--muted); font-weight: 600; }
  .bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: 12px; }
  .bar-row .label { width: 90px; flex-shrink: 0; color: var(--text); }
  .bar-row .track { flex: 1; background: var(--track); border-radius: 4px; height: 8px; overflow: hidden; }
  .bar-row .fill { height: 100%; background: var(--accent); border-radius: 4px; }
  .bar-row .value { width: 60px; flex-shrink: 0; text-align: right; color: var(--muted); }
  .breach { font-size: 11px; color: var(--success); font-weight: 600; margin-top: 3px; }
  .caveat { font-size: 12px; color: var(--muted); background: #fdf6e6; border: 1px solid #f0dca0; border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; }
</style>
</head>
<body>
<header>
  <h1>Attack On Agent — Dashboard</h1>
  <p id="subtitle"></p>
</header>
<div class="layout">
  <nav id="runs"></nav>
  <main id="main"><div class="empty">Выберите прогон слева</div></main>
</div>
<script>
const DATA = __DATA__;

function fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString('ru-RU'); } catch (e) { return iso; }
}

function pct(asr) { return asr === null || asr === undefined ? '—' : Math.round(asr * 100) + '%'; }

function renderRunList() {
  const nav = document.getElementById('runs');
  document.getElementById('subtitle').textContent = DATA.length + ' прогонов · сгенерировано ' + fmtDate(new Date().toISOString());
  if (!DATA.length) {
    nav.innerHTML = '<div class="empty">Нет прогонов в runs/</div>';
    return;
  }
  nav.innerHTML = DATA.map((run, i) => `
    <div class="run" data-i="${i}">
      <div class="id">${run.run_id}</div>
      <div class="meta">${fmtDate(run.created_at)} · ${run.tests.length} тестов · наш ASR ${pct(run.asr)}${run.llamator ? ' · LLAMATOR ASR ' + pct(run.llamator.ASR) : ''}</div>
      <div class="meta">S:${run.counts.SUCCESS} F:${run.counts.FAIL} I:${run.counts.INCONCLUSIVE} E:${run.counts.ERROR}</div>
    </div>
  `).join('');
  nav.querySelectorAll('.run').forEach(el => el.addEventListener('click', () => selectRun(parseInt(el.dataset.i))));
  if (DATA.length) selectRun(0);
}

function selectRun(i) {
  document.querySelectorAll('nav .run').forEach(el => el.classList.toggle('active', parseInt(el.dataset.i) === i));
  const run = DATA[i];
  const main = document.getElementById('main');
  if (!run.tests.length) {
    main.innerHTML = '<div class="empty">В этом прогоне нет завершённых оценок</div>';
    return;
  }
  const llamatorCard = run.llamator
    ? `<div class="card"><div class="n">${pct(run.llamator.ASR)}</div><div class="l">ASR по LLAMATOR (только ответ)</div></div>`
    : '';
  main.innerHTML = `
    <div class="cards">
      <div class="card"><div class="n">${pct(run.asr)}</div><div class="l">ASR (наш оценщик)</div></div>
      ${llamatorCard}
      <div class="card"><div class="n">${run.counts.SUCCESS}</div><div class="l">SUCCESS</div></div>
      <div class="card"><div class="n">${run.counts.FAIL}</div><div class="l">FAIL</div></div>
      <div class="card"><div class="n">${run.counts.INCONCLUSIVE}</div><div class="l">INCONCLUSIVE</div></div>
      <div class="card"><div class="n">${run.counts.ERROR}</div><div class="l">ERROR</div></div>
    </div>
    <div class="charts">
      ${breachChart(run)}
      ${dimensionChart(run)}
      ${verdictChart(run)}
    </div>
    <table id="test-table">
      <thead><tr><th>Тест</th><th>Verdict</th><th>Измерения</th></tr></thead>
      <tbody>${run.tests.map((t, j) => renderRow(t, j)).join('')}</tbody>
    </table>
    <div id="detail"></div>
  `;
  run.tests.forEach((t, j) => {
    document.getElementById('row-' + j).addEventListener('click', () => renderDetail(t));
  });
}

function verdictClass(v) { return DATA_VERDICTS.has(v) ? v : 'unknown'; }
const DATA_VERDICTS = new Set(['SUCCESS', 'FAIL', 'INCONCLUSIVE']);

function barRow(label, count, total) {
  const width = total ? Math.round((count / total) * 100) : 0;
  return `<div class="bar-row"><div class="label">${label}</div><div class="track"><div class="fill" style="width:${width}%"></div></div><div class="value">${count} / ${total}</div></div>`;
}

function breachChart(run) {
  const labels = {output:'финальный ответ', memory:'память', tool:'инструменты', cross_session:'другая сессия'};
  if (!run.success_count) return `<div class="chart-box"><h4>Где сломалось</h4><div class="empty">Успешных атак нет</div></div>`;
  const rows = Object.entries(run.breach_counts || {}).map(([n,c]) => barRow(labels[n]||n, c, run.success_count)).join('');
  return `<div class="chart-box"><h4>Где сломалось (из ${run.success_count} успешных атак)</h4>${rows}</div>`;
}

function dimensionChart(run) {
  const rows = Object.entries(run.dimension_counts || {}).map(([name, count]) => barRow(name, count, run.valid_test_count)).join('');
  return `<div class="chart-box"><h4>Сигнал по разрезам (все валидные тесты)</h4>${rows || '<div class="empty">Нет данных</div>'}</div>`;
}

function verdictChart(run) {
  const total = run.tests.length;
  const rows = ['SUCCESS', 'FAIL', 'INCONCLUSIVE', 'ERROR'].map(name => barRow(name, run.counts[name], total)).join('');
  return `<div class="chart-box"><h4>Verdict по всем тестам прогона</h4>${rows}</div>`;
}

function renderRow(t, j) {
  const labels = {output:'финальный ответ', memory:'память', tool:'инструменты', cross_session:'другая сессия'};
  const dims = Object.entries(t.dimensions || {})
    .map(([name, d]) => `<span class="chip ${d.result || 'INCONCLUSIVE'}">${name}: ${d.result || '?'}</span>`).join('');
  const breach = t.verdict === 'SUCCESS'
    ? `<div class="breach">сломалось: ${(t.breach || []).map(n => labels[n] || n).join(', ') || 'по трассе'}</div>` : '';
  return `<tr id="row-${j}"><td>${t.test_id}${breach}</td><td><span class="badge ${verdictClass(t.verdict)}">${t.verdict}</span></td><td>${dims}</td></tr>`;
}

function renderDetail(t) {
  const judgeBlock = t.judge
    ? `<h3>Вердикт judge</h3><div class="reason"><span class="badge ${verdictClass(t.judge.result)}">${t.judge.result}</span> ${t.judge.reason || ''}</div>`
    : '';
  const stepsBlock = t.steps && t.steps.length
    ? `<h3>Шаги выполнения</h3><ul class="steps">${t.steps.map(s => `<li><b>${s.step_id}</b> — ${s.status}${s.operation ? ' (' + s.operation + ')' : ''}${s.error ? ' — ' + s.error : ''}</li>`).join('')}</ul>`
    : '';
  document.getElementById('detail').innerHTML = `
    <div class="detail">
      <h3>${t.test_id}</h3>
      ${judgeBlock}
      <h3>Измерения (raw evidence)</h3>
      <pre>${escapeHtml(JSON.stringify(t.dimensions, null, 2))}</pre>
      ${t.diff ? `<h3>State diff (memory/state до → после)</h3>
        <div class="caveat">⚠ removed/changed могут относиться к другому тесту, если несколько тестов в кампании используют одного и того же пользователя — снапшот хранит только последние N записей. Judge это исключает из своих данных, здесь показан необработанный diff целиком.</div>
        <pre>${escapeHtml(JSON.stringify(t.diff, null, 2))}</pre>` : ''}
      ${stepsBlock}
    </div>
  `;
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c]));
}

renderRunList();
</script>
</body>
</html>
"""
