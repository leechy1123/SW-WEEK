/* 읽는 순서: init → runScan → renderResult → renderFindings.
   서버에서 온 텍스트는 escapeHtml 또는 textContent로 표시합니다. */
const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stateLabels = {vulnerable: '취약점 발견', pass: '검사 통과', unknown: '미확인'};
let config;
let result = null;
let currentFilter = 'all';
let busy = false;
const badge = (state) => `<span class="badge ${escapeHtml(state)}">${escapeHtml(stateLabels[state] || '미확인')}</span>`;
const categoryClass = (id) => id === 'A02' ? 'blue' : id === 'A05' ? 'purple' : '';

function changePage(page) {
  const names = {dashboard: '진단 대시보드', learn: '취약점 이해하기', guide: '처음 시작하기'};
  if (!names[page]) return;
  document.querySelectorAll('.page').forEach((item) => item.hidden = item.id !== `page-${page}`);
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.dataset.page === page);
    if (item.dataset.page === page) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  $('#breadcrumb').textContent = names[page];
  window.scrollTo({top: 0, behavior: 'auto'});
}
document.addEventListener('click', (event) => {
  const link = event.target.closest('[data-page]');
  if (link) changePage(link.dataset.page);
});

function selectVersion(version) {
  if (!config) return;
  $('#target-url').value = `${config.base}/lab/${version}`;
  $('#open-lab').href = `/lab/${version}`;
  for (const id of ['vulnerable', 'fixed']) {
    $(`#select-${id}`).classList.toggle('selected', version === id);
    $(`#select-${id}`).setAttribute('aria-pressed', String(version === id));
  }
}

function message(text, error = false) {
  const element = $('#status-message');
  element.hidden = !text;
  element.className = error ? 'error' : '';
  element.textContent = text;
}

function codeComparison(lesson) {
  return `<div class="code-grid"><div><h4>수정 전 · 무엇이 빠졌을까요?</h4><pre>${escapeHtml(lesson.before)}</pre></div><div><h4>수정 후 · 이렇게 바꿔요</h4><pre>${escapeHtml(lesson.after)}</pre></div></div>`;
}

function renderLessons() {
  $('#lesson-cards').innerHTML = config.lessons.map((lesson) => `<button class="lesson-card" data-lesson="${lesson.id}"><span class="category ${categoryClass(lesson.id)}">${lesson.id}:2025</span><h3>${escapeHtml(lesson.title)}</h3><p>${escapeHtml(lesson.analogy)}</p><span class="card-link">원리 알아보기 →</span></button>`).join('');
  $('#lessons-full').innerHTML = config.lessons.map((lesson) => `<article class="panel full-lesson" id="lesson-${lesson.id}"><span class="category ${categoryClass(lesson.id)}">${lesson.id}:2025</span><h2>${escapeHtml(lesson.title)}</h2><span class="english">${escapeHtml(lesson.english)}</span><p class="analogy">${escapeHtml(lesson.analogy)}</p><p>${escapeHtml(lesson.description)}</p><div class="fix-box"><h3>어떻게 수정하나요?</h3><p>${escapeHtml(lesson.fix)}</p></div>${codeComparison(lesson)}<div class="lesson-task"><b>직접 해보기</b><br>${escapeHtml(lesson.task)}</div><div class="lesson-links"><a class="button small" href="/lab/vulnerable#${lesson.id}" target="_blank" rel="noopener">실습 열기 ↗</a><a href="${escapeHtml(lesson.source)}" target="_blank" rel="noopener">OWASP 공식 설명 ↗</a></div><p class="code-task">코드 위치: ${escapeHtml(lesson.file)} · ${escapeHtml(lesson.flag)}를 True로 바꾸면 수정 전 버전에도 해결책이 적용됩니다.</p></article>`).join('');
  document.querySelectorAll('[data-lesson]').forEach((button) => button.addEventListener('click', () => {
    changePage('learn');
    $(`#lesson-${button.dataset.lesson}`).scrollIntoView({block: 'start'});
  }));
}

function clearResult() {
  result = null;
  $('#download-button').disabled = true;
  $('#comparison').hidden = true;
  $('#result-filters').hidden = true;
  for (const id of ['vuln', 'pass', 'unknown']) $(`#${id}-count`).innerHTML = '—<small>건</small>';
  $('#result-meta').textContent = '새 진단이 완료되면 결과를 표시합니다.';
  $('#findings').innerHTML = '<div class="empty-state"><span class="loading-mark"></span>실제 요청을 보내 응답을 확인하고 있습니다.</div>';
}

async function runScan(compare) {
  if (busy || !config) return;
  if (!$('#authorized').checked) { message('직접 실행한 교육용 실습 환경 확인란에 체크해 주세요.', true); $('#authorized').focus(); return; }
  if (!$('#target-url').value.trim()) { message('실습 사이트 URL을 입력해 주세요.', true); $('#target-url').focus(); return; }
  busy = true;
  clearResult();
  $('#scan-button').disabled = true;
  $('#compare-button').disabled = true;
  message(compare ? '수정 전·후 버전에 동일한 요청을 보내고 있습니다…' : '실습 사이트의 응답을 확인하고 있습니다…');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:$('#target-url').value, authorized:true, compare}), signal:controller.signal});
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || '진단을 완료하지 못했습니다.');
    result = data;
    currentFilter = 'all';
    renderResult();
    message(`진단이 완료되었습니다. 실제 HTTP 요청 ${data.request_count}회의 응답을 확인했습니다.`);
  } catch (error) {
    message(error.name === 'AbortError' ? '응답 시간이 초과되었습니다. 서버 상태를 확인한 뒤 다시 시도해 주세요.' : error.message, true);
    $('#result-meta').textContent = '진단 실패 · 안전 여부를 판단하지 않았습니다.';
    $('#findings').innerHTML = '<div class="empty-state"><h3>진단을 완료하지 못했어요</h3><p>위 오류 안내를 확인하고 실습 URL로 다시 시도해 주세요.</p></div>';
  } finally {
    clearTimeout(timeout);
    busy = false;
    $('#scan-button').disabled = false;
    $('#compare-button').disabled = false;
  }
}

function visibleReport() { return result.kind === 'compare' ? result.after : result; }

function renderResult() {
  const report = visibleReport();
  const counts = {vulnerable:0, pass:0, unknown:0};
  report.checks.forEach((check) => counts[check.state]++);
  $('#vuln-count').innerHTML = `${counts.vulnerable}<small>건</small>`;
  $('#pass-count').innerHTML = `${counts.pass}<small>건</small>`;
  $('#unknown-count').innerHTML = `${counts.unknown}<small>건</small>`;
  const time = new Date(result.time).toLocaleString('ko-KR', {timeZone:'Asia/Seoul', hour12:false});
  $('#result-meta').textContent = `${result.kind === 'compare' ? '위 수치와 아래 상세 결과는 수정 후 기준 · ' : ''}${report.version === 'fixed' ? '수정 후' : '수정 전'} · ${report.url} · ${time} KST`;
  $('#comparison').hidden = result.kind !== 'compare';
  if (result.kind === 'compare') {
    $('#comparison').innerHTML = `<div class="comparison-box"><h3>같은 요청, 달라진 결과</h3><table><thead><tr><th>검사 항목</th><th>수정 전</th><th>수정 후</th><th>수정 후 정상 기능</th></tr></thead><tbody>${result.before.checks.map((before, i) => `<tr><td><b>${before.id}</b> ${escapeHtml(before.title)}</td><td>${badge(before.state)}</td><td>${badge(result.after.checks[i].state)}</td><td>${result.after.checks[i].normal_ok ? '✓ 유지됨' : '추가 확인 필요'}</td></tr>`).join('')}</tbody></table><p class="compare-note">두 버전에 각각 8회씩 요청했습니다. 아래 항목을 펼치면 수정 전·후의 실제 응답을 함께 볼 수 있습니다.</p></div>`;
  }
  $('#result-filters').hidden = false;
  $('#download-button').disabled = false;
  renderFindings();
}

function evidenceMarkup(cases) {
  return cases.map((item) => `<div class="evidence-item"><div class="evidence-head"><b>${escapeHtml(item.label)}</b><span>HTTP ${item.status}</span></div><div class="evidence-path">GET ${escapeHtml(item.path)}</div><pre>${escapeHtml(JSON.stringify(item.body, null, 2))}</pre></div>`).join('');
}

function renderFindings() {
  document.querySelectorAll('[data-filter]').forEach((button) => {
    button.classList.toggle('active', button.dataset.filter === currentFilter);
    button.setAttribute('aria-pressed', String(button.dataset.filter === currentFilter));
  });
  const checks = visibleReport().checks.filter((check) => currentFilter === 'all' || check.state === currentFilter);
  $('#findings').innerHTML = checks.length ? checks.map((check) => {
    const before = result.kind === 'compare' ? result.before.checks.find((item) => item.id === check.id) : null;
    return `<details class="finding"><summary><span class="category ${categoryClass(check.id)}">${check.id}</span><strong>${escapeHtml(check.title)}</strong>${badge(check.state)}</summary><div class="finding-inside"><p>${escapeHtml(check.reason)}</p><div class="location">발견 위치: ${escapeHtml(check.location)}<br>코드 위치: ${escapeHtml(check.file)}</div><p>${escapeHtml(check.description)}</p><div class="evidence-title">${before ? '수정 후 · ' : ''}확인한 실제 응답</div><div class="evidence-list">${evidenceMarkup(check.evidence)}</div>${before ? `<div class="evidence-title">수정 전 · ${escapeHtml(before.reason)}</div><div class="evidence-list">${evidenceMarkup(before.evidence)}</div>` : ''}<div class="fix-box"><h3>어떻게 수정하나요?</h3><p>${escapeHtml(check.fix)}</p></div>${codeComparison(check)}<div class="result-footer"><span>정상 기능: ${check.normal_ok ? '유지 확인' : '추가 확인 필요'}</span><a href="${escapeHtml(check.source)}" target="_blank" rel="noopener">OWASP 공식 설명 ↗</a></div></div></details>`;
  }).join('') : '<div class="empty-state"><h3>선택한 상태의 항목이 없습니다.</h3><p>전체 결과에서 나머지 항목을 확인하세요.</p></div>';
}

$('#scan-form').addEventListener('submit', (event) => { event.preventDefault(); runScan(false); });
$('#compare-button').addEventListener('click', () => runScan(true));
$('#select-vulnerable').addEventListener('click', () => selectVersion('vulnerable'));
$('#select-fixed').addEventListener('click', () => selectVersion('fixed'));
$('#target-url').addEventListener('input', () => {
  for (const id of ['vulnerable','fixed']) {
    const selected = config && $('#target-url').value === `${config.base}/lab/${id}`;
    $(`#select-${id}`).classList.toggle('selected', Boolean(selected));
    $(`#select-${id}`).setAttribute('aria-pressed', String(Boolean(selected)));
  }
});
document.querySelectorAll('[data-filter]').forEach((button) => button.addEventListener('click', () => { currentFilter = button.dataset.filter; if (result) renderFindings(); }));
$('#download-button').addEventListener('click', () => {
  if (!result) return;
  const data = {project:'SW WEEK Security Lab', owasp:'2025', scope:'로컬 실습 대표 사례 3종. 전체 안전성 보장 아님.', ...result};
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'}));
  const link = document.createElement('a'); link.href = url; link.download = 'sw-week-result.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});

async function init() {
  $('#scan-button').disabled = true;
  $('#compare-button').disabled = true;
  try {
    const response = await fetch('/api/config');
    if (!response.ok) throw new Error('설정을 불러오지 못했습니다.');
    config = await response.json();
    selectVersion('vulnerable');
    renderLessons();
    changePage('dashboard');
    $('#scan-button').disabled = false;
    $('#compare-button').disabled = false;
  } catch (error) { message('서버에 연결하지 못했습니다. python app.py 실행 후 페이지를 새로고침해 주세요.', true); }
}
init();
