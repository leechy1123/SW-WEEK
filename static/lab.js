// 이 화면은 브라우저에서 직접 실습 API를 호출하고 실제 응답을 보여줍니다.
const version = location.pathname.split('/')[2];
const prefix = `/lab/${version}`;
const $ = (selector) => document.querySelector(selector);
$('#version-label').textContent = version === 'fixed' ? '수정 후' : '수정 전';
$('#switch-version').href = `/lab/${version === 'fixed' ? 'vulnerable' : 'fixed'}`;
$('#switch-version').textContent = version === 'fixed' ? '수정 전으로 전환 ⇄' : '수정 후로 전환 ⇄';

async function showResult(path, target, session = '') {
  const area = $(target);
  area.textContent = '응답을 기다리는 중…';
  const headers = session ? {'X-Lab-Session':session} : {};
  try {
    const response = await fetch(`${prefix}/${path}`, {headers});
    const data = await response.json();
    const heading = document.createElement('h3');
    heading.textContent = `HTTP ${response.status} · ${decodeURIComponent(path)}`;
    const content = document.createElement('pre');
    content.textContent = JSON.stringify(data, null, 2);
    area.replaceChildren(heading, content);
  } catch (error) { area.textContent = '서버에 연결할 수 없습니다. 서버를 실행하고 다시 눌러주세요.'; }
}
document.querySelectorAll('[data-post]').forEach((button) => button.addEventListener('click', () => showResult(`posts?id=${button.dataset.post}`, '#post-result', $('#session').value)));
$('#session').addEventListener('change', () => { $('#post-result').textContent = '사용자를 변경했습니다. 글 보기 버튼을 다시 눌러주세요.'; });
$('#normal-error').addEventListener('click', () => showResult('error', '#error-result'));
$('#trigger-error').addEventListener('click', () => showResult('error?trigger=1', '#error-result'));
function search(keyword) { $('#keyword').value = keyword; showResult(`search?${new URLSearchParams({q:keyword})}`, '#search-result'); }
$('#search-form').addEventListener('submit', (event) => { event.preventDefault(); search($('#keyword').value); });
$('#normal-search').addEventListener('click', () => search('노트'));
$('#true-search').addEventListener('click', () => search("' OR 1=1 -- "));
$('#false-search').addEventListener('click', () => search("' OR 1=2 -- "));
