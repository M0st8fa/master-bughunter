# Proven form-driving patterns (battle-tested patterns, use as-is)

## 1. Playwright fill is the default (values survive re-renders)
```js
await tab.playwright.locator('#field-id').fill('value');
await tab.playwright.locator('select[name=citizenship]').selectOption('AU');
```
Real input events → React state updates → values survive re-renders.
If locator click times out ("covered by ..."), use force: true, or scroll first:
```js
await tab.playwright.evaluate("document.getElementById('x').scrollIntoView({block:'center'})");
```

## 2. Native-setter fallback (evaporates on remount — re-verify after waits)
```js
(function(){
  var el=document.getElementById('field');
  var p=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
  el.focus(); p.set.call(el,'value');
  el.dispatchEvent(new Event('input',{bubbles:true}));
  el.dispatchEvent(new Event('change',{bubbles:true}));
  el.blur();
})()
```
For SELECTs use HTMLSelectElement.prototype. Verify values persisted after every
wait; if a re-render wiped them, switch to one-evaluate multi-fill + submit.

## 3. One-evaluate multi-fill + submit (for remount-churning pages)
```js
(async function(){
  var sleep=function(ms){return new Promise(function(r){setTimeout(r,ms);});};
  var set=function(el,v){/* native setter + events, see #2 */};
  set(f1,'v1'); set(f2,'v2'); await sleep(500);
  var b=[...document.querySelectorAll('button')].find(function(b){return b.textContent.trim()==='Submit';});
  b.click(); return 'submitted';
})()
```

## 4. Headless-UI / react-select dropdown ladder (in order)
1. Click the VISIBLE display element — the placeholder div (`[class*=placeholder]`)
   or `.select__control` wrapper — NEVER the hidden combobox input (it is
   z-index-occluded; elementFromPoint proves it).
2. Real CUA keyboard: cua.click input coords → cua.type "filter" → cua
   ArrowDown → cua Enter. Real keys register where synthetic events don't.
3. Tab-walk: focus the previous field via Playwright, then cua keypress Tab —
   real focus lands on the combobox.
4. Beware: answering a survey with "Something else" often spawns a mandatory
   follow-up combobox — pick a SPECIFIC option when available.

## 5. DataTransfer file injection (upload walls, no file chooser)
```js
// minimal valid PDF as JS bytes
var pdf='%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n4 0 obj<</Length 0>>stream\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF';
var bytes=new Uint8Array(pdf.length);
for(var i=0;i<pdf.length;i++)bytes[i]=pdf.charCodeAt(i);
var file=new File([bytes],'resume.pdf',{type:'application/pdf'});
var fi=document.querySelector('input[type=file]');
var dt=new DataTransfer(); dt.items.add(file); fi.files=dt.files;
fi.dispatchEvent(new Event('input',{bubbles:true}));
fi.dispatchEvent(new Event('change',{bubbles:true}));
```
Re-inject after any remount (React clears file inputs on re-render).
Escape notes: in evaluate heredocs write \n carefully — prefer building the
string in a .py/.js file over heredoc when escapes mangle.

## 6. Knockout wizard forms (NEOGOV-style)
- Fields clear on re-render: fill, wait, verify, THEN click submit.
- "Saving..." indicator = autosave fired; capture app IDs via XHR hook:
```js
(function(){window.__cap=[];var ox=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){var s=this;
this.addEventListener('load',function(){try{window.__cap.push({m:m,u:String(u).slice(0,140),s:s.status,r:(s.responseText||'').slice(0,150)});}catch(e){}});return ox.apply(this,arguments);};})()
```
- Application objects are usually keyed (session, jobId) — no separate ID in URLs.

## 7. Verification-email parsing (agent-email --full)
```python
import json, re, html as H
d=json.load(open('mail.json',encoding='utf-8'))
mm=d['data']['messages'][0]
raw=mm.get('html')
if isinstance(raw,list): raw=''.join(str(x) for x in raw)
txt=H.unescape(raw).replace(chr(92)+'/', '/')
links=re.findall(r'https://app\.target\.com/verify\?token=[^\s"\'<>]+', txt)   # FULL match
codes=re.findall(r'\b([A-Z0-9]{5,8})\b', re.sub(r'<[^>]+>',' ',txt))
```
- Tracking-wrapped links: pick by anchor text:
```python
re.findall(r'<a[^>]+href="(https://tracking[^"]+)"[^>]*>\s*Accept invitation', html, re.S)
```
- "link invalid or expired" after opening ⇒ token was truncated — re-extract.

## 8. Session capture from user's "Copy as cURL"
Parse the `-b "..."` cookie string; the auth cookie is usually the long
ASP.NET-style value (`gearset2=CfDJ8...`). Remember: cookies are per-environment
(app.gearset.com session ≠ staging.gearset.com session) and per-domain.
Helper: `scripts/parse_curl_cookies.py "<paste>"` → prints cookie header.

## 9. reCAPTCHA gate detection (hand off instead of retrying)
Signatures: recaptcha iframe loads + all fields valid + submit silently
aborts (no navigation, no error). One reload fixes the transient
"Could not connect to the reCAPTCHA service" case; anything else = the
automation context can't obtain a token → ask the user to complete that
single step in their own browser, then continue.
