const C='deyndhowr-v9',F=['./','./index.html','./config.js','./manifest.json','./icon-192.png','./icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)).catch(()=>{}));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.hostname.endsWith('supabase.co')||u.pathname.includes('/auth/')||u.pathname.includes('/rest/'))return;
const same=u.origin===location.origin,req=same?new Request(u.origin+u.pathname+u.search,{cache:'no-cache',credentials:'same-origin'}):e.request;/* own files: always ask GitHub for the newest copy; cache only when offline */
e.respondWith(fetch(req).then(r=>{if(r&&(r.ok||r.type==='opaque')){const c=r.clone();caches.open(C).then(x=>x.put(same?req:e.request,c))}return r}).catch(()=>caches.match(same?req:e.request,{ignoreSearch:same}).then(r=>r||(e.request.mode==='navigate'?caches.match('./index.html',{ignoreSearch:true}):Response.error()))))});
