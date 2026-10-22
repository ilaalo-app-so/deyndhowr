const C='deyndhowr-v6',F=['./','./index.html','./config.js','./manifest.json','./icon-192.png','./icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)).catch(()=>{}));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.hostname.endsWith('supabase.co')||u.pathname.includes('/auth/')||u.pathname.includes('/rest/'))return;
e.respondWith(fetch(e.request).then(r=>{if(r&&(r.ok||r.type==='opaque')){const c=r.clone();caches.open(C).then(x=>x.put(e.request,c))}return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match('./index.html'))))});
