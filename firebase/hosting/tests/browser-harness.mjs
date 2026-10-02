// Local-only QA: production source + simulated Google identity + real Firestore emulator.
// Never emitted by scripts/build.mjs or deployed. No production writes or credentials.
import { build } from 'esbuild';
import { readFile, writeFile, mkdtemp, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
import { initializeTestEnvironment } from '@firebase/rules-unit-testing';
import { doc, getDocFromServer, setDoc } from 'firebase/firestore';

export async function startHarness() {
  const repo = resolve(new URL('../../../', import.meta.url).pathname);
  const source = join(repo, 'firebase/hosting/src');
  const out = await mkdtemp(join(tmpdir(), 'cct-dashboard-qa-'));
  await mkdir(join(out, 'assets'));
  const ownerUid = 'replace-with-owner-firebase-uid';
  const email = 'owner@example.invalid';
  const projectId = 'demo-cctae-browser';
  const claims = { sub: ownerUid, user_id: ownerUid, email, email_verified: true, firebase: { sign_in_provider: 'google.com', identities: { email: [email] } } };
  const env = await initializeTestEnvironment({ projectId, firestore: { host: '127.0.0.1', port: 8080, rules: await readFile(join(repo, 'firestore.rules'), 'utf8') } });
  await env.clearFirestore();
  const authStub = `
    const email = ${JSON.stringify(email)}, uid = ${JSON.stringify(ownerUid)};
    const user = { email, uid, emailVerified:true, providerData:[{providerId:'google.com'}],
      getIdTokenResult:async()=>({claims:{email,email_verified:true},signInProvider:'google.com',token:'local-fixture-only'}),
      getIdToken:async()=> 'local-fixture-only' };
    const auth={currentUser:user}; let observer;
    export class GoogleAuthProvider { setCustomParameters(){} }
    export const browserLocalPersistence={};
    export const getAuth=()=>auth;
    export const setPersistence=async()=>{};
    export const onAuthStateChanged=(a,cb)=>{observer=cb;queueMicrotask(()=>cb(a.currentUser));return()=>{}};
    export const signInWithPopup=async()=>{auth.currentUser=user;await observer(user);return{user}};
    export const signOut=async()=>{auth.currentUser=null;await observer(null)};
  `;
  let app = await readFile(join(source, 'app.js'), 'utf8');
  if (!app.includes('const db = getFirestore(firebaseApp);')) throw Error('QA injection anchor changed');
  app = `import {connectFirestoreEmulator as qaConnect} from 'firebase/firestore';\n${app}`
    .replace('const db = getFirestore(firebaseApp);', `const db = getFirestore(firebaseApp); qaConnect(db,'127.0.0.1',8080,{mockUserToken:${JSON.stringify(claims)}});`);
  await build({ stdin: { contents: app, resolveDir: source, sourcefile: 'app.js' }, bundle:true,
    format:'esm', platform:'browser', target:'es2022', outdir:join(out,'assets'), entryNames:'qa-app',
    plugins:[{name:'local-fixtures-only', setup(b) {
      b.onResolve({filter:/^firebase\/auth$/},()=>({path:'auth',namespace:'qa'}));
      b.onLoad({filter:/.*/,namespace:'qa'},()=>({contents:authStub,loader:'js'}));
      b.onLoad({filter:/firebase-config\.js$/},()=>({contents:`export const firebaseConfig={apiKey:'demo-key',projectId:'${projectId}',appId:'demo-app',authDomain:'localhost'}; export const ownerPolicy={pinnedUid:'${ownerUid}',provider:'google.com'};`,loader:'js'}));
    }}] });
  let html = await readFile(join(repo,'firebase/hosting/index.template.html'),'utf8');
  html = html.replace('__APP_SCRIPT__','/assets/qa-app.js').replace('__APP_STYLES__','/assets/qa-app.css');
  await writeFile(join(out,'index.html'),html);
  const server = createServer(async(req,res)=>{
    try {
      const pathname = new URL(req.url,'http://localhost').pathname;
      const file = pathname === '/' ? '/index.html' : pathname;
      const target = resolve(out, '.'+file);
      if (!target.startsWith(out+'/')) {res.writeHead(403);res.end();return;}
      const body=await readFile(target);
      res.writeHead(200,{'content-type':target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':'text/html','cache-control':'no-store'});res.end(body);
    } catch {res.writeHead(404);res.end('not found');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return { out, url:`http://127.0.0.1:${server.address().port}`, env,
    async seedSnapshot(snapshot) { return env.withSecurityRulesDisabled(c => setDoc(doc(c.firestore(), 'cct_dashboard', 'current'), {
      schemaVersion: 'cct.firebase_dashboard.v1', ownerUid, ownerEmail: email, snapshot,
    })); },
    async seedOwnerDocument(collection, name, value) {
      return env.withSecurityRulesDisabled(c => setDoc(doc(c.firestore(), collection, name), value));
    },
    async readOwnerDocument(collection, name) {
      let value;
      await env.withSecurityRulesDisabled(async c => {
        value = (await getDocFromServer(doc(c.firestore(), collection, name))).data();
      });
      return value;
    },
    async workspace() {
      // withSecurityRulesDisabled returns void, not the callback result.
      let value;
      await env.withSecurityRulesDisabled(async c => {
        value = (await getDocFromServer(doc(c.firestore(), 'cct_workspace', 'current'))).data();
      });
      return value;
    },
    async close(){await new Promise(resolve=>server.close(resolve));await env.cleanup();} };
}
