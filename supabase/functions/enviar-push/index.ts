// Función de servidor "enviar-push" (Supabase Edge Function).
// Manda a los teléfonos los avisos nuevos (los mismos que se ven en la campana de la app) usando
// Firebase Cloud Messaging. La llama la propia base de datos cada vez que se crea un aviso
// (y cada 5 minutos como red de seguridad), nunca la app.
//
// Al desplegarla hay que DESACTIVAR "Verify JWT": la llamada trae una clave propia en el
// encabezado x-push-secret, que se compara con la guardada en la base (Vault).
//
// Necesita un secreto de función: FIREBASE_SERVICE_ACCOUNT = el archivo .json de la
// "cuenta de servicio" de Firebase (ver GUIA-PUBLICAR.md). Sin él, no envía nada y los
// avisos quedan pendientes (se reintentan durante 2 horas).
import { createClient } from 'npm:@supabase/supabase-js@2';

const json = (cuerpo: unknown, status = 200) =>
  new Response(JSON.stringify(cuerpo), { status, headers: { 'Content-Type': 'application/json' } });

const clave = (nuevas: string | undefined, anterior: string | undefined): string => {
  try { const o = JSON.parse(nuevas ?? ''); return o.default ?? (Object.values(o)[0] as string); } catch { return anterior ?? ''; }
};

// ---------- credenciales de Google (cuenta de servicio) ----------
type Cuenta = { project_id: string; client_email: string; private_key: string };
function leerCuenta(): Cuenta | null {
  let t = (Deno.env.get('FIREBASE_SERVICE_ACCOUNT') ?? '').trim();
  if (!t) return null;
  try {
    if (!t.startsWith('{')) t = atob(t);                 // también se acepta el archivo codificado en base64
    const c = JSON.parse(t);
    return c.project_id && c.client_email && c.private_key ? c : null;
  } catch { return null; }
}
const b64u = (datos: ArrayBuffer | string): string => {
  const bytes = typeof datos === 'string' ? new TextEncoder().encode(datos) : new Uint8Array(datos);
  let s = ''; bytes.forEach((x) => (s += String.fromCharCode(x)));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const pemABytes = (pem: string): ArrayBuffer => {
  const bin = atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};
let cache: { token: string; vence: number } | null = null;
async function tokenGoogle(c: Cuenta): Promise<string> {
  if (cache && cache.vence > Date.now() + 60_000) return cache.token;
  const ahora = Math.floor(Date.now() / 1000);
  const cab = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const cuerpo = b64u(JSON.stringify({
    iss: c.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token', iat: ahora, exp: ahora + 3600,
  }));
  const llave = await crypto.subtle.importKey('pkcs8', pemABytes(c.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const firma = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', llave, new TextEncoder().encode(cab + '.' + cuerpo));
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: cab + '.' + cuerpo + '.' + b64u(firma) }),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j?.access_token) throw new Error('Google no aceptó la cuenta de servicio: ' + (j?.error_description ?? j?.error ?? r.status));
  cache = { token: j.access_token, vence: Date.now() + (j.expires_in ?? 3600) * 1000 };
  return cache.token;
}

// ---------- envío ----------
type Aviso = { id: string; usuario_id: string; tipo: string | null; titulo: string; cuerpo: string | null; ref_tipo: string | null; ref_id: string | null };
type Resultado = 'ok' | 'invalido' | 'reintentar';
async function enviar(proyecto: string, acceso: string, token: string, a: Aviso): Promise<Resultado> {
  let r: Response;
  try {
    r = await fetch(`https://fcm.googleapis.com/v1/projects/${proyecto}/messages:send`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + acceso, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: {
          token,
          notification: { title: (a.titulo ?? '').slice(0, 100), body: (a.cuerpo ?? '').slice(0, 240) },
          data: { aviso_id: a.id, tipo: a.tipo ?? '', ref_tipo: a.ref_tipo ?? '', ref_id: a.ref_id ?? '' },
          android: { priority: 'HIGH' },
          apns: { payload: { aps: { sound: 'default' } } },
        },
      }),
    });
  } catch { return 'reintentar'; }
  if (r.ok) return 'ok';
  const j = await r.json().catch(() => null);
  const codigo: string = j?.error?.details?.find((d: { errorCode?: string }) => d.errorCode)?.errorCode ?? j?.error?.status ?? '';
  if (r.status === 404 || codigo === 'UNREGISTERED' || codigo === 'SENDER_ID_MISMATCH' || (r.status === 400 && codigo === 'INVALID_ARGUMENT')) return 'invalido';
  console.error('FCM rechazó el envío', r.status, codigo, j?.error?.message);
  return 'reintentar';
}

const iguales = (a: string, b: string) => {          // comparación sin atajos
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') return json({ error: 'Método no permitido.' }, 405);
  try {
    const sb = createClient(Deno.env.get('SUPABASE_URL')!,
      clave(Deno.env.get('SUPABASE_SECRET_KEYS'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')),
      { auth: { persistSession: false, autoRefreshToken: false } });

    // 1) ¿Quién llama? Solo la base de datos, con la clave guardada en Vault.
    const { data: secreto } = await sb.rpc('_push_secreto');
    const recibido = req.headers.get('x-push-secret') ?? '';
    if (!secreto || !iguales(String(secreto), recibido)) return json({ error: 'No autorizado.' }, 401);

    // 2) Sin cuenta de Firebase cargada no se hace nada (los avisos quedan pendientes).
    const cuenta = leerCuenta();
    if (!cuenta) return json({ estado: 'sin_credenciales' });

    // 3) Se reclaman los avisos pendientes (cada uno se envía una sola vez).
    const { data: avisos, error: e1 } = await sb.rpc('_push_reclamar', { p_limite: 300 });
    if (e1) throw e1;
    const lista = (avisos ?? []) as Aviso[];
    if (!lista.length) return json({ estado: 'ok', avisos: 0, enviados: 0 });

    // 4) Teléfonos de las personas a avisar.
    const usuarios = [...new Set(lista.map((a) => a.usuario_id))];
    const { data: disp, error: e2 } = await sb.from('dispositivos').select('usuario_id, token').in('usuario_id', usuarios);
    if (e2) { await sb.rpc('_push_soltar', { p_ids: lista.map((a) => a.id) }); throw e2; }
    const porUsuario = new Map<string, string[]>();
    (disp ?? []).forEach((d: { usuario_id: string; token: string }) => {
      porUsuario.set(d.usuario_id, [...(porUsuario.get(d.usuario_id) ?? []), d.token]);
    });

    let acceso: string;
    try { acceso = await tokenGoogle(cuenta); }
    catch (e) { await sb.rpc('_push_soltar', { p_ids: lista.map((a) => a.id) }); throw e; }

    // 5) Envío (10 a la vez).
    const tareas: { aviso: Aviso; token: string }[] = [];
    lista.forEach((a) => (porUsuario.get(a.usuario_id) ?? []).forEach((t) => tareas.push({ aviso: a, token: t })));
    const invalidos = new Set<string>(), reintentar = new Set<string>(), conExito = new Set<string>();
    let enviados = 0;
    for (let i = 0; i < tareas.length; i += 10) {
      await Promise.all(tareas.slice(i, i + 10).map(async ({ aviso, token }) => {
        const r = await enviar(cuenta.project_id, acceso, token, aviso);
        if (r === 'ok') { enviados++; conExito.add(aviso.id); }
        else if (r === 'invalido') invalidos.add(token);
        else reintentar.add(aviso.id);
      }));
    }
    // 6) Limpieza de teléfonos que ya no existen y reintento de lo que falló por un problema pasajero.
    if (invalidos.size) await sb.from('dispositivos').delete().in('token', [...invalidos]);
    const soltar = [...reintentar].filter((id) => !conExito.has(id));
    if (soltar.length) await sb.rpc('_push_soltar', { p_ids: soltar });

    return json({ estado: 'ok', avisos: lista.length, enviados, telefonos_dados_de_baja: invalidos.size, para_reintentar: soltar.length });
  } catch (e) {
    console.error('enviar-push', e);
    return json({ error: 'No se pudieron enviar los avisos.' }, 500);
  }
});
