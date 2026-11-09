// Función de servidor "admin-clientes" (Supabase Edge Function).
// Crea clientes con usuario y contraseña, les cambia la clave y los elimina.
// Solo la puede usar el dueño, salvo dos acciones:
//   · "registrar": una persona nueva crea su propia cuenta (sin sesión, con límite por conexión).
//   · "eliminar_yo": cada cliente borra su propia cuenta.
// Verifica quién llama antes de hacer nada.
//
// Al desplegarla hay que DESACTIVAR "Verify JWT" (la verificación la hace
// esta misma función con getUser y es_dueno, más abajo).
import { createClient } from 'npm:@supabase/supabase-js@2';

// Los usuarios de la app son "usuario@DOMINIO". Nunca se envían mails a esa dirección.
const DOMINIO = Deno.env.get('DOMINIO_EMAIL') ?? 'pglogistica.app';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (cuerpo: unknown, status = 200) =>
  new Response(JSON.stringify(cuerpo), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

const sha256 = async (t: string) =>
  Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t))))
    .map((x) => x.toString(16).padStart(2, '0')).join('');

const MAX_REGISTROS_POR_HORA = 8;

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'Método no permitido.' }, 405);

  try {
    const url = Deno.env.get('SUPABASE_URL')!;
    // Claves nuevas (publishable / secret) y, si no están, las anteriores (anon / service_role).
    const clave = (nuevas: string | undefined, anterior: string | undefined): string => {
      try { const o = JSON.parse(nuevas ?? ''); return o.default ?? (Object.values(o)[0] as string); } catch { return anterior ?? ''; }
    };
    const anon = clave(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS'), Deno.env.get('SUPABASE_ANON_KEY'));
    const servicio = clave(Deno.env.get('SUPABASE_SECRET_KEYS'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));

    const b = await req.json();

    // Registro propio: no hay sesión todavía. Se limita por conexión para evitar cuentas basura.
    if (b.accion === 'registrar') {
      const admin = createClient(url, servicio, { auth: { persistSession: false, autoRefreshToken: false } });
      const ip = (req.headers.get('x-forwarded-for') ?? '').split(',')[0].trim() || 'desconocida';
      const ipHash = await sha256(`${ip}|${Deno.env.get('SALT_IP') ?? 'pg-logistica'}`);
      const hace1h = new Date(Date.now() - 3600 * 1000).toISOString();
      const { count } = await admin.from('registros_intentos').select('id', { count: 'exact', head: true })
        .eq('ip_hash', ipHash).gte('creado_en', hace1h);
      if ((count ?? 0) >= MAX_REGISTROS_POR_HORA) {
        return json({ error: 'Hubo demasiados intentos desde esta conexión. Probá de nuevo en una hora.' }, 429);
      }
      await admin.from('registros_intentos').insert({ ip_hash: ipHash });
      await admin.from('registros_intentos').delete().lt('creado_en', new Date(Date.now() - 2 * 86400 * 1000).toISOString());

      const usuario = String(b.usuario ?? '').trim().toLowerCase();
      const nombre = String(b.nombre ?? '').trim().slice(0, 120);
      const clave = String(b.password ?? '');
      const telefono = String(b.telefono ?? '').trim().slice(0, 40);
      const codigo = String(b.codigo ?? '').trim();
      if (!/^[a-z0-9._-]{3,30}$/.test(usuario)) return json({ error: 'El usuario necesita entre 3 y 30 letras o números, sin espacios ni tildes.' }, 400);
      if (nombre.length < 2) return json({ error: 'Escribí tu nombre y apellido.' }, 400);
      if (clave.length < 6 || clave.length > 72) return json({ error: 'La contraseña necesita entre 6 y 72 caracteres.' }, 400);
      if (telefono.replace(/\D/g, '').length < 8) return json({ error: 'Escribí un teléfono válido, con característica.' }, 400);

      const { data: enUso } = await admin.rpc('admin_telefono_en_uso', { p_tel: telefono });
      if (enUso === true) return json({ error: 'Ya hay una cuenta con ese teléfono. Si es tuya, ingresá con tu usuario.' }, 400);

      let referente: string | null = null;
      if (codigo) {
        const { data: val } = await admin.rpc('validar_codigo', { p_codigo: codigo, p_telefono: telefono });
        if (val?.error) return json({ error: val.error }, 400);
        if (val?.ok) {
          const cod = codigo.toUpperCase().replace(/[^A-Z0-9-]/g, '');
          const { data: ref } = await admin.from('perfiles').select('id').eq('codigo', cod).maybeSingle();
          referente = ref?.id ?? null;
        }
      }

      const { data: nuevo, error: errCrear } = await admin.auth.admin.createUser({
        email: `${usuario}@${DOMINIO}`, password: clave, email_confirm: true, user_metadata: { usuario },
      });
      if (errCrear || !nuevo?.user) {
        const ya = /already|registered|exists/i.test(errCrear?.message ?? '');
        return json({ error: ya ? 'Ese usuario ya existe. Elegí otro.' : 'No se pudo crear la cuenta. Probá de nuevo.' }, 400);
      }
      const { error: errPerfil } = await admin.rpc('admin_crear_perfil', {
        p_id: nuevo.user.id, p_usuario: usuario, p_nombre: nombre, p_telefono: telefono, p_unidad: null,
      });
      if (errPerfil) {
        await admin.auth.admin.deleteUser(nuevo.user.id);
        return json({ error: 'No se pudo crear la cuenta. Probá de nuevo.' }, 400);
      }
      if (referente) await admin.rpc('admin_fijar_referido', { p_id: nuevo.user.id, p_ref: referente });
      return json({ ok: true, referido: !!referente });
    }

    // 1. Quién llama: con su propio token.
    const autorizacion = req.headers.get('Authorization') ?? '';
    const jwt = autorizacion.replace(/^Bearer\s+/i, '');
    const quien = createClient(url, anon, {
      global: { headers: { Authorization: autorizacion } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: sesion, error: errSesion } = await quien.auth.getUser(jwt);
    if (errSesion || !sesion?.user) return json({ error: 'Ingresá de nuevo.' }, 401);
    const { data: esDueno } = await quien.rpc('es_dueno');

    // 2. Con permisos de servidor, hace lo pedido.
    const admin = createClient(url, servicio, { auth: { persistSession: false, autoRefreshToken: false } });
    const clienteExiste = async (id: string) => {
      const { data } = await admin.from('perfiles').select('rol').eq('id', id).maybeSingle();
      return data?.rol === 'cliente';
    };

    // Un cliente puede eliminar su propia cuenta (lo exigen Apple y Google).
    // Sus pedidos de presupuesto quedan sin nombre, teléfono ni direcciones.
    if (b.accion === 'eliminar_yo') {
      if (esDueno === true) return json({ error: 'Solo un cliente puede eliminar su cuenta.' }, 403);
      const id = sesion.user.id;
      if (!(await clienteExiste(id))) return json({ error: 'No encontramos tu cuenta.' }, 404);
      const { error: errAnon } = await admin.from('presupuestos')
        .update({ nombre: 'Cliente eliminado', telefono: '', origen: '', destino: '', detalle: '' }).eq('cliente_id', id);
      if (errAnon) return json({ error: errAnon.message }, 400);
      const { error: errDb } = await admin.rpc('admin_eliminar_perfil', { p_id: id });
      if (errDb) return json({ error: errDb.message }, 400);
      const { error: errAuth } = await admin.auth.admin.deleteUser(id);
      if (errAuth) return json({ error: errAuth.message }, 400);
      return json({ ok: true });
    }

    // Todo lo demás es solo del dueño.
    if (esDueno !== true) return json({ error: 'Solo el dueño puede hacer esto.' }, 403);

    if (b.accion === 'crear') {
      const usuario = String(b.usuario ?? '').trim().toLowerCase();
      const nombre = String(b.nombre ?? '').trim();
      const clave = String(b.password ?? '');
      if (!/^[a-z0-9._-]{3,}$/.test(usuario)) return json({ error: 'El usuario necesita 3 letras o números como mínimo, sin espacios.' }, 400);
      if (nombre.length < 2) return json({ error: 'Escribí el nombre del cliente.' }, 400);
      if (clave.length < 6) return json({ error: 'La contraseña necesita 6 caracteres como mínimo.' }, 400);

      const { data: nuevo, error: errCrear } = await admin.auth.admin.createUser({
        email: `${usuario}@${DOMINIO}`, password: clave, email_confirm: true, user_metadata: { usuario },
      });
      if (errCrear || !nuevo?.user) {
        const ya = /already|registered|exists/i.test(errCrear?.message ?? '');
        return json({ error: ya ? 'Ese usuario ya existe.' : (errCrear?.message ?? 'No se pudo crear el usuario.') }, 400);
      }
      const { data: perfil, error: errPerfil } = await admin.rpc('admin_crear_perfil', {
        p_id: nuevo.user.id, p_usuario: usuario, p_nombre: nombre,
        p_telefono: String(b.telefono ?? ''), p_unidad: b.unidad_id || null,
      });
      if (errPerfil) {                                   // si falla el perfil, no deja un usuario huérfano
        await admin.auth.admin.deleteUser(nuevo.user.id);
        return json({ error: errPerfil.message }, 400);
      }
      return json({ ok: true, perfil });
    }

    if (b.accion === 'clave') {
      const clave = String(b.password ?? '');
      if (!b.id || !(await clienteExiste(b.id))) return json({ error: 'El cliente no existe.' }, 404);
      if (clave.length < 6) return json({ error: 'La contraseña necesita 6 caracteres como mínimo.' }, 400);
      const { error } = await admin.auth.admin.updateUserById(b.id, { password: clave });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    if (b.accion === 'eliminar') {
      if (!b.id || !(await clienteExiste(b.id))) return json({ error: 'El cliente no existe.' }, 404);
      const { error: errDb } = await admin.rpc('admin_eliminar_perfil', { p_id: b.id });
      if (errDb) return json({ error: errDb.message }, 400);
      const { error: errAuth } = await admin.auth.admin.deleteUser(b.id);
      if (errAuth) return json({ error: errAuth.message }, 400);
      return json({ ok: true });
    }

    return json({ error: 'Acción desconocida.' }, 400);
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : 'Error inesperado.' }, 500);
  }
});
