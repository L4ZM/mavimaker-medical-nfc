import { createClient } from "npm:@supabase/supabase-js@2";

const url = Deno.env.get("SUPABASE_URL");
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
if (!url || !serviceKey) throw new Error("Supabase environment not configured");
const db = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
const cors = {
  "Access-Control-Allow-Origin": "https://l4zm.github.io",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
};
const fields = "id,full_name,date_of_birth,birth_place,residence_city,blood_type,allergies,medical_conditions,medications,emergency_contact_name,emergency_contact_phone,emergency_contact_preference,imss_number,is_active,token_revoked_at,access_token";
const writable = ["full_name","date_of_birth","birth_place","residence_city","blood_type","allergies","medical_conditions","medications","emergency_contact_name","emergency_contact_phone","emergency_contact_preference","imss_number"];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const reply = (status: number, payload: unknown) => new Response(JSON.stringify(payload), { status, headers: cors });
const clean = (body: Record<string, unknown>) => {
  const out: Record<string, string | null> = {};
  for (const k of writable) {
    if (Object.prototype.hasOwnProperty.call(body, k)) {
      if (body[k] !== null && typeof body[k] !== "string") throw new Error("INVALID_FIELD");
      const val = typeof body[k] === "string" ? body[k].trim() : "";
      if (val.length > 5000) throw new Error("FIELD_TOO_LONG");
      out[k] = val || null;
    }
  }
  return out;
};
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (!["GET","POST","PATCH"].includes(req.method)) return reply(405, { success: false, error: "Método no permitido" });
  try {
    const bearer = req.headers.get("Authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!bearer) return reply(401, { success: false, error: "Inicia sesión" });
    const { data: userData, error: authError } = await db.auth.getUser(bearer);
    if (authError || !userData.user) return reply(401, { success: false, error: "Sesión inválida" });
    const { data: admin, error: adminError } = await db.from("admin_users").select("user_id").eq("user_id", userData.user.id).maybeSingle();
    if (adminError) return reply(500, { success: false, error: "Error verificando permisos" });
    if (!admin) return reply(403, { success: false, error: "Sin permisos administrativos" });
    if (req.method === "GET") {
      const { data, error } = await db.from("medical_profiles").select(fields).order("full_name", { ascending: true }).limit(500);
      if (error) return reply(500, { success: false, error: "No se pudo consultar pacientes" });
      return reply(200, { success: true, patients: data });
    }
    let body: Record<string, unknown>;
    try {
      const input = await req.json();
      if (!input || typeof input !== "object" || Array.isArray(input)) return reply(400, { success: false, error: "Datos inválidos" });
      body = input;
    } catch { return reply(400, { success: false, error: "JSON inválido" }); }
    if (req.method === "POST") {
      let values: Record<string, string | null>;
      try { values = clean(body); } catch { return reply(400, { success: false, error: "Campos inválidos" }); }
      if (!values.full_name || !values.date_of_birth) return reply(400, { success: false, error: "Nombre y fecha de nacimiento obligatorios" });
      // Prevent accidental duplicates; admin must review matches rather than silently overwrite.
      const { data: matches, error: matchError } = await db.from("medical_profiles").select("id,full_name,date_of_birth").ilike("full_name", values.full_name).eq("date_of_birth", values.date_of_birth).limit(5);
      if (matchError) return reply(500, { success: false, error: "No se pudo verificar duplicados" });
      if (matches?.length) return reply(409, { success: false, error: "Posible paciente duplicado; revisa el expediente existente", matches });
      const { data, error } = await db.from("medical_profiles").insert({ ...values, is_active: true }).select(fields).single();
      if (error) return reply(500, { success: false, error: "No se pudo registrar. Verifica los datos y las columnas de la tabla." });
      return reply(201, { success: true, patient: data });
    }
    const id = typeof body.id === "string" ? body.id : "";
    if (!uuid.test(id)) return reply(400, { success: false, error: "ID inválido" });
    if (body.action === "revoke") {
      const { data, error } = await db.from("medical_profiles").update({ is_active: false, token_revoked_at: new Date().toISOString() }).eq("id", id).select(fields).maybeSingle();
      if (error) return reply(500, { success: false, error: "No se pudo revocar" });
      if (!data) return reply(404, { success: false, error: "Paciente no encontrado" });
      return reply(200, { success: true, patient: data });
    }
    if (body.action === "rotate") {
      const { data, error } = await db.from("medical_profiles").update({ access_token: crypto.randomUUID(), is_active: true, token_revoked_at: null }).eq("id", id).select(fields).maybeSingle();
      if (error) return reply(500, { success: false, error: "No se pudo reemplazar el enlace" });
      if (!data) return reply(404, { success: false, error: "Paciente no encontrado" });
      return reply(200, { success: true, patient: data });
    }
    if (body.action === "reactivate") return reply(400, { success: false, error: "Para reactivar, genera un nuevo enlace NFC" });
    let values: Record<string, string | null>;
    try { values = clean(body); } catch { return reply(400, { success: false, error: "Campos inválidos" }); }
    if (!Object.keys(values).length) return reply(400, { success: false, error: "No hay cambios" });
    const { data, error } = await db.from("medical_profiles").update(values).eq("id", id).select(fields).maybeSingle();
    if (error) return reply(500, { success: false, error: "No se pudo actualizar" });
    if (!data) return reply(404, { success: false, error: "Paciente no encontrado" });
    return reply(200, { success: true, patient: data });
  } catch (e) {
    console.error("admin-patients unexpected error", e instanceof Error ? e.name : "unknown");
    return reply(500, { success: false, error: "Error interno" });
  }
});
