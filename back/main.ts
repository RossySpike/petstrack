import { JWTPayload, jwtVerify, SignJWT } from "npm:jose@5.9.6";
import { createClient } from "npm:@supabase/supabase-js@2";
import bcryptjs from "npm:bcryptjs@2.4.3"; // Needed for deno playground deploy

interface Payload extends JWTPayload {
  role: "USER" | "ADMIN";
}

const JWT_KEY = Deno.env.get("JWT_KEY");
const DB_URL = Deno.env.get("DB_URL");
const DB_KEY = Deno.env.get("DB_KEY");

const SECRET = new TextEncoder().encode(JWT_KEY);
const SUPABASE = createClient(DB_URL, DB_KEY);

//NOTE: bcrypt >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// Crear versiones async
const hash = async (password, saltRounds) => {
  return bcryptjs.hashSync(password, saltRounds);
};

const compare = async (password, hash) => {
  return bcryptjs.compareSync(password, hash);
};

const genSalt = async (saltRounds) => {
  return bcryptjs.genSaltSync(saltRounds);
};

interface Payload extends JWTPayload {
  role: "USER" | "ADMIN";
}

async function hashPassword(plainPassword) {
  const saltRounds = 10;
  const salt = await genSalt(saltRounds);
  const hashedPassword = await hash(plainPassword, salt);
  return hashedPassword;
}

async function verifyPassword(plainPassword, hashedPassword) {
  try {
    const isValid = await compare(plainPassword, hashedPassword);
    return isValid; // true o false
  } catch (error) {
    console.error("Error verificando password:", error);
    return false;
  }
}
//NOTE:  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//NOTE: jwt >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
async function createJWT(payload: Payload): Promise<string> {
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("3h")
    .sign(SECRET);

  return jwt;
}
async function verifyJWT(token: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, SECRET);
    return payload;
  } catch (error) {
    console.error("Error verifying JWT:", error);
    return null;
  }
}

function extractJWT(request: Request) {
  const authValue = request.headers.get("authorization") as string;
  let splited: string[];
  return !authValue.includes("Bearer") ||
    (splited = authValue.split(" ")).length !== 2
    ? ""
    : splited[1];
}
async function validateRoleJWT(jwt: string, role: string) {
  const validatedJWT: Payload | null = await verifyJWT(jwt);
  return !validatedJWT || validatedJWT.role !== role ? null : validatedJWT;
}

//NOTE: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//NOTE: validation >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
type BodyValidator = { key: string; type: string; notRequired?: true };
type Validators =
  | {
      headers: { key: string; value?: string }[];
      body?: BodyValidator[];
    }
  | {
      headers?: { key: string; value?: string }[];
      body: BodyValidator[];
    };
async function validateRequest<T = any>(
  request: Request,
  validators: Validators,
): Promise<{ valid: boolean; data?: Response | T }> {
  if (validators.headers !== undefined) {
    for (let header of validators.headers) {
      const contentType = request.headers.get(header.key);
      if (header.value !== undefined && !contentType?.includes(header.value)) {
        return {
          valid: false,
          data: new Response(`Bad request -->${header.key}:${header.value}`, {
            status: 400,
            headers: { "Content-Type": "text/plain" },
          }),
        };
      }
    }
  }
  if (validators.body !== undefined) {
    let payload: any;
    try {
      payload = await request.json();
    } catch (e) {
      console.error("[-] Something happened while trying to parse body:");
      console.error("[-] Body content:");
      console.error(await request.text());
      console.error(e);
      return {
        valid: false,
        data: new Response(`Empty body`, {
          status: 422,
          headers: { "Content-Type": "text/plain" },
        }),
      };
    }

    for (let entry of validators.body) {
      if (entry?.notRequired === true && !(entry.key in payload)) continue;
      if (!(entry.key in payload) || typeof payload[entry.key] !== entry.type)
        return {
          valid: false,
          data: new Response(
            `Body does not meet expectations -->'{"${entry.key}":"${entry.type}"}'`,
            {
              status: 422,
              headers: { "Content-Type": "text/plain" },
            },
          ),
        };
    }
    return { valid: true, data: payload };
  }

  return { valid: true };
}
function isValidEmail(email: any): email is string {
  return (
    typeof email === "string" &&
    email.length > 0 &&
    email.length <= 255 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}
//NOTE: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//NOTE: endpoints >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
async function getMyData(url: URL, request: Request) {
  if (url.pathname !== "/api/users" || request.method !== "GET")
    return undefined;
  // Sanitize req
  const validation = await validateRequest(request, {
    headers: [{ key: "authorization" }],
  });
  if (!validation.valid) return validation.data;
  const jwt = extractJWT(request);
  if (jwt.length === 0)
    return new Response(`Bad request -->Authorization: Bearer "token"`, {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwtData: Payload | null = await verifyJWT(jwt);
  if (jwtData === null)
    return new Response("Invalid jwt", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  return new Response(
    JSON.stringify({ userId: jwtData.userId, username: jwtData.username }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}
async function login(url: URL, request: Request) {
  if (url.pathname === "/api/login" && request.method === "POST") {
    // Sanitize req
    const validation = await validateRequest(request, {
      headers: [{ key: "content-type", value: "application/json" }],
      body: [
        { key: "email", type: "string" },
        { key: "pass", type: "string" },
      ],
    });

    if (!validation.valid) {
      return validation.data;
    }

    const payload = validation.data as { email: string; pass: string };

    // Validaciones de negocio
    if (!isValidEmail(payload.email)) {
      return new Response(`Invalid email format`, {
        status: 422,
        headers: { "Content-Type": "text/plain" },
      });
    }

    if (payload.pass.length === 0) {
      return new Response(`Password cannot be empty`, {
        status: 422,
        headers: { "Content-Type": "text/plain" },
      });
    }
    // login
    const email = payload.email.trim().toLowerCase();
    try {
      const { data, error } = await SUPABASE.from("owners")
        .select("id,name,role,pass")
        .eq("email", email)
        .single();
      // TODO:
      // Refactorizar >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
      if (error)
        return new Response(`Invalid email or password`, {
          status: 401,
          headers: { "Content-Type": "text/plain" },
        });

      const cmp = await compare(payload.pass, data?.pass);
      if (!cmp)
        return new Response(`Invalid email or password`, {
          status: 401,
          headers: { "Content-Type": "text/plain" },
        });
      // TODO: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

      return new Response(
        await createJWT({
          userId: data?.id,
          username: data?.name,
          role: data?.role,
        }),
        {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        },
      );
    } catch (e) {
      console.error("[-] Something happened while trying to login:");
      console.error(e);
      console.error(await request.text());
      return new Response(`Unexpected error`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }
  }
  return undefined;
}
async function signin(url: URL, request: Request) {
  if (url.pathname === "/api/signin" && request.method === "POST") {
    // Sanitize req
    const validation = await validateRequest(request, {
      headers: [{ key: "content-type", value: "application/json" }],
      body: [
        { key: "name", type: "string" },
        { key: "email", type: "string" },
        { key: "pass", type: "string" },
      ],
    });

    if (!validation.valid) {
      return validation.data;
    }

    const payload = validation.data as {
      name: string;
      email: string;
      pass: string;
    };

    // Validaciones de negocio
    if (!isValidEmail(payload.email)) {
      return new Response(`Invalid email format`, {
        status: 422,
        headers: { "Content-Type": "text/plain" },
      });
    }
    if (!(payload.name = payload.name.trim()))
      return new Response(`Name cannot be empty`, {
        status: 422,
        headers: { "Content-Type": "text/plain" },
      });
    if (payload.pass.length === 0)
      return new Response(`Password cannot be empty`, {
        status: 422,
        headers: { "Content-Type": "text/plain" },
      });
    // Crear el usuario
    try {
      const pass = await hashPassword(payload.pass);
      const { data, error } = await SUPABASE.from("owners")
        .insert({
          name: payload.name,
          pass: pass,
          email: payload.email.trim(),
        })
        .select("id,role")
        .single();
      // Si falla lo que me importa es que el email no este repetido, creo que puede fallar por otras cosas pero xs
      // WARN: esconde otros errores.
      return error
        ? new Response(
            `Failed to create user\n${error?.code === "23505" ? "Email already exist" : ""}`,
            {
              status: error?.code === "23505" ? 409 : 500,
              headers: { "Content-Type": "text/plain" },
            },
          )
        : new Response(
            await createJWT({
              userId: data?.id,
              username: payload.name,
              role: data?.role,
            }),
            {
              status: 201,
              headers: { "Content-Type": "text/plain" },
            },
          );
    } catch (e) {
      console.error(
        "[-] Something happened while trying to insert into owners:",
      );
      console.error(e);
      console.error(await request.text());
      return new Response(`Unexpected error`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }
  }
  return undefined;
}
async function getMyPets(url: URL, request: Request) {
  //TODO: add response for too many parameters.
  if (url.pathname !== "/api/pets" || request.method !== "GET") {
    return undefined;
  }
  // Sanitize req
  const validation = await validateRequest(request, {
    headers: [{ key: "authorization" }],
  });
  if (!validation.valid) return validation.data;
  const jwt = extractJWT(request);
  if (jwt.length === 0)
    return new Response(`Bad request -->Authorization: Bearer "token"`, {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwtData: Payload | null = await verifyJWT(jwt);
  if (jwtData === null)
    return new Response("Invalid jwt", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });

  // Si introduce parametros
  let query = SUPABASE.from("ownership")
    .select(`pets ( id, name )`)
    .eq("owner", Number(jwtData.userId)); // NOTE: puede lanzar NaN....

  if (url.searchParams.size > 0) {
    if (!url.searchParams.has("id"))
      return new Response("Invalid parameters", {
        status: 400,
        headers: { "Content-Type": "text/plain" },
      });
    const petId = Number(url.searchParams.get("id"));
    if (isNaN(petId))
      return new Response("id must be a number", {
        status: 400,
        headers: { "Content-Type": "text/plain" },
      });

    query = SUPABASE.from("ownership")
      .select(
        `
    owner,
    pet,
    pets!inner (
      id,
      name,
      activity (
        id,
        name,
        description,
        times,
        progress,
        completed,
        deleted,
        created_at
      )
    )
  `,
      )
      .eq("owner", Number(jwtData.userId))
      .eq("pet", petId)
      .order("created_at", {
        foreignTable: "pets.activity",
        ascending: false,
      })
      .single();
  }

  try {
    const { data, error } = await query;
    if (error) {
      console.log(error);
      if (error?.code === "PGRST116")
        return new Response(`Pet not found`, {
          status: 404,
          headers: { "Content-Type": "text/plain" },
        });

      return new Response(`Failed to read ownership`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }

    console.log(data);
    if (!Array.isArray(data) && "activity" in data?.pets) {
      data.pets.activity = data.pets.activity.filter((a) => !a.deleted);
    }
    console.log(data);
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("[-] Something happened while trying to read a pet:");
    console.error(e);
    console.error(await request.text());
    return new Response(`Unexpected error`, {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
}

async function addPet(url: URL, request: Request) {
  if (url.pathname !== "/api/pets" || request.method !== "POST")
    return undefined;

  // Sanitize req
  const validation = await validateRequest(request, {
    headers: [
      { key: "content-type", value: "application/json" },
      { key: "authorization" },
    ],
    body: [{ key: "name", type: "string" }],
  });
  if (!validation.valid) return validation.data;
  const jwt = extractJWT(request);
  if (jwt.length === 0)
    return new Response(`Bad request -->Authorization: Bearer "token"`, {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwtData: Payload | null = await verifyJWT(jwt);
  if (jwtData === null)
    return new Response("Invalid jwt", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });

  const payload = validation.data as { name: string };
  try {
    // NOTE: siempre va a tener {data,error}
    const petInsert = await SUPABASE.from("pets")
      .insert({
        name: payload.name,
      })
      .select("id")
      .single();
    if (petInsert.error)
      new Response(`Failed to create pet`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });

    const ownershipInsert = await SUPABASE.from("ownership").insert({
      owner: jwtData.userId,
      pet: petInsert.data.id,
    });
    if (ownershipInsert.error)
      new Response(`Failed to create ownership relation`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });

    return new Response("", {
      status: 201,
      headers: { "Content-Type": "text/plain" },
    });
  } catch (e) {
    console.error("[-] Something happened while trying to add a pet:");
    console.error(e);
    console.error(await request.text());
    return new Response(`Unexpected error`, {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
}

async function addActivity(url: URL, request: Request) {
  if (url.pathname !== "/api/activity" || request.method !== "POST") {
    return undefined;
  }
  // Sanitize req
  const validation = await validateRequest(request, {
    headers: [
      { key: "content-type", value: "application/json" },
      { key: "authorization" },
    ],
    body: [
      { key: "pet", type: "number" },
      { key: "name", type: "string" },
      { key: "times", type: "number" },
      { key: "description", type: "string", notRequired: true },
    ],
  });

  if (!validation.valid) {
    return validation.data;
  }

  if (isNaN((validation.data.pet = Number(validation.data.pet))))
    return new Response("pet must be a number", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  if (isNaN((validation.data.times = Number(validation.data.times))))
    return new Response("times must be a number", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  if (validation.data.name.trim().length === 0)
    return new Response("Name cannot be empty", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  if (
    validation.data.description &&
    validation.data.description.trim().length === 0
  )
    return new Response(`Bad request -->description:string`, {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwt = extractJWT(request);
  if (jwt.length === 0)
    return new Response(`Bad request -->Authorization: Bearer "token"`, {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwtData: Payload | null = await verifyJWT(jwt);
  if (jwtData === null)
    return new Response("Invalid jwt", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  //NOTE: ver otra forma
  const vData = validation.data;
  const payload = {
    starter: Number(jwtData.userId),
    pet: vData.pet,
    name: vData.name,
    description: vData.description ?? "",
    times: vData.times,
  };
  // Crear actividad
  try {
    const { data, error } = await SUPABASE.from("activity")
      .insert(payload)
      .select("*")
      .single();
    if (error) {
      if (error?.code === "P0001")
        return new Response(`You are not the owner of this pet`, {
          status: 403,
          headers: { "Content-Type": "text/plain" },
        });

      return new Response(`Failed to activity`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }
    return new Response(JSON.stringify(data), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(
      "[-] Something happened while trying to insert into activity:",
    );
    console.error(e);
    console.error(await request.text());
    return new Response(`Unexpected error`, {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
}
// IA:
async function incrementActivityProgress(url: URL, request: Request) {
  if (url.pathname !== "/api/activity/increment" || request.method !== "POST")
    return undefined;

  const jwt = extractJWT(request);
  if (!jwt) return new Response("Missing token", { status: 400 });

  const jwtData = await verifyJWT(jwt);
  if (!jwtData) return new Response("Invalid jwt", { status: 401 });

  const activityId = Number(url.searchParams.get("id"));
  if (isNaN(activityId))
    return new Response("Invalid activity id", { status: 400 });

  try {
    // 🚀 UNA SOLA QUERY - INCREMENTO REAL EN BD
    const { data, error } = await SUPABASE.rpc("increment_progress", {
      activity_id: activityId,
      user_id: Number(jwtData.userId),
    });

    if (error) {
      if (error.message.includes("not found")) {
        return new Response("Activity not found or unauthorized", {
          status: 404,
        });
      }
      return new Response("Failed to increment", { status: 500 });
    }

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error(
      "[-] Something happened while trying to incrementActivityProgress:",
    );
    console.error(e);
    console.error(await request.text());
    return new Response("Unexpected error", { status: 500 });
  }
}
async function deleteActivity(url: URL, request: Request) {
  if (url.pathname !== "/api/activity" || request.method !== "DELETE")
    return undefined;

  // Validar JWT
  const jwt = extractJWT(request);
  if (!jwt)
    return new Response("Missing token", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwtData = await verifyJWT(jwt);
  if (!jwtData)
    return new Response("Invalid jwt", {
      status: 401,
      headers: { "Content-Type": "text/plain" },
    });

  // Obtener ID de la actividad
  const activityId = Number(url.searchParams.get("id"));
  if (isNaN(activityId))
    return new Response("Invalid activity id", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  try {
    // Llamar a la función SQL
    const { data, error } = await SUPABASE.rpc("delete_activity", {
      activity_id: activityId,
      user_id: Number(jwtData.userId),
    });

    if (error) {
      console.log(error);

      // Manejar errores específicos
      if (error.message.includes("not found")) {
        return new Response("Activity not found", {
          status: 404,
          headers: { "Content-Type": "text/plain" },
        });
      }

      if (error.message.includes("already deleted")) {
        return new Response("Activity already deleted", {
          status: 400,
          headers: { "Content-Type": "text/plain" },
        });
      }

      if (
        error.message.includes("Unauthorized") ||
        error.message.includes("not an owner")
      ) {
        return new Response("You are not an owner of this pet", {
          status: 403,
          headers: { "Content-Type": "text/plain" },
        });
      }

      return new Response("Failed to delete activity", {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    }

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("[-] Something happened while deleting activity:");
    console.error(e);
    console.error(await request.text());
    return new Response("Unexpected error", {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
}
async function sharePet(url: URL, request: Request) {
  if (url.pathname !== "/api/pets/share" || request.method !== "POST")
    return undefined;

  const jwt = extractJWT(request);
  if (!jwt) return new Response("Missing token", { status: 400 });

  const jwtData = await verifyJWT(jwt);
  if (!jwtData) return new Response("Invalid jwt", { status: 401 });

  // Validar body
  const validation = await validateRequest(request, {
    headers: [{ key: "content-type", value: "application/json" }],
    body: [
      { key: "newOwner", type: "number" },
      { key: "petId", type: "number" },
    ],
  });

  if (!validation.valid) return validation.data;

  const { newOwner, petId } = validation.data;

  try {
    const { data, error } = await SUPABASE.rpc("share_pet", {
      p_owner1_id: jwtData.userId,
      p_owner2_id: newOwner,
      p_pet_id: petId,
    });

    if (error) {
      return new Response(error.message, {
        status: 400,
        headers: { "Content-Type": "text/plain" },
      });
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: data,
      }),
      {
        status: 201,
        headers: { "Content-Type": "application/json" },
      },
    );
  } catch (e) {
    console.error("[-] Something happened while sharing pet:");
    console.error(e);
    console.error(await request.text());
    return new Response("Unexpected error", { status: 500 });
  }
}
//NOTE: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
async function deleteOwnership(url: URL, request: Request) {
  if (url.pathname !== "/api/pets/ownership" || request.method !== "DELETE") {
    return undefined;
  }
  const validation = await validateRequest(request, {
    headers: [{ key: "authorization" }],
  });
  if (!validation.valid) return validation.data;
  const jwt = extractJWT(request);
  if (jwt.length === 0)
    return new Response(`Bad request -->Authorization: Bearer "token"`, {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });

  const jwtData: Payload | null = await verifyJWT(jwt);
  if (jwtData === null)
    return new Response("Invalid jwt", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });

  const petId = Number(url.searchParams.get("id"));
  if (isNaN(petId))
    return new Response("Invalid pet id", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  try {
    const { error, count } = await SUPABASE.from("ownership")
      .delete()
      .eq("owner", jwtData.userId)
      .eq("pet", petId)
      .select();
    if (error && !count)
      return new Response("Relation not found", {
        status: 404,
        headers: {
          "Content-Type": "text/plain",
        },
      });
    if (error)
      return new Response(`Unexpected error`, {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    return new Response("", { status: 200 });
  } catch (e) {
    console.error(
      "[-] Something happened while trying to delete an ownership row:",
    );
    console.error(e);
    console.error(await request.text());
    return new Response(`Unexpected error`, {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
}
async function health(url: URL, request: Request) {
  if (url.pathname === "/api/health" && request.method === "GET") {
    const { data, error } = await SUPABASE.from("pets").select("id");

    const db = error ? `Connection failed` : "Connected to db";
    return new Response(`Server: Alive\nDb: ${db}`, { status: 200 });
  }
  return undefined;
}

//NOTE: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
const endpoints: Array<
  (url: URL, request: Request) => Promise<unknown | undefined>
> = [
  login,
  signin,
  getMyData,
  addPet,
  getMyPets,
  sharePet,
  addActivity,
  incrementActivityProgress,
  deleteActivity,
  deleteOwnership,
  health,
];

// TODO: MODIFICAR
// Al inicio del archivo, antes de Deno.serve
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Max-Age": "86400",
};

// Modifica Deno.serve para manejar OPTIONS y agregar headers
Deno.serve(async (req: Request) => {
  // Manejar preflight OPTIONS
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS,
    });
  }

  const url = new URL(req.url);
  let response: Response | undefined;

  for (let fn of endpoints) {
    const res = await fn(url, req);
    if (res !== undefined) {
      response = res;
      break;
    }
  }

  if (!response) {
    response = new Response("f u", { status: 403 });
  }

  // Agregar CORS headers a todas las respuestas
  const newHeaders = new Headers(response.headers);
  Object.entries(CORS_HEADERS).forEach(([key, value]) => {
    newHeaders.set(key, value);
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
});
