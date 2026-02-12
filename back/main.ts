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
    console.log("JWT is valid:", payload);
    return payload;
  } catch (error) {
    console.error("Invalid JWT:", error);
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
type Validators =
  | {
      headers: { key: string; value?: string }[];
      body?: { key: string; type: string }[];
    }
  | {
      headers?: { key: string; value?: string }[];
      body: { key: string; type: string }[];
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
      return {
        valid: false,
        data: new Response(`Empty body`, {
          status: 422,
          headers: { "Content-Type": "text/plain" },
        }),
      };
    }

    for (let entry of validators.body) {
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
      .select(`pets ( id, name )`)
      .eq("owner", Number(jwtData.userId)) // NOTE: puede lanzar NaN....
      .eq("pet", petId)
      .single();
  }

  try {
    const { data, error } = await query;
    if (error) {
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

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("[-] Something happened while trying to add a pet:");
    console.error(e);
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
    return new Response(`Unexpected error`, {
      status: 500,
      headers: { "Content-Type": "text/plain" },
    });
  }
}

async function health(url: URL, request: Request) {
  if (url.pathname === "/api/health" && request.method === "GET") {
    const { data, error } = await SUPABASE.from("pets").select("id");

    const db = error
      ? `Connection failed: ${error?.message}`
      : "Connected to db";
    return new Response(`Server: Alive\nDb: ${db}`, { status: 200 });
  }
  return undefined;
}

//NOTE: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
const endpoints: Array<
  (url: URL, request: Request) => Promise<unknown | undefined>
> = [login, signin, addPet, getMyPets, health];

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  for (let fn of endpoints) {
    const res = await fn(url, req);
    if (res !== undefined) return res;
  }
  // Health
  return new Response("f u", { status: 403 });
});
