/**
 * Supabase Edge Function: `sms-proxy`
 * Zero-Trust server-side proxy to the Sendmode SMS-REST 3.0 Bulk SMS API.
 *
 * Security & Functional Architecture (Phases 3–6):
 * - Strict CORS allowlist (`http://localhost:3000` and production Vercel URL only).
 * - Cryptographic JWT verification via `supabaseAdmin.auth.getUser(token)` before any logic executes.
 * - Hard 150-character (`MAX_ALLOWED_CHARACTERS = 150`) and 1-segment (`MAX_ALLOWED_SEGMENTS = 1`) business rule.
 * - Default `senderId` set to `"Dilli Haat"`.
 * - Server-side audience resolution from `public.contacts` / `customPhones` and `public.opt_outs` stripping.
 * - Server-side `analyzeSmsSegments`, `valid_recipient_count`, and `totalCost` recalculation.
 * - Server-side credit gatekeeper summing `scheduled` and `processing` rows (`402 Payment Required`).
 * - Write-Ahead state machine (`status = 'processing'` -> Sendmode dispatch -> `'sent'`/`'scheduled'` or `'failed'`).
 * - Sendmode SMS-REST 3.0 endpoint mapping (`/balance`, `/send`, `/send-bulk`, `/schedule-bulk`, `/schedule-delete`)
 *   with `Authorization: Bearer ${Deno.env.get("SMS_API")}` and sanitized `502 Bad Gateway` / `500` error handling.
 */

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import {
  createClient,
  type SupabaseClient,
} from "https://esm.sh/@supabase/supabase-js@2.47.0";

const SENDMODE_BASE_URL = (
  Deno.env.get("SMS_REST_3_BASE_URL") ?? "https://rest.sendmode.com/v3"
).replace(/\/+$/, "");

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const PRODUCTION_VERCEL_URL =
  Deno.env.get("PRODUCTION_VERCEL_URL") ??
  Deno.env.get("ALLOWED_ORIGIN") ??
  "https://dilli-haat-sms-campaign.vercel.app";

const ALLOWED_ORIGINS = new Set<string>([
  "http://localhost:3000",
  PRODUCTION_VERCEL_URL,
]);

const E164_REGEX = /^\+[1-9]\d{6,14}$/;
const MAX_ALLOWED_CHARACTERS = 150;
const MAX_ALLOWED_SEGMENTS = 1;
const DEFAULT_SENDER_ID = "Dilli Haat";

/**
 * Standard 3GPP TS 23.038 GSM-7 Default Alphabet (1 septet each)
 */
const GSM7_BASIC_CHARS = new Set([
  "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å",
  "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "Æ", "æ", "ß", "É", " ",
  "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
  "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
  "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",
  "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
  "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à",
]);

/**
 * GSM-7 Extension Table characters (count as 2 septets each: ESC + char)
 */
const GSM7_EXTENDED_CHARS = new Set(["^", "{", "}", "\\", "[", "~", "]", "|", "€", "\f"]);

type SmsEncoding = "GSM-7" | "UCS-2";

interface SegmentAnalysis {
  encoding: SmsEncoding;
  rawCharacterCount: number;
  effectiveUnitCount: number;
  segments: number;
  maxUnitsPerSegment: number;
  singleSegmentLimit: number;
  multiSegmentLimit: number;
  remainingInCurrentSegment: number;
  maxAllowedUnitsTotal: number;
  isOverMaxSegments: boolean;
}

/**
 * Server-side SMS segment analyzer (3GPP TS 23.038 GSM-7 vs UCS-2).
 * Enforces MAX_ALLOWED_CHARACTERS = 150 and MAX_ALLOWED_SEGMENTS = 1.
 */
function analyzeSmsSegments(text: string): SegmentAnalysis {
  if (!text || text.length === 0) {
    return {
      encoding: "GSM-7",
      rawCharacterCount: 0,
      effectiveUnitCount: 0,
      segments: 0,
      maxUnitsPerSegment: MAX_ALLOWED_CHARACTERS,
      singleSegmentLimit: 160,
      multiSegmentLimit: 153,
      remainingInCurrentSegment: MAX_ALLOWED_CHARACTERS,
      maxAllowedUnitsTotal: MAX_ALLOWED_CHARACTERS,
      isOverMaxSegments: false,
    };
  }

  let hasNonGsm = false;
  let gsmSeptets = 0;
  const codePoints = Array.from(text);

  for (const char of codePoints) {
    if (GSM7_BASIC_CHARS.has(char)) {
      gsmSeptets += 1;
    } else if (GSM7_EXTENDED_CHARS.has(char)) {
      gsmSeptets += 2;
    } else {
      hasNonGsm = true;
    }
  }

  const isUcs2 = hasNonGsm;
  const encoding: SmsEncoding = isUcs2 ? "UCS-2" : "GSM-7";
  const singleSegmentLimit = isUcs2 ? 70 : 160;
  const multiSegmentLimit = isUcs2 ? 67 : 153;
  const effectiveUnitCount = isUcs2 ? text.length : gsmSeptets;

  let segments = 0;
  let maxUnitsPerSegment = Math.min(singleSegmentLimit, MAX_ALLOWED_CHARACTERS);

  if (effectiveUnitCount === 0) {
    segments = 0;
  } else if (effectiveUnitCount <= singleSegmentLimit) {
    segments = 1;
    maxUnitsPerSegment = Math.min(singleSegmentLimit, MAX_ALLOWED_CHARACTERS);
  } else {
    segments = Math.ceil(effectiveUnitCount / multiSegmentLimit);
    maxUnitsPerSegment = multiSegmentLimit;
  }

  const maxAllowedUnitsTotal =
    MAX_ALLOWED_SEGMENTS === 1
      ? Math.min(singleSegmentLimit, MAX_ALLOWED_CHARACTERS)
      : Math.min(
          multiSegmentLimit * MAX_ALLOWED_SEGMENTS,
          MAX_ALLOWED_CHARACTERS
        );
  const remainingInCurrentSegment = Math.max(
    0,
    maxAllowedUnitsTotal - effectiveUnitCount
  );
  const isOverMaxSegments =
    segments > MAX_ALLOWED_SEGMENTS ||
    codePoints.length > MAX_ALLOWED_CHARACTERS ||
    effectiveUnitCount > MAX_ALLOWED_CHARACTERS;

  return {
    encoding,
    rawCharacterCount: codePoints.length,
    effectiveUnitCount,
    segments,
    maxUnitsPerSegment,
    singleSegmentLimit,
    multiSegmentLimit,
    remainingInCurrentSegment,
    maxAllowedUnitsTotal,
    isOverMaxSegments,
  };
}

/**
 * Converts a UTC ISO-8601 timestamp into Sendmode's required UTC date-time format (`YYYY-MM-DD HH:mm:ss`).
 */
function formatSendmodeDate(isoUtc: string): string {
  const date = new Date(isoUtc);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
    date.getUTCDate()
  )} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(
    date.getUTCSeconds()
  )}`;
}

/**
 * Extracts and logs detailed Sendmode error responses server-side via `console.error()`
 * without leaking upstream provider internals to the client.
 */
async function logSendmodeError(
  res: Response,
  operation: string
): Promise<string> {
  let rawBody = "";
  try {
    rawBody = await res.text();
    const parsed = JSON.parse(rawBody);
    const providerMessage =
      parsed?.error ??
      parsed?.message ??
      parsed?.statusMessage ??
      parsed?.detail ??
      rawBody;
    console.error(
      `[Sendmode API Error - ${operation}] HTTP ${res.status}: ${String(
        providerMessage
      )}`,
      parsed
    );
  } catch {
    console.error(
      `[Sendmode API Error - ${operation}] HTTP ${res.status}: ${
        rawBody || res.statusText
      }`
    );
  }
  return `Sendmode ${operation} failed with HTTP ${res.status}.`;
}

/**
 * Strict CORS Enforcement: Only allow `http://localhost:3000` and the production Vercel URL.
 */
function getCorsConfig(req: Request): {
  corsHeaders: Record<string, string>;
  isAllowedOrigin: boolean;
} {
  const origin = req.headers.get("Origin") ?? req.headers.get("origin") ?? "";
  const isAllowedOrigin = !origin || ALLOWED_ORIGINS.has(origin);
  const resolvedOrigin = ALLOWED_ORIGINS.has(origin)
    ? origin
    : "http://localhost:3000";

  return {
    isAllowedOrigin,
    corsHeaders: {
      "Access-Control-Allow-Origin": resolvedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers":
        "authorization, x-client-info, apikey, content-type, x-idempotency-key",
      Vary: "Origin",
    },
  };
}

interface CampaignCreditRow {
  status?: string | null;
  estimated_credits?: number | null;
}

interface OptOutRow {
  phone?: string | null;
}

interface ContactRow {
  phone_e164?: string | null;
  visit_count?: number | null;
}

interface ResolvedAudienceResult {
  validPhoneArray: string[];
  rawRecipientCount: number;
  validRecipientCount: number;
  duplicatesRemovedCount: number;
  optedOutStrippedCount: number;
  invalidRejectedCount: number;
}

function isDuplicateIdempotencyError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const pgErr = err as {
    code?: string;
    message?: string;
    details?: string;
    hint?: string;
  };
  if (pgErr.code === "23505") return true;
  const combined = `${pgErr.message ?? ""} ${pgErr.details ?? ""} ${pgErr.hint ?? ""}`;
  return /duplicate key|unique constraint|idempotency_key/i.test(combined);
}

class SendmodeGatewayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SendmodeGatewayError";
  }
}

/**
 * Fetches the live credit balance from Sendmode (`GET /balance`) and sums
 * `estimated_credits` for all `scheduled` and `processing` rows in `public.sms_campaigns`.
 */
async function computeCreditLedger(
  supabaseAdmin: SupabaseClient
): Promise<{
  liveBalance: number;
  reservedCredits: number;
  effectiveAvailableCredits: number;
}> {
  const { data: campaignRows, error: dbErr } = await supabaseAdmin
    .from("sms_campaigns")
    .select("status, estimated_credits");

  if (dbErr) throw dbErr;

  const rows: CampaignCreditRow[] = (campaignRows ?? []) as CampaignCreditRow[];
  const reservedCredits = rows
    .filter(
      (r: CampaignCreditRow) =>
        r.status === "scheduled" || r.status === "processing"
    )
    .reduce(
      (sum: number, r: CampaignCreditRow) =>
        sum + Number(r.estimated_credits ?? 0),
      0
    );

  let providerRes: Response;
  try {
    providerRes = await fetch(`${SENDMODE_BASE_URL}/balance`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${Deno.env.get("SMS_API")}`,
        Accept: "application/json",
      },
    });
  } catch (networkErr) {
    console.error("[Sendmode API Network Error - GET /balance]", networkErr);
    throw new SendmodeGatewayError(
      "Bad Gateway: Unable to reach Sendmode balance endpoint."
    );
  }

  if (!providerRes.ok) {
    await logSendmodeError(providerRes, "GET /balance");
    throw new SendmodeGatewayError(
      "Bad Gateway: Upstream SMS provider failed to return credit balance."
    );
  }

  const providerJson = await providerRes.json();
  const liveBalance = Number(
    providerJson?.balance ?? providerJson?.liveBalance ?? 0
  );

  if (Number.isNaN(liveBalance)) {
    console.error(
      "[Sendmode API Error - GET /balance] Invalid balance payload:",
      providerJson
    );
    throw new SendmodeGatewayError(
      "Bad Gateway: Upstream SMS provider returned an invalid balance format."
    );
  }

  return {
    liveBalance,
    reservedCredits,
    effectiveAvailableCredits: liveBalance - reservedCredits,
  };
}

/**
 * Resolves the actual recipient E.164 phone list on the server:
 * - Fetches all `phone` values from `public.opt_outs` into a `Set`.
 * - If `audienceId === "custom"`, validates E.164, deduplicates, and strips `opt_outs` from `customPhones`.
 * - If `audienceId === "all"`, `"random"`, or `"top"`, queries `public.contacts` for `phone_e164`,
 *   strips `opt_outs`, and applies the subset (`ORDER BY visit_count DESC LIMIT N` for `"top"`,
 *   or Fisher-Yates shuffle `LIMIT N` for `"random"`).
 */
async function resolveAudienceRecipients(
  supabaseAdmin: SupabaseClient,
  audienceId: string,
  body: Record<string, unknown>
): Promise<{ data?: ResolvedAudienceResult; clientError?: string }> {
  const { data: optOutRows, error: optOutErr } = await supabaseAdmin
    .from("opt_outs")
    .select("phone");

  if (optOutErr) throw optOutErr;

  const optOutSet = new Set<string>(
    ((optOutRows ?? []) as OptOutRow[])
      .map((r: OptOutRow) =>
        String(r.phone ?? "")
          .trim()
          .replace(/[\s()-]/g, "")
      )
      .filter(Boolean)
  );

  const seenValid = new Set<string>();
  let validPhoneArray: string[] = [];
  let rawRecipientCount = 0;
  let duplicatesRemovedCount = 0;
  let optedOutStrippedCount = 0;
  let invalidRejectedCount = 0;

  if (audienceId === "custom") {
    if (!Array.isArray(body.customPhones)) {
      return {
        clientError:
          "customPhones array is required when audienceId is 'custom'.",
      };
    }

    for (const raw of body.customPhones) {
      const normalized = String(raw ?? "")
        .trim()
        .replace(/[\s()-]/g, "");
      if (!normalized) continue;
      rawRecipientCount++;

      if (!E164_REGEX.test(normalized)) {
        invalidRejectedCount++;
        continue;
      }

      if (seenValid.has(normalized)) {
        duplicatesRemovedCount++;
        continue;
      }
      seenValid.add(normalized);

      if (optOutSet.has(normalized)) {
        optedOutStrippedCount++;
        continue;
      }

      validPhoneArray.push(normalized);
    }
  } else if (
    audienceId === "all" ||
    audienceId === "random" ||
    audienceId === "top"
  ) {
    const contactsQuery = supabaseAdmin
      .from("contacts")
      .select("phone_e164, visit_count");

    const { data: contactRows, error: contactsErr } =
      audienceId === "top" && typeof contactsQuery.order === "function"
        ? await contactsQuery.order("visit_count", { ascending: false })
        : await contactsQuery;

    if (contactsErr) throw contactsErr;

    const rows: ContactRow[] = [...((contactRows ?? []) as ContactRow[])];
    if (audienceId === "top") {
      rows.sort(
        (a: ContactRow, b: ContactRow) =>
          Number(b.visit_count ?? 0) - Number(a.visit_count ?? 0)
      );
    }

    for (const row of rows) {
      const normalized = String(row.phone_e164 ?? "")
        .trim()
        .replace(/[\s()-]/g, "");
      if (!normalized) continue;
      rawRecipientCount++;

      if (!E164_REGEX.test(normalized)) {
        invalidRejectedCount++;
        continue;
      }

      if (seenValid.has(normalized)) {
        duplicatesRemovedCount++;
        continue;
      }
      seenValid.add(normalized);

      if (optOutSet.has(normalized)) {
        optedOutStrippedCount++;
        continue;
      }

      validPhoneArray.push(normalized);
    }

    if (audienceId === "top" || audienceId === "random") {
      const rawLimit =
        body.audienceSize ??
        body.limit ??
        body.subsetSize ??
        body.recipientsCount;
      const limitN = Math.floor(Number(rawLimit ?? 0));
      if (!Number.isFinite(limitN) || limitN <= 0) {
        return {
          clientError:
            "A positive recipient subset limit is required for 'top' or 'random' audiences.",
        };
      }

      if (audienceId === "random") {
        // Fisher-Yates shuffle
        for (let i = validPhoneArray.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          const temp = validPhoneArray[i];
          validPhoneArray[i] = validPhoneArray[j];
          validPhoneArray[j] = temp;
        }
      }

      validPhoneArray = validPhoneArray.slice(0, limitN);
    }
  } else {
    return {
      clientError: `Unsupported audienceId '${audienceId}'. Must be 'all', 'random', 'top', or 'custom'.`,
    };
  }

  const validRecipientCount = validPhoneArray.length;
  rawRecipientCount = Math.max(rawRecipientCount, validRecipientCount);

  return {
    data: {
      validPhoneArray,
      rawRecipientCount,
      validRecipientCount,
      duplicatesRemovedCount,
      optedOutStrippedCount,
      invalidRejectedCount,
    },
  };
}

serve(async (req: Request): Promise<Response> => {
  const { corsHeaders, isAllowedOrigin } = getCorsConfig(req);

  if (!isAllowedOrigin) {
    return new Response(
      JSON.stringify({
        error: "Forbidden: Origin not permitted by CORS policy.",
      }),
      {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // =========================================================================
    // Cryptographic JWT Verification (Zero-Trust Identity Check)
    // =========================================================================
    const authHeader =
      req.headers.get("Authorization") ?? req.headers.get("authorization") ?? "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : "";

    if (!token) {
      return new Response(
        JSON.stringify({ error: "Unauthorized: Missing Bearer token." }),
        {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const { data: authData, error: authError } =
      await supabaseAdmin.auth.getUser(token);

    if (authError || !authData?.user) {
      return new Response(
        JSON.stringify({
          error: "Unauthorized: Invalid or expired session token.",
        }),
        {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const authenticatedUser = authData.user;
    const body = await req.json();
    const { action } = body;

    // =========================================================================
    // Action 1: `check_credit_balance` -> GET /balance
    // =========================================================================
    if (action === "check_credit_balance") {
      const ledger = await computeCreditLedger(supabaseAdmin);

      return new Response(
        JSON.stringify({
          balance: ledger.liveBalance,
          liveBalance: ledger.liveBalance,
          reservedCredits: ledger.reservedCredits,
          effectiveAvailableCredits: ledger.effectiveAvailableCredits,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // Action 2: `send_single_sms` -> POST /send
    // =========================================================================
    if (action === "send_single_sms") {
      const {
        idempotencyKey,
        phoneNumber,
        messageBody,
        message,
        scheduledAt,
        senderId = DEFAULT_SENDER_ID,
      } = body;

      const trimmedSenderId =
        String(senderId ?? DEFAULT_SENDER_ID).trim() || DEFAULT_SENDER_ID;
      if (trimmedSenderId.length < 3 || trimmedSenderId.length > 15) {
        return new Response(
          JSON.stringify({
            error: "Sender ID must be between 3 and 15 characters.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const cleanPhone = String(phoneNumber ?? "").trim();
      if (!E164_REGEX.test(cleanPhone)) {
        return new Response(
          JSON.stringify({ error: "Invalid E.164 phone number format." }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Server-side segment & character limit enforcement (max 150 chars, 1 segment)
      const resolvedMessage = String(messageBody ?? message ?? "");
      const segmentAnalysis = analyzeSmsSegments(resolvedMessage);
      const trueSegmentCount = segmentAnalysis.segments;
      const serverCalculatedCost = trueSegmentCount;

      if (
        !resolvedMessage ||
        segmentAnalysis.rawCharacterCount > MAX_ALLOWED_CHARACTERS ||
        trueSegmentCount < 1 ||
        trueSegmentCount > MAX_ALLOWED_SEGMENTS ||
        segmentAnalysis.isOverMaxSegments
      ) {
        return new Response(
          JSON.stringify({
            error: `Message must be between 1 and ${MAX_ALLOWED_CHARACTERS} characters and fit within ${MAX_ALLOWED_SEGMENTS} segment.`,
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Server-Side Opt-Out Verification (returns 403 Forbidden if blacklisted)
      const { data: optedOutRow, error: optOutErr } = await supabaseAdmin
        .from("opt_outs")
        .select("phone")
        .eq("phone", cleanPhone)
        .maybeSingle();

      if (optOutErr) throw optOutErr;

      if (optedOutRow) {
        return new Response(
          JSON.stringify({
            error: `Forbidden: ${cleanPhone} is on the Opt-Out blacklist.`,
          }),
          {
            status: 403,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Basic Rate Limiting Guardrail (max 1 single SMS per 30 seconds per user)
      const thirtySecondsAgoIso = new Date(
        Date.now() - 30 * 1000
      ).toISOString();
      const { data: recentDispatches, error: rateLimitErr } =
        await supabaseAdmin
          .from("sms_campaigns")
          .select("id, created_at")
          .eq("user_id", authenticatedUser.id)
          .eq("valid_recipient_count", 1)
          .gte("created_at", thirtySecondsAgoIso)
          .limit(1);

      if (rateLimitErr) throw rateLimitErr;

      if (recentDispatches && recentDispatches.length > 0) {
        return new Response(
          JSON.stringify({
            error:
              "Too Many Requests: Please wait at least 30 seconds before sending another single SMS.",
          }),
          {
            status: 429,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (scheduledAt) {
        const diffMinutes =
          (Date.parse(String(scheduledAt)) - Date.now()) / (1000 * 60);
        if (Number.isNaN(diffMinutes) || diffMinutes < 15) {
          return new Response(
            JSON.stringify({
              error:
                "SCHEDULE_BUFFER_VIOLATION: Scheduled SMS must be at least 15 minutes in the future (UTC).",
            }),
            {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
      }

      // Server-Side Credit Check (liveBalance - reservedCredits where reservedCredits includes scheduled + processing)
      const ledger = await computeCreditLedger(supabaseAdmin);
      if (serverCalculatedCost > ledger.liveBalance - ledger.reservedCredits) {
        return new Response(
          JSON.stringify({
            error: "Insufficient effective credits for test SMS.",
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const sendmodeSinglePayload: Record<string, unknown> = {
        to: cleanPhone,
        senderid: trimmedSenderId,
        message: resolvedMessage,
      };

      if (scheduledAt) {
        sendmodeSinglePayload.senddate = formatSendmodeDate(
          String(scheduledAt)
        );
      }

      let providerRes: Response;
      try {
        providerRes = await fetch(`${SENDMODE_BASE_URL}/send`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${Deno.env.get("SMS_API")}`,
            "Content-Type": "application/json",
            ...(idempotencyKey
              ? { "X-Idempotency-Key": String(idempotencyKey) }
              : {}),
          },
          body: JSON.stringify(sendmodeSinglePayload),
        });
      } catch (networkErr) {
        console.error("[Sendmode API Network Error - POST /send]", networkErr);
        return new Response(
          JSON.stringify({
            error: "Bad Gateway: Failed to dispatch single SMS via provider.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (!providerRes.ok) {
        await logSendmodeError(providerRes, "POST /send");
        return new Response(
          JSON.stringify({
            error: "Bad Gateway: Failed to dispatch single SMS via provider.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      let providerData: Record<string, unknown> = {};
      try {
        providerData = await providerRes.json();
      } catch {
        providerData = {};
      }

      const messageId = String(
        providerData.messageId ??
          providerData.batchId ??
          providerData.id ??
          `${scheduledAt ? "sched-msg" : "msg"}-${Date.now()}`
      );
      const newBalance =
        typeof providerData.newBalance === "number" ||
        typeof providerData.balance === "number"
          ? Number(providerData.newBalance ?? providerData.balance)
          : scheduledAt
          ? ledger.liveBalance
          : Math.max(0, ledger.liveBalance - serverCalculatedCost);

      // Record single SMS dispatch in `sms_campaigns` for audit trail and 30s rate-limit tracking
      const { error: singleInsertErr } = await supabaseAdmin
        .from("sms_campaigns")
        .insert({
          idempotency_key: idempotencyKey || crypto.randomUUID(),
          user_id: authenticatedUser.id,
          name: "Single Test SMS",
          sender_id: trimmedSenderId,
          audience_id: "single_test",
          audience_name: cleanPhone,
          message: resolvedMessage,
          encoding: segmentAnalysis.encoding,
          character_count: segmentAnalysis.rawCharacterCount,
          effective_unit_count: segmentAnalysis.effectiveUnitCount,
          segments: trueSegmentCount,
          raw_recipient_count: 1,
          valid_recipient_count: 1,
          duplicates_removed_count: 0,
          opted_out_stripped_count: 0,
          invalid_rejected_count: 0,
          dispatch_type: scheduledAt ? "scheduled" : "immediate",
          status: scheduledAt ? "scheduled" : "sent",
          provider_campaign_id: messageId,
          scheduled_at: scheduledAt ?? null,
          dispatched_at: scheduledAt ? null : new Date().toISOString(),
        });

      if (singleInsertErr) {
        if (isDuplicateIdempotencyError(singleInsertErr)) {
          return new Response(
            JSON.stringify({
              error: "Duplicate request blocked by Idempotency Key guardrail.",
            }),
            {
              status: 409,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
        throw singleInsertErr;
      }

      return new Response(
        JSON.stringify({
          success: true,
          messageId,
          segmentCount: trueSegmentCount,
          totalCost: serverCalculatedCost,
          newBalance,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // Action 3: `send_bulk_sms` -> POST /send-bulk
    // =========================================================================
    if (action === "send_bulk_sms") {
      const {
        idempotencyKey,
        name,
        senderId = DEFAULT_SENDER_ID,
        audienceId = "all",
        audienceName = "All Contacts",
        message,
      } = body;

      const trimmedName = String(name ?? "").trim();
      const trimmedSenderId =
        String(senderId ?? DEFAULT_SENDER_ID).trim() || DEFAULT_SENDER_ID;
      const messageText = String(message ?? "");

      if (!idempotencyKey || !trimmedName || !messageText) {
        return new Response(
          JSON.stringify({ error: "Missing required campaign fields." }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (trimmedName.length < 3 || trimmedName.length > 80) {
        return new Response(
          JSON.stringify({
            error: "Campaign name must be between 3 and 80 characters.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (trimmedSenderId.length < 3 || trimmedSenderId.length > 15) {
        return new Response(
          JSON.stringify({
            error: "Sender ID must be between 3 and 15 characters.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Server-side segment & character limit enforcement (max 150 chars, 1 segment)
      const segmentAnalysis = analyzeSmsSegments(messageText);
      const trueSegments = segmentAnalysis.segments;

      if (
        segmentAnalysis.rawCharacterCount > MAX_ALLOWED_CHARACTERS ||
        trueSegments < 1 ||
        trueSegments > MAX_ALLOWED_SEGMENTS ||
        segmentAnalysis.isOverMaxSegments
      ) {
        return new Response(
          JSON.stringify({
            error: `Campaign message exceeds the ${MAX_ALLOWED_CHARACTERS}-character / ${MAX_ALLOWED_SEGMENTS}-segment ceiling.`,
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Server-side audience resolution & opt-out stripping
      const resolvedAudience = await resolveAudienceRecipients(
        supabaseAdmin,
        String(audienceId),
        body
      );

      if (resolvedAudience.clientError || !resolvedAudience.data) {
        return new Response(
          JSON.stringify({
            error:
              resolvedAudience.clientError ||
              "Failed to resolve campaign recipients.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const {
        validPhoneArray,
        rawRecipientCount,
        validRecipientCount: validCount,
        duplicatesRemovedCount,
        optedOutStrippedCount,
        invalidRejectedCount,
      } = resolvedAudience.data;

      if (validCount <= 0) {
        return new Response(
          JSON.stringify({
            error: "No valid opted-in recipients resolved for this campaign.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const serverCalculatedCost = validCount * trueSegments;

      // Server-Side Credit Gatekeeper (`scheduled` + `processing` reserved credits)
      const ledger = await computeCreditLedger(supabaseAdmin);
      if (serverCalculatedCost > ledger.liveBalance - ledger.reservedCredits) {
        return new Response(
          JSON.stringify({
            error: `Insufficient effective credits: need ${serverCalculatedCost}, have ${
              ledger.liveBalance - ledger.reservedCredits
            }.`,
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Write-Ahead State Machine Step 1: INSERT with `status = 'processing'`
      const { data: processingCampaign, error: insertErr } = await supabaseAdmin
        .from("sms_campaigns")
        .insert({
          idempotency_key: idempotencyKey,
          user_id: authenticatedUser.id,
          name: trimmedName,
          sender_id: trimmedSenderId,
          audience_id: String(audienceId),
          audience_name: String(audienceName),
          message: messageText,
          encoding: segmentAnalysis.encoding,
          character_count: segmentAnalysis.rawCharacterCount,
          effective_unit_count: segmentAnalysis.effectiveUnitCount,
          segments: trueSegments,
          raw_recipient_count: rawRecipientCount,
          valid_recipient_count: validCount,
          duplicates_removed_count: duplicatesRemovedCount,
          opted_out_stripped_count: optedOutStrippedCount,
          invalid_rejected_count: invalidRejectedCount,
          dispatch_type: "immediate",
          status: "processing",
        })
        .select()
        .single();

      if (insertErr) {
        if (isDuplicateIdempotencyError(insertErr)) {
          return new Response(
            JSON.stringify({
              error: "Duplicate request blocked by Idempotency Key guardrail.",
            }),
            {
              status: 409,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
        throw insertErr;
      }

      // Write-Ahead State Machine Step 2: Call Sendmode POST /send-bulk
      let providerRes: Response;
      try {
        providerRes = await fetch(`${SENDMODE_BASE_URL}/send-bulk`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${Deno.env.get("SMS_API")}`,
            "Content-Type": "application/json",
            "X-Idempotency-Key": String(idempotencyKey),
          },
          body: JSON.stringify({
            to: validPhoneArray,
            senderid: trimmedSenderId,
            message: messageText,
          }),
        });
      } catch (networkErr) {
        console.error(
          "[Sendmode API Network Error - POST /send-bulk]",
          networkErr
        );
        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: "Network error communicating with Sendmode API.",
          })
          .eq("id", processingCampaign.id);

        return new Response(
          JSON.stringify({
            error: "Bad Gateway: Provider bulk SMS dispatch failed.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (!providerRes.ok) {
        const failureReason = await logSendmodeError(
          providerRes,
          "POST /send-bulk"
        );
        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: failureReason,
          })
          .eq("id", processingCampaign.id);

        return new Response(
          JSON.stringify({
            error: "Bad Gateway: Provider bulk SMS dispatch failed.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      let providerData: Record<string, unknown> = {};
      try {
        providerData = await providerRes.json();
      } catch {
        providerData = {};
      }

      const batchId = String(
        providerData.batchId ??
          providerData.batch_id ??
          providerData.providerCampaignId ??
          providerData.id ??
          `batch-${Date.now()}`
      );
      const newBalance =
        typeof providerData.newBalance === "number" ||
        typeof providerData.balance === "number"
          ? Number(providerData.newBalance ?? providerData.balance)
          : Math.max(0, ledger.liveBalance - serverCalculatedCost);

      // Write-Ahead State Machine Step 3: UPDATE row to `status = 'sent'`
      const { data: finalizedCampaign, error: updateErr } = await supabaseAdmin
        .from("sms_campaigns")
        .update({
          status: "sent",
          provider_campaign_id: batchId,
          dispatched_at: new Date().toISOString(),
        })
        .eq("id", processingCampaign.id)
        .select()
        .single();

      if (updateErr) throw updateErr;

      return new Response(
        JSON.stringify({
          success: true,
          batchId,
          recipientsCount: validCount,
          segmentCount: trueSegments,
          totalCost: serverCalculatedCost,
          newBalance,
          campaign: finalizedCampaign,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // Action 4: `schedule_bulk_sms` -> POST /schedule-bulk
    // =========================================================================
    if (action === "schedule_bulk_sms") {
      const {
        idempotencyKey,
        name,
        senderId = DEFAULT_SENDER_ID,
        audienceId = "all",
        audienceName = "All Contacts",
        message,
        scheduledAt,
      } = body;

      const trimmedName = String(name ?? "").trim();
      const trimmedSenderId =
        String(senderId ?? DEFAULT_SENDER_ID).trim() || DEFAULT_SENDER_ID;
      const messageText = String(message ?? "");

      if (!idempotencyKey || !trimmedName || !messageText || !scheduledAt) {
        return new Response(
          JSON.stringify({
            error: "Missing required scheduled campaign fields.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (trimmedName.length < 3 || trimmedName.length > 80) {
        return new Response(
          JSON.stringify({
            error: "Campaign name must be between 3 and 80 characters.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (trimmedSenderId.length < 3 || trimmedSenderId.length > 15) {
        return new Response(
          JSON.stringify({
            error: "Sender ID must be between 3 and 15 characters.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Server-side segment & character limit enforcement (max 150 chars, 1 segment)
      const segmentAnalysis = analyzeSmsSegments(messageText);
      const trueSegments = segmentAnalysis.segments;

      if (
        segmentAnalysis.rawCharacterCount > MAX_ALLOWED_CHARACTERS ||
        trueSegments < 1 ||
        trueSegments > MAX_ALLOWED_SEGMENTS ||
        segmentAnalysis.isOverMaxSegments
      ) {
        return new Response(
          JSON.stringify({
            error: `Campaign message exceeds the ${MAX_ALLOWED_CHARACTERS}-character / ${MAX_ALLOWED_SEGMENTS}-segment ceiling.`,
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const diffMinutes =
        (Date.parse(String(scheduledAt)) - Date.now()) / (1000 * 60);
      if (Number.isNaN(diffMinutes) || diffMinutes < 15) {
        return new Response(
          JSON.stringify({
            error:
              "SCHEDULE_BUFFER_VIOLATION: Scheduled campaign must be at least 15 minutes in the future (UTC).",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Server-side audience resolution & opt-out stripping
      const resolvedAudience = await resolveAudienceRecipients(
        supabaseAdmin,
        String(audienceId),
        body
      );

      if (resolvedAudience.clientError || !resolvedAudience.data) {
        return new Response(
          JSON.stringify({
            error:
              resolvedAudience.clientError ||
              "Failed to resolve campaign recipients.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const {
        validPhoneArray,
        rawRecipientCount,
        validRecipientCount: validCount,
        duplicatesRemovedCount,
        optedOutStrippedCount,
        invalidRejectedCount,
      } = resolvedAudience.data;

      if (validCount <= 0) {
        return new Response(
          JSON.stringify({
            error: "No valid opted-in recipients resolved for this campaign.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const serverCalculatedCost = validCount * trueSegments;

      // Server-Side Credit Gatekeeper (`scheduled` + `processing` reserved credits)
      const ledger = await computeCreditLedger(supabaseAdmin);
      if (serverCalculatedCost > ledger.liveBalance - ledger.reservedCredits) {
        return new Response(
          JSON.stringify({
            error: `Insufficient effective credits: need ${serverCalculatedCost}, have ${
              ledger.liveBalance - ledger.reservedCredits
            }.`,
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Write-Ahead State Machine Step 1: INSERT with `status = 'processing'`
      const { data: processingCampaign, error: insertErr } = await supabaseAdmin
        .from("sms_campaigns")
        .insert({
          idempotency_key: idempotencyKey,
          user_id: authenticatedUser.id,
          name: trimmedName,
          sender_id: trimmedSenderId,
          audience_id: String(audienceId),
          audience_name: String(audienceName),
          message: messageText,
          encoding: segmentAnalysis.encoding,
          character_count: segmentAnalysis.rawCharacterCount,
          effective_unit_count: segmentAnalysis.effectiveUnitCount,
          segments: trueSegments,
          raw_recipient_count: rawRecipientCount,
          valid_recipient_count: validCount,
          duplicates_removed_count: duplicatesRemovedCount,
          opted_out_stripped_count: optedOutStrippedCount,
          invalid_rejected_count: invalidRejectedCount,
          dispatch_type: "scheduled",
          status: "processing",
          scheduled_at: scheduledAt,
        })
        .select()
        .single();

      if (insertErr) {
        if (isDuplicateIdempotencyError(insertErr)) {
          return new Response(
            JSON.stringify({
              error: "Duplicate request blocked by Idempotency Key guardrail.",
            }),
            {
              status: 409,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
        throw insertErr;
      }

      const sendmodeScheduledDate = formatSendmodeDate(String(scheduledAt));

      // Write-Ahead State Machine Step 2: Call Sendmode POST /schedule-bulk
      let providerRes: Response;
      try {
        providerRes = await fetch(`${SENDMODE_BASE_URL}/schedule-bulk`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${Deno.env.get("SMS_API")}`,
            "Content-Type": "application/json",
            "X-Idempotency-Key": String(idempotencyKey),
          },
          body: JSON.stringify({
            to: validPhoneArray,
            senderid: trimmedSenderId,
            message: messageText,
            senddate: sendmodeScheduledDate,
          }),
        });
      } catch (networkErr) {
        console.error(
          "[Sendmode API Network Error - POST /schedule-bulk]",
          networkErr
        );
        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: "Network error communicating with Sendmode API.",
          })
          .eq("id", processingCampaign.id);

        return new Response(
          JSON.stringify({
            error: "Bad Gateway: Provider campaign scheduling failed.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (!providerRes.ok) {
        const failureReason = await logSendmodeError(
          providerRes,
          "POST /schedule-bulk"
        );
        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: failureReason,
          })
          .eq("id", processingCampaign.id);

        return new Response(
          JSON.stringify({
            error: "Bad Gateway: Provider campaign scheduling failed.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      let providerData: Record<string, unknown> = {};
      try {
        providerData = await providerRes.json();
      } catch {
        providerData = {};
      }

      const providerCampaignId = String(
        providerData.batchId ??
          providerData.batch_id ??
          providerData.providerCampaignId ??
          providerData.scheduleId ??
          providerData.id ??
          `sched-${Date.now()}`
      );

      // Write-Ahead State Machine Step 3: UPDATE row to `status = 'scheduled'`
      const { data: finalizedCampaign, error: updateErr } = await supabaseAdmin
        .from("sms_campaigns")
        .update({
          status: "scheduled",
          provider_campaign_id: providerCampaignId,
        })
        .eq("id", processingCampaign.id)
        .select()
        .single();

      if (updateErr) throw updateErr;

      return new Response(
        JSON.stringify({
          success: true,
          providerCampaignId,
          recipientsCount: validCount,
          segmentCount: trueSegments,
          totalCost: serverCalculatedCost,
          campaign: finalizedCampaign,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // Action 5: `schedule_delete` -> POST /schedule-delete
    // =========================================================================
    if (action === "schedule_delete") {
      const { campaignId, providerCampaignId } = body;

      let { data: campaign, error: fetchErr } = await supabaseAdmin
        .from("sms_campaigns")
        .select("*")
        .eq("id", campaignId)
        .maybeSingle();

      if ((!campaign || fetchErr) && providerCampaignId) {
        const fallbackRes = await supabaseAdmin
          .from("sms_campaigns")
          .select("*")
          .eq("provider_campaign_id", providerCampaignId)
          .maybeSingle();
        campaign = fallbackRes.data;
        fetchErr = fallbackRes.error;
      }

      if (fetchErr || !campaign) {
        return new Response(JSON.stringify({ error: "Campaign not found" }), {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const diffMinutes =
        (Date.parse(String(campaign.scheduled_at)) - Date.now()) /
        (1000 * 60);
      if (diffMinutes < 5) {
        return new Response(
          JSON.stringify({
            error:
              "CANCELLATION_LOCK_ACTIVE: Cannot cancel within 5 minutes of dispatch.",
          }),
          {
            status: 423,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const targetBatchId = String(
        campaign.provider_campaign_id ?? providerCampaignId ?? ""
      ).trim();

      if (!targetBatchId) {
        return new Response(
          JSON.stringify({
            error:
              "Missing provider batchId for scheduled campaign cancellation.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // STEP 1: Call Sendmode `POST /schedule-delete` FIRST
      let delRes: Response;
      try {
        delRes = await fetch(`${SENDMODE_BASE_URL}/schedule-delete`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${Deno.env.get("SMS_API")}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            batchId: targetBatchId,
          }),
        });
      } catch (networkErr) {
        console.error(
          "[Sendmode API Network Error - POST /schedule-delete]",
          networkErr
        );
        return new Response(
          JSON.stringify({
            error:
              "Bad Gateway: Provider Schedule Delete failed; Supabase status left unchanged.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (!delRes.ok) {
        await logSendmodeError(delRes, "POST /schedule-delete");
        return new Response(
          JSON.stringify({
            error:
              "Bad Gateway: Provider Schedule Delete failed; Supabase status left unchanged.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // STEP 2: Only after Sendmode confirms, mark `cancelled` in Supabase
      const { data: updated, error: updateErr } = await supabaseAdmin
        .from("sms_campaigns")
        .update({
          status: "cancelled",
          cancelled_at: new Date().toISOString(),
        })
        .eq("id", campaign.id)
        .select()
        .single();

      if (updateErr) throw updateErr;

      return new Response(
        JSON.stringify({ success: true, campaign: updated }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // =========================================================================
    // Action 6: Opt-Out Number (`optout_number`)
    // =========================================================================
    if (action === "optout_number") {
      const { phoneNumber } = body;
      const cleanPhone = String(phoneNumber ?? "").trim();

      if (!E164_REGEX.test(cleanPhone)) {
        return new Response(
          JSON.stringify({
            error: "Phone number must be strict E.164 format.",
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const { error: upsertErr } = await supabaseAdmin
        .from("opt_outs")
        .upsert(
          {
            phone: cleanPhone,
            reason: "User opted out",
            source: "manual_admin",
            provider_synced: true,
          },
          { onConflict: "phone" }
        );

      if (upsertErr) throw upsertErr;

      return new Response(
        JSON.stringify({ success: true, phone: cleanPhone }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    return new Response(JSON.stringify({ error: "Unknown action" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    if (error instanceof SendmodeGatewayError) {
      return new Response(
        JSON.stringify({
          error: error.message,
        }),
        {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    console.error(error);
    return new Response(
      JSON.stringify({
        error: "Internal server error processing SMS request.",
      }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
