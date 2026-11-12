/**
 * Supabase Edge Function: `sms-proxy`
 * Phase 6: Sendmode API Integration & Zero-Trust Architecture
 *
 * Security & Functional Guarantees:
 * - Sendmode Base URL: `https://sms-rest.sendmode.dev`
 * - Sendmode Auth Header: `Authorization: ${Deno.env.get("SMS_API")}` (no "Bearer" prefix)
 * - Strict CORS allowlist (`http://localhost:3000` and production Vercel domain)
 * - Cryptographic JWT verification via `supabaseAdmin.auth.getUser(token)` (`401 Unauthorized` if invalid)
 * - Zero-Trust server-side audience resolution (`public.contacts`, `customPhones`, `public.opt_outs` stripping)
 * - Zero-Trust server-side segment & credit math (`analyzeSmsSegments`, `MAX_ALLOWED_CHARACTERS = 150`, `MAX_ALLOWED_SEGMENTS = 1`)
 * - Server-side credit gate via `GET /3.0/balance` and `sms_campaigns` reserved credits (`402 Payment Required`)
 * - 100-recipient batch chunking via `Promise.all` on `POST /3.0/send/bulk` and `POST /3.0/schedule/bulk`
 * - JSON body `{ "request_id": "..." }` on `DELETE /3.0/schedule`
 * - Write-Ahead state machine (`status = 'processing'` -> `'sent'` / `'scheduled'` or `'failed'`)
 * - Sanitized `500` error responses with server-side `console.error` logging
 */

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import {
  createClient,
  type SupabaseClient,
} from "https://esm.sh/@supabase/supabase-js@2.47.0";

const SENDMODE_BASE_URL = "https://sms-rest.sendmode.dev";
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
const SENDMODE_BATCH_LIMIT = 100;

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
 * Splits an array of phone numbers into chunks of at most `size` (default 100).
 */
function chunkPhoneNumbers(
  phones: string[],
  size: number = SENDMODE_BATCH_LIMIT
): string[][] {
  const chunks: string[][] = [];
  for (let i = 0; i < phones.length; i += size) {
    chunks.push(phones.slice(i, i + size));
  }
  return chunks;
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

/**
 * Calls Sendmode `GET /3.0/balance` and computes reserved credits from
 * `scheduled` (and `processing`) rows in `public.sms_campaigns`.
 */
async function computeCreditLedger(
  supabaseAdmin: SupabaseClient
): Promise<{
  liveBalance: number;
  reservedCredits: number;
  effectiveAvailableCredits: number;
}> {
  const balanceRes = await fetch(`${SENDMODE_BASE_URL}/3.0/balance`, {
    method: "GET",
    headers: {
      Authorization: `${Deno.env.get("SMS_API")}`,
    },
  });

  if (!balanceRes.ok) {
    throw new Error(
      `Failed to fetch credit balance from Sendmode (HTTP ${balanceRes.status}).`
    );
  }

  const balanceJson = await balanceRes.json();
  const parsedBalance = parseInt(String(balanceJson?.balance ?? 0), 10);
  const liveBalance = Number.isNaN(parsedBalance) ? 0 : parsedBalance;

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

  return {
    liveBalance,
    reservedCredits,
    effectiveAvailableCredits: liveBalance - reservedCredits,
  };
}

/**
 * Resolves the actual recipient E.164 phone list strictly on the server:
 * - Ignores client-supplied `recipientsCount` for billing/dispatch.
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
        body.recipientsCount ??
        500;
      const limitN = Math.floor(Number(rawLimit));
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
    // 1. Cryptographic JWT Verification (Zero-Trust Identity Check)
    // =========================================================================
    const authHeader =
      req.headers.get("Authorization") ?? req.headers.get("authorization") ?? "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim();

    if (!token) {
      return new Response(
        JSON.stringify({ error: "Unauthorized: Missing JWT token." }),
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
    // A. Check Credit Balance (`GET /3.0/balance`)
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
    // B. Send Single SMS (`POST /3.0/send`)
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

      const resolvedMessage = String(messageBody ?? message ?? "");
      const segmentAnalysis = analyzeSmsSegments(resolvedMessage);
      const actualSegments = segmentAnalysis.segments;
      const calculatedCost = actualSegments;

      if (
        !resolvedMessage ||
        segmentAnalysis.rawCharacterCount > MAX_ALLOWED_CHARACTERS ||
        actualSegments < 1 ||
        actualSegments > MAX_ALLOWED_SEGMENTS ||
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

      // Server-side opt-out verification
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

      // Per-user 30-second rate limit for single SMS
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

      // Credit Gate via GET /3.0/balance
      const ledger = await computeCreditLedger(supabaseAdmin);
      if (ledger.liveBalance - ledger.reservedCredits < calculatedCost) {
        return new Response(
          JSON.stringify({
            error: "Insufficient effective credits for single SMS.",
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Write-Ahead Pre-dispatch Lock (`status = 'processing'`)
      const { data: processingRow, error: insertErr } = await supabaseAdmin
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
          segments: actualSegments,
          raw_recipient_count: 1,
          valid_recipient_count: 1,
          duplicates_removed_count: 0,
          opted_out_stripped_count: 0,
          invalid_rejected_count: 0,
          dispatch_type: scheduledAt ? "scheduled" : "immediate",
          status: "processing",
          scheduled_at: scheduledAt
            ? new Date(String(scheduledAt)).toISOString()
            : null,
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

      // Call Sendmode `POST /3.0/send`
      let providerRes: Response;
      try {
        providerRes = await fetch(`${SENDMODE_BASE_URL}/3.0/send`, {
          method: "POST",
          headers: {
            Authorization: `${Deno.env.get("SMS_API")}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            sender_id: trimmedSenderId,
            message: resolvedMessage,
            mobile_number: cleanPhone,
          }),
        });
      } catch (networkErr) {
        console.error(networkErr);
        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: "Network error communicating with Sendmode API.",
          })
          .eq("id", processingRow.id);

        return new Response(
          JSON.stringify({ error: "Sendmode failed to dispatch single SMS." }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      if (!providerRes.ok) {
        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: `Sendmode /3.0/send returned HTTP ${providerRes.status}.`,
          })
          .eq("id", processingRow.id);

        return new Response(
          JSON.stringify({ error: "Sendmode failed to dispatch single SMS." }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const providerData = await providerRes.json();
      const requestId = String(providerData?.request_id ?? "");
      const newBalance = Math.max(0, ledger.liveBalance - calculatedCost);

      const { error: updateErr } = await supabaseAdmin
        .from("sms_campaigns")
        .update({
          status: scheduledAt ? "scheduled" : "sent",
          provider_campaign_id: requestId,
          dispatched_at: scheduledAt ? null : new Date().toISOString(),
        })
        .eq("id", processingRow.id);

      if (updateErr) throw updateErr;

      return new Response(
        JSON.stringify({
          success: true,
          request_id: requestId,
          messageId: requestId,
          segmentCount: actualSegments,
          totalCost: calculatedCost,
          newBalance,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // C. Send Bulk SMS (`POST /3.0/send/bulk` with 100-number chunking)
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

      // 1. Server-side segment & character analysis (Zero-Trust)
      const segmentAnalysis = analyzeSmsSegments(messageText);
      const actualSegments = segmentAnalysis.segments;

      if (
        segmentAnalysis.rawCharacterCount > MAX_ALLOWED_CHARACTERS ||
        actualSegments < 1 ||
        actualSegments > MAX_ALLOWED_SEGMENTS ||
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

      // 2. Fetch Recipients Server-Side (Zero-Trust; ignores frontend `recipientsCount`)
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

      // 3. Calculate Cost Server-Side
      const calculatedCost = actualSegments * validPhoneArray.length;

      // 4. Credit Gate via `GET /3.0/balance`
      const ledger = await computeCreditLedger(supabaseAdmin);
      if (ledger.liveBalance - ledger.reservedCredits < calculatedCost) {
        return new Response(
          JSON.stringify({
            error: `Insufficient effective credits: need ${calculatedCost}, have ${ledger.liveBalance - ledger.reservedCredits
              }.`,
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // 5. Write-Ahead Pre-dispatch Lock (`status = 'processing'`)
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
          segments: actualSegments,
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

      // 6. Chunk `validPhoneArray` into batches of 100 and dispatch via `Promise.all`
      const phoneBatches = chunkPhoneNumbers(
        validPhoneArray,
        SENDMODE_BATCH_LIMIT
      );
      let joinedRequestIds = "";

      try {
        const batchRequestIds = await Promise.all(
          phoneBatches.map(async (batch) => {
            const providerRes = await fetch(
              `${SENDMODE_BASE_URL}/3.0/send/bulk`,
              {
                method: "POST",
                headers: {
                  Authorization: `${Deno.env.get("SMS_API")}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  sender_id: trimmedSenderId,
                  message: messageText,
                  mobile_numbers: batch,
                }),
              }
            );

            if (!providerRes.ok) {
              throw new Error(
                `Sendmode /3.0/send/bulk returned HTTP ${providerRes.status}.`
              );
            }

            const providerData = await providerRes.json();
            return String(providerData?.request_id ?? "").trim();
          })
        );

        joinedRequestIds = batchRequestIds.filter(Boolean).join(",");
      } catch (providerErr) {
        console.error(providerErr);
        const failureReason =
          providerErr instanceof Error
            ? providerErr.message
            : "Sendmode bulk SMS dispatch failed.";

        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: failureReason,
          })
          .eq("id", processingCampaign.id);

        return new Response(
          JSON.stringify({ error: "Sendmode bulk SMS dispatch failed." }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // 7. Post-dispatch Update (`status = 'sent'`, `provider_campaign_id = joinedRequestIds`)
      const { data: finalizedCampaign, error: updateErr } = await supabaseAdmin
        .from("sms_campaigns")
        .update({
          status: "sent",
          provider_campaign_id: joinedRequestIds,
          dispatched_at: new Date().toISOString(),
        })
        .eq("id", processingCampaign.id)
        .select()
        .single();

      if (updateErr) throw updateErr;

      const newBalance = Math.max(0, ledger.liveBalance - calculatedCost);

      return new Response(
        JSON.stringify({
          success: true,
          request_id: joinedRequestIds,
          batchId: joinedRequestIds,
          recipientsCount: validCount,
          segmentCount: actualSegments,
          totalCost: calculatedCost,
          newBalance,
          campaign: finalizedCampaign,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // D. Schedule Bulk SMS (`POST /3.0/schedule/bulk`)
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

      // 1. Server-side segment & character analysis (Zero-Trust)
      const segmentAnalysis = analyzeSmsSegments(messageText);
      const actualSegments = segmentAnalysis.segments;

      if (
        segmentAnalysis.rawCharacterCount > MAX_ALLOWED_CHARACTERS ||
        actualSegments < 1 ||
        actualSegments > MAX_ALLOWED_SEGMENTS ||
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

      const parsedScheduleMs = Date.parse(String(scheduledAt));
      const diffMinutes = (parsedScheduleMs - Date.now()) / (1000 * 60);
      if (Number.isNaN(parsedScheduleMs) || diffMinutes < 15) {
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

      // Format `schedule_date` as an ISO 8601 string in UTC
      const scheduleDateIsoUtc = new Date(parsedScheduleMs).toISOString();

      // 2. Fetch Recipients Server-Side (Zero-Trust; ignores frontend `recipientsCount`)
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

      // 3. Calculate Cost Server-Side
      const calculatedCost = actualSegments * validPhoneArray.length;

      // 4. Credit Gate via `GET /3.0/balance`
      const ledger = await computeCreditLedger(supabaseAdmin);
      if (ledger.liveBalance - ledger.reservedCredits < calculatedCost) {
        return new Response(
          JSON.stringify({
            error: `Insufficient effective credits: need ${calculatedCost}, have ${ledger.liveBalance - ledger.reservedCredits
              }.`,
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // 5. Write-Ahead Pre-dispatch Lock (`status = 'processing'`)
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
          segments: actualSegments,
          raw_recipient_count: rawRecipientCount,
          valid_recipient_count: validCount,
          duplicates_removed_count: duplicatesRemovedCount,
          opted_out_stripped_count: optedOutStrippedCount,
          invalid_rejected_count: invalidRejectedCount,
          dispatch_type: "scheduled",
          status: "processing",
          scheduled_at: scheduleDateIsoUtc,
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

      // 6. Chunk `validPhoneArray` into batches of 100 and schedule via `Promise.all`
      const phoneBatches = chunkPhoneNumbers(
        validPhoneArray,
        SENDMODE_BATCH_LIMIT
      );
      let joinedRequestIds = "";

      try {
        const batchRequestIds = await Promise.all(
          phoneBatches.map(async (batch) => {
            const providerRes = await fetch(
              `${SENDMODE_BASE_URL}/3.0/schedule/bulk`,
              {
                method: "POST",
                headers: {
                  Authorization: `${Deno.env.get("SMS_API")}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  sender_id: trimmedSenderId,
                  message: messageText,
                  mobile_numbers: batch,
                  schedule_date: scheduleDateIsoUtc,
                }),
              }
            );

            if (!providerRes.ok) {
              throw new Error(
                `Sendmode /3.0/schedule/bulk returned HTTP ${providerRes.status}.`
              );
            }

            const providerData = await providerRes.json();
            return String(providerData?.request_id ?? "").trim();
          })
        );

        joinedRequestIds = batchRequestIds.filter(Boolean).join(",");
      } catch (providerErr) {
        console.error(providerErr);
        const failureReason =
          providerErr instanceof Error
            ? providerErr.message
            : "Sendmode bulk campaign scheduling failed.";

        await supabaseAdmin
          .from("sms_campaigns")
          .update({
            status: "failed",
            failure_reason: failureReason,
          })
          .eq("id", processingCampaign.id);

        return new Response(
          JSON.stringify({
            error: "Sendmode campaign scheduling failed.",
          }),
          {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // 7. Post-dispatch Update (`status = 'scheduled'`, `provider_campaign_id = joinedRequestIds`)
      const { data: finalizedCampaign, error: updateErr } = await supabaseAdmin
        .from("sms_campaigns")
        .update({
          status: "scheduled",
          provider_campaign_id: joinedRequestIds,
        })
        .eq("id", processingCampaign.id)
        .select()
        .single();

      if (updateErr) throw updateErr;

      return new Response(
        JSON.stringify({
          success: true,
          request_id: joinedRequestIds,
          providerCampaignId: joinedRequestIds,
          recipientsCount: validCount,
          segmentCount: actualSegments,
          totalCost: calculatedCost,
          campaign: finalizedCampaign,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // =========================================================================
    // E. Schedule Delete (`DELETE /3.0/schedule` with JSON body `{ "request_id": "..." }`)
    // =========================================================================
    if (action === "schedule_delete") {
      const { campaignId, providerCampaignId, request_id } = body;

      let { data: campaign, error: fetchErr } = await supabaseAdmin
        .from("sms_campaigns")
        .select("*")
        .eq("id", campaignId)
        .maybeSingle();

      if ((!campaign || fetchErr) && (providerCampaignId || request_id)) {
        const lookupId = String(providerCampaignId ?? request_id);
        const fallbackRes = await supabaseAdmin
          .from("sms_campaigns")
          .select("*")
          .eq("provider_campaign_id", lookupId)
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

      const rawRequestIds = String(
        campaign.provider_campaign_id ?? providerCampaignId ?? request_id ?? ""
      )
        .split(",")
        .map((id) => id.trim())
        .filter(Boolean);

      if (rawRequestIds.length > 0) {
        try {
          await Promise.all(
            rawRequestIds.map(async (reqId) => {
              const delRes = await fetch(`${SENDMODE_BASE_URL}/3.0/schedule`, {
                method: "DELETE",
                headers: {
                  Authorization: `${Deno.env.get("SMS_API")}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({ request_id: reqId }),
              });

              if (!delRes.ok) {
                throw new Error(
                  `Sendmode DELETE /3.0/schedule failed with HTTP ${delRes.status}.`
                );
              }
            })
          );
        } catch (delErr) {
          console.error(delErr);
          return new Response(
            JSON.stringify({
              error:
                "Sendmode Schedule Delete failed; Supabase status left unchanged.",
            }),
            {
              status: 502,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
      }

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
    // F. Opt-Out Number (`optout_number`)
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
