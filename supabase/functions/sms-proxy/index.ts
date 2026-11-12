/**
 * Supabase Edge Function: `sms-proxy`
 * Zero-Trust server-side proxy to the third-party `sms-rest 3.0` Bulk SMS API.
 *
 * Security Hardening (Phase 3 & Phase 4):
 * - Strict CORS allowlist (`http://localhost:3000` and production Vercel URL only).
 * - Cryptographic JWT verification via `supabaseAdmin.auth.getUser(token)` before any logic executes.
 * - Server-side `analyzeSmsSegments` & `totalCost` recalculation (zero trust of client-supplied segment/cost values).
 * - Server-side `opt_outs` blacklist verification (`403 Forbidden`) and 30-second per-user rate limiting (`429 Too Many Requests`) on `send_single_sms`.
 * - Enforces idempotency, E.164 sanitization, 15-minute schedule buffer, 5-minute cancel lock, and two-step `Schedule Delete`.
 */

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.47.0";

const SMS_PROVIDER_BASE_URL =
  Deno.env.get("SMS_REST_3_BASE_URL") ?? "https://api.sms-rest.example/v3";
const SMS_PROVIDER_API_KEY = Deno.env.get("SMS_REST_3_API_KEY") ?? "";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const DEFAULT_STARTING_CREDITS = Number(
  Deno.env.get("DEFAULT_SMS_CREDITS") ?? 15000
);

const PRODUCTION_VERCEL_URL =
  Deno.env.get("PRODUCTION_VERCEL_URL") ??
  Deno.env.get("ALLOWED_ORIGIN") ??
  "https://dilli-haat-sms-campaign.vercel.app";

const ALLOWED_ORIGINS = new Set<string>([
  "http://localhost:3000",
  PRODUCTION_VERCEL_URL,
]);

const isLiveProviderConfigured =
  Boolean(SMS_PROVIDER_API_KEY) &&
  !SMS_PROVIDER_BASE_URL.includes(".example");

const E164_REGEX = /^\+[1-9]\d{6,14}$/;
const MAX_ALLOWED_SEGMENTS = 5;

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
 * Never trust client-supplied `segmentCount` or `totalCost`.
 */
function analyzeSmsSegments(text: string): SegmentAnalysis {
  if (!text || text.length === 0) {
    return {
      encoding: "GSM-7",
      rawCharacterCount: 0,
      effectiveUnitCount: 0,
      segments: 0,
      maxUnitsPerSegment: 160,
      singleSegmentLimit: 160,
      multiSegmentLimit: 153,
      remainingInCurrentSegment: 160,
      maxAllowedUnitsTotal: 153 * MAX_ALLOWED_SEGMENTS,
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
  let maxUnitsPerSegment = singleSegmentLimit;

  if (effectiveUnitCount === 0) {
    segments = 0;
  } else if (effectiveUnitCount <= singleSegmentLimit) {
    segments = 1;
    maxUnitsPerSegment = singleSegmentLimit;
  } else {
    segments = Math.ceil(effectiveUnitCount / multiSegmentLimit);
    maxUnitsPerSegment = multiSegmentLimit;
  }

  const currentCapacity =
    segments <= 1 ? singleSegmentLimit : segments * multiSegmentLimit;
  const remainingInCurrentSegment = Math.max(
    0,
    currentCapacity - effectiveUnitCount
  );
  const maxAllowedUnitsTotal = multiSegmentLimit * MAX_ALLOWED_SEGMENTS;
  const isOverMaxSegments = segments > MAX_ALLOWED_SEGMENTS;

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

async function computeCreditLedger(
  supabaseAdmin: ReturnType<typeof createClient>
): Promise<{
  liveBalance: number;
  reservedCredits: number;
  effectiveAvailableCredits: number;
}> {
  const { data: campaignRows, error: dbErr } = await supabaseAdmin
    .from<CampaignCreditRow>("sms_campaigns")
    .select("status, estimated_credits");

  if (dbErr) throw dbErr;

  const rows: CampaignCreditRow[] = campaignRows ?? [];
  const reservedCredits = rows
    .filter((r: CampaignCreditRow) => r.status === "scheduled")
    .reduce(
      (sum: number, r: CampaignCreditRow) =>
        sum + Number(r.estimated_credits ?? 0),
      0
    );
  const sentCredits = rows
    .filter((r: CampaignCreditRow) => r.status === "sent")
    .reduce(
      (sum: number, r: CampaignCreditRow) =>
        sum + Number(r.estimated_credits ?? 0),
      0
    );

  let liveBalance = Math.max(0, DEFAULT_STARTING_CREDITS - sentCredits);

  if (isLiveProviderConfigured) {
    const providerRes = await fetch(
      `${SMS_PROVIDER_BASE_URL}/credits/balance`,
      {
        headers: { Authorization: `Bearer ${SMS_PROVIDER_API_KEY}` },
      }
    );
    if (!providerRes.ok) {
      throw new Error("Failed to fetch credit balance from SMS provider.");
    }
    const providerJson = await providerRes.json();
    liveBalance = Number(
      providerJson.balance ?? providerJson.liveBalance ?? liveBalance
    );
  }

  return {
    liveBalance,
    reservedCredits,
    effectiveAvailableCredits: liveBalance - reservedCredits,
  };
}

serve(async (req: Request): Promise<Response> => {
  const { corsHeaders, isAllowedOrigin } = getCorsConfig(req);

  if (!isAllowedOrigin) {
    return new Response(
      JSON.stringify({ error: "Forbidden: Origin not permitted by CORS policy." }),
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
    // PHASE 3 TASK 2: Cryptographic JWT Verification (Zero-Trust Identity Check)
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
          error:
            authError?.message || "Unauthorized: Invalid or expired session token.",
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

    // 1. Check Credit Balance + Compute Effective Available Credits
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

    // 2. Send Single SMS / Schedule Single SMS (`send_single_sms`)
    if (action === "send_single_sms") {
      const { idempotencyKey, phoneNumber, messageBody, message, scheduledAt } =
        body;

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

      // PHASE 4 TASK 1: Server-side segment & cost recalculation (never trust client `segments` / `totalCost`)
      const resolvedMessage = String(messageBody ?? message ?? "");
      const segmentAnalysis = analyzeSmsSegments(resolvedMessage);
      const trueSegmentCount = segmentAnalysis.segments;
      const trueTotalCost = trueSegmentCount;

      if (
        !resolvedMessage ||
        trueSegmentCount < 1 ||
        trueSegmentCount > MAX_ALLOWED_SEGMENTS ||
        segmentAnalysis.isOverMaxSegments
      ) {
        return new Response(
          JSON.stringify({
            error: `Message must be between 1 and ${MAX_ALLOWED_SEGMENTS} segments.`,
          }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // PHASE 4 TASK 3: Server-Side Opt-Out Verification (returns 403 Forbidden if blacklisted)
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

      // PHASE 4 TASK 4: Basic Rate Limiting Guardrail (max 1 single SMS per 30 seconds per user)
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

      const ledger = await computeCreditLedger(supabaseAdmin);
      if (ledger.effectiveAvailableCredits < trueTotalCost) {
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

      let messageId = `${scheduledAt ? "sched-msg" : "msg"}-${Date.now()}`;
      let newBalance = scheduledAt
        ? ledger.liveBalance
        : Math.max(0, ledger.liveBalance - trueTotalCost);

      if (isLiveProviderConfigured) {
        const endpoint = scheduledAt
          ? `${SMS_PROVIDER_BASE_URL}/messages/schedule`
          : `${SMS_PROVIDER_BASE_URL}/messages/send`;

        const providerRes = await fetch(endpoint, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${SMS_PROVIDER_API_KEY}`,
            "Content-Type": "application/json",
            ...(idempotencyKey
              ? { "X-Idempotency-Key": String(idempotencyKey) }
              : {}),
          },
          body: JSON.stringify({
            to: cleanPhone,
            message: resolvedMessage,
            segments: trueSegmentCount,
            totalCost: trueTotalCost,
            scheduledAt: scheduledAt ?? undefined,
          }),
        });

        if (!providerRes.ok) {
          return new Response(
            JSON.stringify({
              error: "Provider failed to dispatch single SMS.",
            }),
            {
              status: 502,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }

        const providerData = await providerRes.json();
        messageId = providerData.messageId ?? providerData.id ?? messageId;
        if (
          typeof providerData.newBalance === "number" ||
          typeof providerData.balance === "number"
        ) {
          newBalance = Number(
            providerData.newBalance ?? providerData.balance
          );
        }
      }

      // Record single SMS dispatch in `sms_campaigns` for audit trail and 30s rate-limit tracking
      const { error: singleInsertErr } = await supabaseAdmin
        .from("sms_campaigns")
        .insert({
          idempotency_key: idempotencyKey || crypto.randomUUID(),
          user_id: authenticatedUser.id,
          name: "Single Test SMS",
          sender_id: "DILLIHAAT",
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

      if (singleInsertErr) throw singleInsertErr;

      return new Response(
        JSON.stringify({
          success: true,
          messageId,
          segmentCount: trueSegmentCount,
          totalCost: trueTotalCost,
          newBalance,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 3. Send Bulk SMS Immediately (`send_bulk_sms`)
    if (action === "send_bulk_sms") {
      const {
        idempotencyKey,
        name,
        senderId = "DILLIHAAT",
        audienceId = "all",
        audienceName = "All Contacts",
        recipientsCount,
        rawRecipientCount,
        duplicatesRemoved = 0,
        optedOutStripped = 0,
        invalidRejected = 0,
        message,
      } = body;

      const trimmedName = String(name ?? "").trim();
      const validCount = Number(recipientsCount ?? 0);
      const messageText = String(message ?? "");

      // PHASE 4 TASK 1: Server-side segment & cost recalculation (ignores client `segmentCount` and `totalCost`)
      const segmentAnalysis = analyzeSmsSegments(messageText);
      const trueSegments = segmentAnalysis.segments;
      const trueTotalCost = validCount * trueSegments;

      if (!idempotencyKey || !trimmedName || !messageText || validCount <= 0) {
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

      if (
        trueSegments < 1 ||
        trueSegments > MAX_ALLOWED_SEGMENTS ||
        segmentAnalysis.isOverMaxSegments
      ) {
        return new Response(
          JSON.stringify({ error: "Campaign exceeds 5-segment ceiling." }),
          {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Check idempotency key in Supabase before dispatching
      const { data: existingDup } = await supabaseAdmin
        .from("sms_campaigns")
        .select("id")
        .eq("idempotency_key", String(idempotencyKey))
        .maybeSingle();

      if (existingDup) {
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

      const ledger = await computeCreditLedger(supabaseAdmin);
      if (ledger.effectiveAvailableCredits < trueTotalCost) {
        return new Response(
          JSON.stringify({
            error: `Insufficient effective credits: need ${trueTotalCost}, have ${ledger.effectiveAvailableCredits}.`,
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      let batchId = `batch-${Date.now()}`;
      let newBalance = Math.max(0, ledger.liveBalance - trueTotalCost);

      if (isLiveProviderConfigured) {
        const providerRes = await fetch(
          `${SMS_PROVIDER_BASE_URL}/campaigns/send`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${SMS_PROVIDER_API_KEY}`,
              "Content-Type": "application/json",
              "X-Idempotency-Key": String(idempotencyKey),
            },
            body: JSON.stringify({
              idempotencyKey,
              name: trimmedName,
              senderId,
              recipientsCount: validCount,
              segmentCount: trueSegments,
              totalCost: trueTotalCost,
              message: messageText,
            }),
          }
        );

        if (!providerRes.ok) {
          return new Response(
            JSON.stringify({ error: "Provider bulk SMS dispatch failed." }),
            {
              status: 502,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }

        const providerData = await providerRes.json();
        batchId =
          providerData.batchId ??
          providerData.providerCampaignId ??
          providerData.id ??
          batchId;
        if (
          typeof providerData.newBalance === "number" ||
          typeof providerData.balance === "number"
        ) {
          newBalance = Number(
            providerData.newBalance ?? providerData.balance
          );
        }
      }

      const rawCount = Math.max(
        validCount,
        Number(rawRecipientCount ?? validCount)
      );

      const { data: insertedCampaign, error: insertErr } = await supabaseAdmin
        .from("sms_campaigns")
        .insert({
          idempotency_key: idempotencyKey,
          user_id: authenticatedUser.id,
          name: trimmedName,
          sender_id: senderId,
          audience_id: audienceId,
          audience_name: audienceName,
          message: messageText,
          encoding: segmentAnalysis.encoding,
          character_count: segmentAnalysis.rawCharacterCount,
          effective_unit_count: segmentAnalysis.effectiveUnitCount,
          segments: trueSegments,
          raw_recipient_count: rawCount,
          valid_recipient_count: validCount,
          duplicates_removed_count: Number(duplicatesRemoved),
          opted_out_stripped_count: Number(optedOutStripped),
          invalid_rejected_count: Number(invalidRejected),
          dispatch_type: "immediate",
          status: "sent",
          provider_campaign_id: batchId,
          dispatched_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (insertErr) throw insertErr;

      return new Response(
        JSON.stringify({
          success: true,
          batchId,
          segmentCount: trueSegments,
          totalCost: trueTotalCost,
          newBalance,
          campaign: insertedCampaign,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 4. Schedule Bulk SMS (`schedule_bulk_sms`)
    if (action === "schedule_bulk_sms") {
      const {
        idempotencyKey,
        name,
        senderId = "DILLIHAAT",
        audienceId = "all",
        audienceName = "All Contacts",
        recipientsCount,
        rawRecipientCount,
        duplicatesRemoved = 0,
        optedOutStripped = 0,
        invalidRejected = 0,
        message,
        scheduledAt,
      } = body;

      const trimmedName = String(name ?? "").trim();
      const validCount = Number(recipientsCount ?? 0);
      const messageText = String(message ?? "");

      // PHASE 4 TASK 1: Server-side segment & cost recalculation (ignores client `segmentCount` and `totalCost`)
      const segmentAnalysis = analyzeSmsSegments(messageText);
      const trueSegments = segmentAnalysis.segments;
      const trueTotalCost = validCount * trueSegments;

      if (
        !idempotencyKey ||
        !trimmedName ||
        !messageText ||
        !scheduledAt ||
        validCount <= 0
      ) {
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

      if (
        trueSegments < 1 ||
        trueSegments > MAX_ALLOWED_SEGMENTS ||
        segmentAnalysis.isOverMaxSegments
      ) {
        return new Response(
          JSON.stringify({ error: "Campaign exceeds 5-segment ceiling." }),
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

      // Check idempotency key in Supabase before scheduling
      const { data: existingDup } = await supabaseAdmin
        .from("sms_campaigns")
        .select("id")
        .eq("idempotency_key", String(idempotencyKey))
        .maybeSingle();

      if (existingDup) {
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

      const ledger = await computeCreditLedger(supabaseAdmin);
      if (ledger.effectiveAvailableCredits < trueTotalCost) {
        return new Response(
          JSON.stringify({
            error: `Insufficient effective credits: need ${trueTotalCost}, have ${ledger.effectiveAvailableCredits}.`,
          }),
          {
            status: 402,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      let providerCampaignId = `sched-${Date.now()}`;

      if (isLiveProviderConfigured) {
        const providerRes = await fetch(
          `${SMS_PROVIDER_BASE_URL}/campaigns/schedule`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${SMS_PROVIDER_API_KEY}`,
              "Content-Type": "application/json",
              "X-Idempotency-Key": String(idempotencyKey),
            },
            body: JSON.stringify({
              idempotencyKey,
              name: trimmedName,
              senderId,
              recipientsCount: validCount,
              segmentCount: trueSegments,
              totalCost: trueTotalCost,
              message: messageText,
              scheduledAt,
            }),
          }
        );

        if (!providerRes.ok) {
          return new Response(
            JSON.stringify({ error: "Provider campaign scheduling failed." }),
            {
              status: 502,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }

        const providerData = await providerRes.json();
        providerCampaignId =
          providerData.providerCampaignId ??
          providerData.id ??
          providerCampaignId;
      }

      const rawCount = Math.max(
        validCount,
        Number(rawRecipientCount ?? validCount)
      );

      const { data: insertedCampaign, error: insertErr } = await supabaseAdmin
        .from("sms_campaigns")
        .insert({
          idempotency_key: idempotencyKey,
          user_id: authenticatedUser.id,
          name: trimmedName,
          sender_id: senderId,
          audience_id: audienceId,
          audience_name: audienceName,
          message: messageText,
          encoding: segmentAnalysis.encoding,
          character_count: segmentAnalysis.rawCharacterCount,
          effective_unit_count: segmentAnalysis.effectiveUnitCount,
          segments: trueSegments,
          raw_recipient_count: rawCount,
          valid_recipient_count: validCount,
          duplicates_removed_count: Number(duplicatesRemoved),
          opted_out_stripped_count: Number(optedOutStripped),
          invalid_rejected_count: Number(invalidRejected),
          dispatch_type: "scheduled",
          status: "scheduled",
          provider_campaign_id: providerCampaignId,
          scheduled_at: scheduledAt,
        })
        .select()
        .single();

      if (insertErr) throw insertErr;

      return new Response(
        JSON.stringify({
          success: true,
          providerCampaignId,
          segmentCount: trueSegments,
          totalCost: trueTotalCost,
          campaign: insertedCampaign,
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 5. Two-Step Atomic Cancellation (`Schedule Delete` -> Supabase `cancelled`)
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

      // STEP 1: Call sms-rest 3.0 `Schedule Delete` FIRST
      if (isLiveProviderConfigured && campaign.provider_campaign_id) {
        const delRes = await fetch(
          `${SMS_PROVIDER_BASE_URL}/campaigns/schedule/${encodeURIComponent(
            String(campaign.provider_campaign_id)
          )}`,
          {
            method: "DELETE",
            headers: { Authorization: `Bearer ${SMS_PROVIDER_API_KEY}` },
          }
        );

        if (!delRes.ok) {
          return new Response(
            JSON.stringify({
              error:
                "Provider Schedule Delete failed; Supabase status left unchanged.",
            }),
            {
              status: 502,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
      }

      // STEP 2: Only after provider confirms, mark `cancelled` in Supabase
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

    // 6. Opt-Out Number (`optout_number`)
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

      if (isLiveProviderConfigured) {
        const providerRes = await fetch(`${SMS_PROVIDER_BASE_URL}/optouts`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${SMS_PROVIDER_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ phone: cleanPhone }),
        });

        if (!providerRes.ok) {
          return new Response(
            JSON.stringify({
              error: "Failed to sync opt-out number with SMS provider.",
            }),
            {
              status: 502,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          );
        }
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
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: err instanceof Error ? err.message : "Unexpected error",
      }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
