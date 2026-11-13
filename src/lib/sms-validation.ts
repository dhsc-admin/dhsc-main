import { z } from "zod";

/**
 * NON-NEGOTIABLE GUARDRAIL CONSTANTS
 * The server automatically appends `" Stop: dhsc.uk/x"` (16 chars) to every SMS.
 * Standard 1-segment limits (160 GSM-7 / 70 UCS-2) are reduced by 16 characters
 * on the frontend: 144 characters for GSM-7 and 54 characters for UCS-2.
 */
export const OPT_OUT_SUFFIX = " Stop: dhsc.uk/x";
export const OPT_OUT_SUFFIX_LENGTH = 16;
export const MAX_GSM7_CHARACTERS = 160 - OPT_OUT_SUFFIX_LENGTH; // 144
export const MAX_UCS2_CHARACTERS = 70 - OPT_OUT_SUFFIX_LENGTH; // 54
export const MAX_ALLOWED_CHARACTERS = MAX_GSM7_CHARACTERS; // 144
export const MAX_ALLOWED_SEGMENTS = 1;
export const DEFAULT_SENDER_ID = "Dilli Haat";
export const MIN_SCHEDULE_BUFFER_MINUTES = 15;
export const MIN_CANCEL_BUFFER_MINUTES = 5;

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

export type SmsEncoding = "GSM-7" | "UCS-2";

export interface SegmentAnalysis {
  encoding: SmsEncoding;
  rawCharacterCount: number;
  /** For GSM-7, extended chars count as 2 septets. For UCS-2, UTF-16 code units are used. */
  effectiveUnitCount: number;
  segments: number;
  maxUnitsPerSegment: number;
  singleSegmentLimit: number;
  multiSegmentLimit: number;
  remainingInCurrentSegment: number;
  maxAllowedUnitsTotal: number;
  isOverMaxSegments: boolean;
  nonGsmCharacters: string[];
  extendedGsmCharacters: string[];
}

/**
 * Analyzes an SMS message string for GSM-7 vs UCS-2 (Unicode) encoding,
 * exact septet / UTF-16 code unit length, and segment boundaries.
 */
export function analyzeSmsSegments(text: string): SegmentAnalysis {
  if (!text || text.length === 0) {
    return {
      encoding: "GSM-7",
      rawCharacterCount: 0,
      effectiveUnitCount: 0,
      segments: 0,
      maxUnitsPerSegment: MAX_GSM7_CHARACTERS,
      singleSegmentLimit: MAX_GSM7_CHARACTERS,
      multiSegmentLimit: 153,
      remainingInCurrentSegment: MAX_GSM7_CHARACTERS,
      maxAllowedUnitsTotal: MAX_GSM7_CHARACTERS,
      isOverMaxSegments: false,
      nonGsmCharacters: [],
      extendedGsmCharacters: [],
    };
  }

  const nonGsmSet = new Set<string>();
  const extendedSet = new Set<string>();
  let gsmSeptets = 0;

  // Iterate over Unicode code points (handles surrogate pairs like emojis properly)
  const codePoints = Array.from(text);

  for (const char of codePoints) {
    if (GSM7_BASIC_CHARS.has(char)) {
      gsmSeptets += 1;
    } else if (GSM7_EXTENDED_CHARS.has(char)) {
      gsmSeptets += 2;
      extendedSet.add(char);
    } else {
      nonGsmSet.add(char);
    }
  }

  const isUcs2 = nonGsmSet.size > 0;
  const encoding: SmsEncoding = isUcs2 ? "UCS-2" : "GSM-7";

  const rawSingleSegmentLimit = isUcs2 ? 70 : 160;
  const adjustedSingleSegmentLimit = isUcs2
    ? MAX_UCS2_CHARACTERS
    : MAX_GSM7_CHARACTERS;
  const multiSegmentLimit = isUcs2 ? 67 : 153;

  // In UCS-2, SMS gateways count UTF-16 code units (text.length in JS),
  // meaning Astral plane emojis (surrogate pairs) take 2 UCS-2 characters (4 bytes).
  const effectiveUnitCount = isUcs2 ? text.length : gsmSeptets;

  let segments = 0;
  const maxUnitsPerSegment = adjustedSingleSegmentLimit;

  if (effectiveUnitCount === 0) {
    segments = 0;
  } else if (effectiveUnitCount <= adjustedSingleSegmentLimit) {
    segments = 1;
  } else if (effectiveUnitCount <= rawSingleSegmentLimit) {
    // Exceeds user limit once the 16-character opt-out suffix is appended (2 segments total)
    segments = 2;
  } else {
    segments = Math.ceil(
      (effectiveUnitCount + OPT_OUT_SUFFIX_LENGTH) / multiSegmentLimit
    );
  }

  const maxAllowedUnitsTotal = adjustedSingleSegmentLimit;
  const remainingInCurrentSegment = Math.max(
    0,
    adjustedSingleSegmentLimit - effectiveUnitCount
  );
  const isOverMaxSegments =
    segments > MAX_ALLOWED_SEGMENTS ||
    effectiveUnitCount > adjustedSingleSegmentLimit ||
    codePoints.length > adjustedSingleSegmentLimit;

  return {
    encoding,
    rawCharacterCount: codePoints.length,
    effectiveUnitCount,
    segments,
    maxUnitsPerSegment,
    singleSegmentLimit: adjustedSingleSegmentLimit,
    multiSegmentLimit,
    remainingInCurrentSegment,
    maxAllowedUnitsTotal,
    isOverMaxSegments,
    nonGsmCharacters: Array.from(nonGsmSet),
    extendedGsmCharacters: Array.from(extendedSet),
  };
}

/**
 * Strict UK E.164 Phone Number Validation
 * Must start with '+44' followed by 9 or 10 digits.
 */
export const E164_REGEX = /^\+44\d{9,10}$/;

export function isValidE164(phone: string): boolean {
  return E164_REGEX.test(phone.trim());
}

export interface RecipientSanitizationResult {
  rawInputCount: number;
  validBillableNumbers: string[];
  duplicatesRemoved: string[];
  optedOutStripped: string[];
  invalidFormatRejected: string[];
}

/**
 * Sanitizes, validates E.164, deduplicates, and cross-checks against opt_outs table.
 */
export function sanitizeRecipients(
  rawPhones: string[],
  optOutNumbers: Iterable<string>
): RecipientSanitizationResult {
  const optOutSet = new Set(
    Array.from(optOutNumbers).map((n) => n.trim())
  );

  const seenValid = new Set<string>();
  const validBillableNumbers: string[] = [];
  const duplicatesRemoved: string[] = [];
  const optedOutStripped: string[] = [];
  const invalidFormatRejected: string[] = [];

  let rawInputCount = 0;

  for (const raw of rawPhones) {
    // Strip invisible whitespace but do NOT guess country codes (strict E.164 requirement)
    const normalized = raw.trim().replace(/[\s()-]/g, "");
    if (!normalized) continue;
    rawInputCount++;

    if (!isValidE164(normalized)) {
      invalidFormatRejected.push(raw.trim());
      continue;
    }

    if (seenValid.has(normalized)) {
      duplicatesRemoved.push(normalized);
      continue;
    }

    seenValid.add(normalized);

    if (optOutSet.has(normalized)) {
      optedOutStripped.push(normalized);
      continue;
    }

    validBillableNumbers.push(normalized);
  }

  return {
    rawInputCount,
    validBillableNumbers,
    duplicatesRemoved,
    optedOutStripped,
    invalidFormatRejected,
  };
}

/**
 * Parses a free-form string of phone numbers (newline, comma, or semicolon separated)
 */
export function parsePhoneListString(input: string): string[] {
  if (!input.trim()) return [];
  return input
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Timezone & Scheduling Guardrails (UTC enforcement)
 */
export function validateScheduleTimestamp(
  scheduledAtIsoUtc: string,
  nowMs: number = Date.now()
): { valid: boolean; diffMinutes: number; error?: string } {
  const parsedMs = Date.parse(scheduledAtIsoUtc);
  if (Number.isNaN(parsedMs)) {
    return {
      valid: false,
      diffMinutes: 0,
      error: "Invalid UTC timestamp format.",
    };
  }

  const diffMs = parsedMs - nowMs;
  const diffMinutes = diffMs / (1000 * 60);

  if (diffMinutes < MIN_SCHEDULE_BUFFER_MINUTES) {
    return {
      valid: false,
      diffMinutes,
      error: `Scheduled dispatch must be at least ${MIN_SCHEDULE_BUFFER_MINUTES} minutes in the future (currently ${Math.floor(diffMinutes)}m).`,
    };
  }

  return { valid: true, diffMinutes };
}

/**
 * Cancellation Guardrail: Cannot cancel within 5 minutes of scheduled execution
 */
export function canCancelScheduledCampaign(
  scheduledAtIsoUtc: string,
  nowMs: number = Date.now()
): { allowed: boolean; minutesRemaining: number; reason?: string } {
  const parsedMs = Date.parse(scheduledAtIsoUtc);
  if (Number.isNaN(parsedMs)) {
    return {
      allowed: false,
      minutesRemaining: 0,
      reason: "Invalid scheduled timestamp.",
    };
  }

  const diffMinutes = (parsedMs - nowMs) / (1000 * 60);

  if (diffMinutes <= 0) {
    return {
      allowed: false,
      minutesRemaining: diffMinutes,
      reason: "Campaign dispatch window has already passed.",
    };
  }

  if (diffMinutes < MIN_CANCEL_BUFFER_MINUTES) {
    return {
      allowed: false,
      minutesRemaining: diffMinutes,
      reason: `Safety lock active: Cannot cancel within ${MIN_CANCEL_BUFFER_MINUTES} minutes of dispatch (${diffMinutes.toFixed(1)}m remaining) to prevent provider race conditions.`,
    };
  }

  return {
    allowed: true,
    minutesRemaining: diffMinutes,
  };
}

/**
 * Strict Credit Gatekeeping Calculation
 */
export interface CreditAuditResult {
  liveBalance: number;
  reservedQueuedCredits: number;
  effectiveAvailableCredits: number;
  campaignCreditCost: number;
  remainingAfterCampaign: number;
  hasQueueDeficit: boolean;
  queueDeficitAmount: number;
  canAffordCampaign: boolean;
  campaignShortfall: number;
}

export function evaluateCreditGate(
  liveBalance: number,
  reservedQueuedCredits: number,
  campaignCreditCost: number
): CreditAuditResult {
  const effectiveAvailableCredits = liveBalance - reservedQueuedCredits;
  const hasQueueDeficit = reservedQueuedCredits > liveBalance;
  const queueDeficitAmount = Math.max(0, reservedQueuedCredits - liveBalance);
  const canAffordCampaign =
    campaignCreditCost > 0
      ? campaignCreditCost <= effectiveAvailableCredits
      : effectiveAvailableCredits >= 0;
  const campaignShortfall = Math.max(0, campaignCreditCost - Math.max(0, effectiveAvailableCredits));
  const remainingAfterCampaign = effectiveAvailableCredits - campaignCreditCost;

  return {
    liveBalance,
    reservedQueuedCredits,
    effectiveAvailableCredits,
    campaignCreditCost,
    remainingAfterCampaign,
    hasQueueDeficit,
    queueDeficitAmount,
    canAffordCampaign,
    campaignShortfall,
  };
}

/**
 * Zod Schemas shared between Frontend Form and Edge Function Payload Validation
 */
export const TestSmsSchema = z.object({
  recipientPhone: z
    .string()
    .trim()
    .regex(
      E164_REGEX,
      "Must be a valid UK number starting with +44 (e.g., +447700900077)"
    ),
  message: z
    .string()
    .min(1, "Message body cannot be empty")
    .max(
      MAX_GSM7_CHARACTERS,
      `Message cannot exceed ${MAX_GSM7_CHARACTERS} characters (reserves ${OPT_OUT_SUFFIX_LENGTH} chars for opt-out suffix).`
    )
    .superRefine((val, ctx) => {
      const analysis = analyzeSmsSegments(val);
      if (analysis.isOverMaxSegments) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Message exceeds 1 segment with opt-out suffix (max ${analysis.maxAllowedUnitsTotal} ${analysis.encoding} characters).`,
        });
      }
    }),
  scheduleMode: z.enum(["immediate", "scheduled"]).default("immediate"),
  scheduledAtUtc: z.string().optional(),
  idempotencyKey: z.string().uuid("Valid UUID v4 idempotency_key is required"),
});

export const CampaignFormSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(3, "Campaign name must be at least 3 characters")
      .max(80, "Campaign name cannot exceed 80 characters"),
    senderId: z
      .string()
      .trim()
      .min(3, "Sender ID is required")
      .max(15, "Sender ID must be <= 15 characters")
      .default(DEFAULT_SENDER_ID),
    audienceId: z.string().min(1, "Please select a recipient audience or custom list"),
    customRecipientsRaw: z
      .string()
      .optional()
      .refine(
        (val) => {
          if (!val || !val.trim()) return true;
          const phones = parsePhoneListString(val);
          return phones.every((p) => E164_REGEX.test(p.replace(/[\s()-]/g, "")));
        },
        {
          message:
            "Must be a valid UK number starting with +44 (e.g., +447700900077)",
        }
      ),
    message: z
      .string()
      .min(1, "SMS message body is required")
      .max(
        MAX_GSM7_CHARACTERS,
        `SMS message cannot exceed ${MAX_GSM7_CHARACTERS} characters (reserves ${OPT_OUT_SUFFIX_LENGTH} chars for opt-out suffix).`
      )
      .superRefine((val, ctx) => {
        const analysis = analyzeSmsSegments(val);
        if (analysis.isOverMaxSegments) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Message exceeds 1 segment with opt-out suffix (max ${analysis.maxAllowedUnitsTotal} ${analysis.encoding} characters).`,
          });
        }
      }),
    dispatchType: z.enum(["immediate", "scheduled"]),
    scheduledAtUtc: z.string().optional(),
    idempotencyKey: z.string().uuid("Invalid UUID v4 idempotency key"),
  })
  .superRefine((data, ctx) => {
    if (data.dispatchType === "scheduled") {
      if (!data.scheduledAtUtc) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["scheduledAtUtc"],
          message: "Scheduled execution UTC time is required for future campaigns.",
        });
        return;
      }
      const check = validateScheduleTimestamp(data.scheduledAtUtc);
      if (!check.valid) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["scheduledAtUtc"],
          message: check.error || "Invalid schedule time.",
        });
      }
    }
  });

export type CampaignFormValues = z.infer<typeof CampaignFormSchema>;
export type TestSmsFormValues = z.infer<typeof TestSmsSchema>;
