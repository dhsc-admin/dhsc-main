import { describe, expect, it, vi, afterEach } from "vitest";

vi.hoisted(() => {
  if (
    !process.env.NEXT_PUBLIC_SUPABASE_URL ||
    !process.env.NEXT_PUBLIC_SUPABASE_URL.startsWith("http")
  ) {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://example.supabase.co";
  }
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||= "test-anon-key";
});

import {
  analyzeSmsSegments,
  appendOptOutSuffix,
  CampaignFormSchema,
  canCancelScheduledCampaign,
  DEFAULT_SENDER_ID,
  evaluateCreditGate,
  hasForbiddenAngleBrackets,
  isValidE164,
  londonLocalToUtcDate,
  londonLocalToUtcIso,
  MAX_ALLOWED_CHARACTERS,
  MAX_ALLOWED_SEGMENTS,
  MAX_UCS2_CHARACTERS,
  normalizeUkPhone,
  OPT_OUT_SUFFIX,
  sanitizeRecipients,
  utcToLondonDate,
  utcToLondonLocalString,
  validateScheduleTimestamp,
} from "../sms-validation";
import { supabase } from "../supabase";
import {
  calculateMessageDetails,
  ApiServices,
  formatDate,
  getFutureDatetimeLocal,
} from "../../components/BulkSMSManager";

describe("Dilli Haat SMS Campaign (DHSC) — Guardrail & Validation Suite", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("1. Enforces strict UK (+44) E.164 validation, UK phone normalization (07.../0044.../44...), deduplication, and opt-out stripping", () => {
    expect(normalizeUkPhone("07700 900 077")).toBe("+447700900077");
    expect(normalizeUkPhone("00447700900077")).toBe("+447700900077");
    expect(normalizeUkPhone("447700900077")).toBe("+447700900077");
    expect(normalizeUkPhone("+447700900077")).toBe("+447700900077");

    expect(isValidE164("+447700900077")).toBe(true);
    expect(isValidE164(normalizeUkPhone("07700 900 077"))).toBe(true);
    expect(isValidE164("+442079460991")).toBe(true);
    expect(isValidE164("+14155552671")).toBe(false);
    expect(isValidE164("+919810012345")).toBe(false);
    expect(isValidE164("98100-12345")).toBe(false);
    expect(isValidE164("+0123456789")).toBe(false);

    const raw = [
      "+447700900077",
      "07700 900 077", // normalized duplicate of +447700900077
      "07700900099", // normalized opted-out (+447700900099)
      "+919810012345", // non-UK rejected
      "+14155552671", // non-UK rejected
      "07700-INVALID", // invalid E.164
      "00447700900078", // normalized valid (+447700900078)
    ];
    const optOuts = ["+447700900099"];

    const res = sanitizeRecipients(raw, optOuts);
    expect(res.validBillableNumbers).toEqual(["+447700900077", "+447700900078"]);
    expect(res.duplicatesRemoved).toEqual(["+447700900077"]);
    expect(res.optedOutStripped).toEqual(["+447700900099"]);
    expect(res.invalidFormatRejected).toEqual([
      "+919810012345",
      "+14155552671",
      "07700-INVALID",
    ]);
  });

  it("2. Accurately calculates GSM-7 vs UCS-2 with idempotent opt-out suffix and disallows '<' and '>'", () => {
    expect(OPT_OUT_SUFFIX).toBe(" Stop: dhsc.uk/x");
    expect(OPT_OUT_SUFFIX.length).toBe(16);
    expect(MAX_ALLOWED_CHARACTERS).toBe(144);
    expect(MAX_UCS2_CHARACTERS).toBe(54);
    expect(MAX_ALLOWED_SEGMENTS).toBe(1);
    expect(DEFAULT_SENDER_ID).toBe("Dilli Haat");

    // Idempotent opt-out suffix helper
    expect(appendOptOutSuffix("Hello")).toBe("Hello Stop: dhsc.uk/x");
    expect(appendOptOutSuffix("Hello Stop: dhsc.uk/x")).toBe(
      "Hello Stop: dhsc.uk/x"
    );
    expect(appendOptOutSuffix("Hello stop: dhsc.uk/x  ")).toBe(
      "Hello stop: dhsc.uk/x"
    );

    const singleGsm = calculateMessageDetails("Hello Dilli Haat €10 voucher");
    expect(singleGsm.encoding).toBe("GSM-7");
    // "Hello Dilli Haat €10 voucher" (28 chars, 29 septets) + " Stop: dhsc.uk/x" (16 chars) = 44 chars, 45 septets
    expect(singleGsm.charCount).toBe(44);
    expect(singleGsm.effectiveUnits).toBe(45);
    expect(singleGsm.perSegmentLimit).toBe(160);
    expect(singleGsm.remainingInSegment).toBe(160 - 45);
    expect(singleGsm.segmentCount).toBe(1);
    expect(singleGsm.isOverLimit).toBe(false);

    // Pre-appended suffix is not double-counted
    const alreadySuffixed = calculateMessageDetails(
      "Hello Dilli Haat €10 voucher Stop: dhsc.uk/x"
    );
    expect(alreadySuffixed.charCount).toBe(44);
    expect(alreadySuffixed.remainingInSegment).toBe(160 - 45);
    expect(alreadySuffixed.segmentCount).toBe(1);

    const exact144Gsm = calculateMessageDetails("A".repeat(144));
    expect(exact144Gsm.charCount).toBe(160);
    expect(exact144Gsm.remainingInSegment).toBe(0);
    expect(exact144Gsm.segmentCount).toBe(1);
    expect(exact144Gsm.isOverLimit).toBe(false);

    const over144Gsm = calculateMessageDetails("A".repeat(145));
    expect(over144Gsm.charCount).toBe(161);
    expect(over144Gsm.isOverLimit).toBe(true);

    const backtickUcs2 = calculateMessageDetails("Backtick ` forces UCS-2");
    expect(backtickUcs2.encoding).toBe("UCS-2 (Unicode)");
    expect(backtickUcs2.perSegmentLimit).toBe(70);

    const exact54Ucs2 = calculateMessageDetails("`" + "A".repeat(53));
    expect(exact54Ucs2.charCount).toBe(70);
    expect(exact54Ucs2.remainingInSegment).toBe(0);
    expect(exact54Ucs2.segmentCount).toBe(1);
    expect(exact54Ucs2.isOverLimit).toBe(false);

    const over54Ucs2 = calculateMessageDetails("`" + "A".repeat(54));
    expect(over54Ucs2.charCount).toBe(71);
    expect(over54Ucs2.isOverLimit).toBe(true);

    // Disallow '<' and '>' characters (Sendmode pattern: [^<>]*)
    expect(hasForbiddenAngleBrackets("Discount <50%>")).toBe(true);
    const angleMsg = calculateMessageDetails("Offer <VIP>");
    expect(angleMsg.hasForbiddenChars).toBe(true);
    expect(angleMsg.isOverLimit).toBe(true);

    expect(() =>
      CampaignFormSchema.parse({
        name: "Bad Brackets",
        audienceId: "all",
        message: "Hello <world>",
        dispatchType: "immediate",
        idempotencyKey: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
      })
    ).toThrow(/not allowed/i);

    const multiGsm = analyzeSmsSegments("A".repeat(161));
    expect(multiGsm.encoding).toBe("GSM-7");
    expect(multiGsm.segments).toBe(2);
    expect(multiGsm.isOverMaxSegments).toBe(true);

    const singleUcs2 = analyzeSmsSegments("Hello 🔥");
    expect(singleUcs2.encoding).toBe("UCS-2");
    expect(singleUcs2.segments).toBe(1);
    expect(singleUcs2.isOverMaxSegments).toBe(false);

    const multiUcs2 = analyzeSmsSegments("🔥".repeat(36));
    expect(multiUcs2.encoding).toBe("UCS-2");
    expect(multiUcs2.segments).toBe(2);
    expect(multiUcs2.isOverMaxSegments).toBe(true);

    const parsedDefaults = CampaignFormSchema.parse({
      name: "Weekend Haat",
      audienceId: "all",
      message: "Welcome to Dilli Haat!",
      dispatchType: "immediate",
      idempotencyKey: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
    });
    expect(parsedDefaults.senderId).toBe("Dilli Haat");
  });

  it("3. Enforces Strict Credit Gatekeeping: Cost <= (Live Balance - Reserved Credits)", () => {
    const allowed = evaluateCreditGate(15000, 620, 5000);
    expect(allowed.effectiveAvailableCredits).toBe(14380);
    expect(allowed.canAffordCampaign).toBe(true);

    const rejected = evaluateCreditGate(300, 620, 150);
    expect(rejected.hasQueueDeficit).toBe(true);
    expect(rejected.queueDeficitAmount).toBe(320);
    expect(rejected.canAffordCampaign).toBe(false);
  });

  it("4. Enforces 15-minute future scheduling buffer, 15-minute UTC slot interval (:00/:15/:30/:45), 5-minute cancellation lock, and Europe/London <-> UTC conversion", () => {
    const now = Date.parse("2026-07-15T12:00:00Z");
    const tenMinAhead = new Date(now + 10 * 60 * 1000).toISOString(); // 12:10:00Z (<15m)
    const twentyMinUnaligned = new Date(now + 20 * 60 * 1000).toISOString(); // 12:20:00Z (not :00/:15/:30/:45)
    const thirtyMinAligned = new Date(now + 30 * 60 * 1000).toISOString(); // 12:30:00Z (valid)

    expect(validateScheduleTimestamp(tenMinAhead, now).valid).toBe(false);
    expect(validateScheduleTimestamp(twentyMinUnaligned, now).valid).toBe(false);
    expect(validateScheduleTimestamp(twentyMinUnaligned, now).error).toBe(
      "Scheduled time must be on a 15-minute interval (:00, :15, :30, or :45)."
    );
    expect(validateScheduleTimestamp(thirtyMinAligned, now).valid).toBe(true);

    const threeMinAhead = new Date(now + 3 * 60 * 1000).toISOString();
    expect(canCancelScheduledCampaign(threeMinAhead, now).allowed).toBe(false);
    expect(canCancelScheduledCampaign(thirtyMinAligned, now).allowed).toBe(true);

    // British Summer Time (BST = UTC+1): 14:30 in London -> 13:30 UTC
    const bstUtcIso = londonLocalToUtcIso("2026-07-15T14:30");
    expect(bstUtcIso).toBe("2026-07-15T13:30:00Z");
    expect(utcToLondonLocalString("2026-07-15T13:30:00Z")).toBe(
      "2026-07-15T14:30"
    );
    expect(londonLocalToUtcDate("2026-07-15T14:30")?.toISOString()).toBe(
      "2026-07-15T13:30:00.000Z"
    );
    expect(utcToLondonDate("2026-07-15T13:30:00Z")).toBeInstanceOf(Date);

    // Greenwich Mean Time (GMT = UTC+0): 14:30 in London -> 14:30 UTC
    const gmtUtcIso = londonLocalToUtcIso("2026-11-15T14:30");
    expect(gmtUtcIso).toBe("2026-11-15T14:30:00Z");
    expect(utcToLondonLocalString("2026-11-15T14:30:00Z")).toBe(
      "2026-11-15T14:30"
    );

    // Default scheduler input helper snaps forward to the next 15-minute boundary >= 30m ahead in Europe/London
    const bstUnalignedBaseMs = Date.parse("2026-07-15T13:04:00Z"); // 14:04 BST -> +30m = 14:34 BST -> snaps to 14:45 BST
    expect(getFutureDatetimeLocal(30, bstUnalignedBaseMs)).toBe(
      "2026-07-15T14:45"
    );

    // UI formatDate forces Europe/London display
    expect(formatDate("2026-07-15T13:30:00Z", true)).toContain("14:30");
  });

  it("5. Wires ApiServices to supabase.functions.invoke('sms-proxy') and propagates guardrail errors", async () => {
    const invokeSpy = vi
      .spyOn(supabase.functions, "invoke")
      .mockResolvedValueOnce({
        data: { liveBalance: 14200, reservedCredits: 500, effectiveAvailableCredits: 13700 },
        error: null,
      })
      .mockResolvedValueOnce({
        data: null,
        error: { message: "Duplicate request blocked by Idempotency Key guardrail." },
      });

    const balanceRes = await ApiServices.checkCreditBalance();
    expect(invokeSpy).toHaveBeenNthCalledWith(1, "sms-proxy", {
      body: { action: "check_credit_balance" },
    });
    expect(balanceRes.liveBalance).toBe(14200);
    expect(balanceRes.reservedCredits).toBe(500);
    expect(balanceRes.effectiveAvailableCredits).toBe(13700);

    const key = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    await expect(
      ApiServices.sendBulkSMS({
        idempotencyKey: key,
        name: "Duplicate Test",
        recipientsCount: 10,
        segmentCount: 1,
        totalCost: 10,
        message: "Test",
      })
    ).rejects.toThrow(/Idempotency Key/i);

    expect(invokeSpy).toHaveBeenNthCalledWith(
      2,
      "sms-proxy",
      expect.objectContaining({
        body: expect.objectContaining({
          action: "send_bulk_sms",
          idempotencyKey: key,
          name: "Duplicate Test",
          recipientsCount: 10,
          segmentCount: 1,
          totalCost: 10,
          message: "Test",
        }),
      })
    );
  });
});
