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
  CampaignFormSchema,
  canCancelScheduledCampaign,
  DEFAULT_SENDER_ID,
  evaluateCreditGate,
  isValidE164,
  londonLocalToUtcDate,
  londonLocalToUtcIso,
  MAX_ALLOWED_CHARACTERS,
  MAX_ALLOWED_SEGMENTS,
  MAX_UCS2_CHARACTERS,
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

  it("1. Enforces strict UK (+44) E.164 validation, deduplication, and opt-out stripping", () => {
    expect(isValidE164("+447700900077")).toBe(true);
    expect(isValidE164("+442079460991")).toBe(true);
    expect(isValidE164("+14155552671")).toBe(false);
    expect(isValidE164("+919810012345")).toBe(false);
    expect(isValidE164("98100-12345")).toBe(false);
    expect(isValidE164("+0123456789")).toBe(false);

    const raw = [
      "+447700900077",
      "+447700900077", // duplicate
      "+447700900099", // opted-out
      "+919810012345", // non-UK rejected
      "+14155552671", // non-UK rejected
      "07700-INVALID", // invalid E.164
      "+447700900078",
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

  it("2. Accurately calculates GSM-7 (including extended chars like €) vs UCS-2 and enforces 144 GSM-7 / 54 UCS-2 / 1-segment limit", () => {
    expect(OPT_OUT_SUFFIX).toBe(" Stop: dhsc.uk/x");
    expect(OPT_OUT_SUFFIX.length).toBe(16);
    expect(MAX_ALLOWED_CHARACTERS).toBe(144);
    expect(MAX_UCS2_CHARACTERS).toBe(54);
    expect(MAX_ALLOWED_SEGMENTS).toBe(1);
    expect(DEFAULT_SENDER_ID).toBe("Dilli Haat");

    const singleGsm = calculateMessageDetails("Hello Dilli Haat €10 voucher");
    expect(singleGsm.encoding).toBe("GSM-7");
    // "Hello Dilli Haat €10 voucher" is 28 chars, but '€' is 2 septets -> 29 effective units
    expect(singleGsm.charCount).toBe(28);
    expect(singleGsm.effectiveUnits).toBe(29);
    expect(singleGsm.perSegmentLimit).toBe(144);
    expect(singleGsm.remainingInSegment).toBe(144 - 29);
    expect(singleGsm.segmentCount).toBe(1);
    expect(singleGsm.isOverLimit).toBe(false);

    const exact144Gsm = calculateMessageDetails("A".repeat(144));
    expect(exact144Gsm.charCount).toBe(144);
    expect(exact144Gsm.remainingInSegment).toBe(0);
    expect(exact144Gsm.segmentCount).toBe(1);
    expect(exact144Gsm.isOverLimit).toBe(false);

    const over144Gsm = calculateMessageDetails("A".repeat(145));
    expect(over144Gsm.charCount).toBe(145);
    expect(over144Gsm.isOverLimit).toBe(true);

    const backtickUcs2 = calculateMessageDetails("Backtick ` forces UCS-2");
    expect(backtickUcs2.encoding).toBe("UCS-2 (Unicode)");
    expect(backtickUcs2.perSegmentLimit).toBe(54);

    const exact54Ucs2 = calculateMessageDetails("`" + "A".repeat(53));
    expect(exact54Ucs2.charCount).toBe(54);
    expect(exact54Ucs2.remainingInSegment).toBe(0);
    expect(exact54Ucs2.segmentCount).toBe(1);
    expect(exact54Ucs2.isOverLimit).toBe(false);

    const over54Ucs2 = calculateMessageDetails("`" + "A".repeat(54));
    expect(over54Ucs2.charCount).toBe(55);
    expect(over54Ucs2.isOverLimit).toBe(true);

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

  it("4. Enforces 15-minute future scheduling buffer, 5-minute cancellation lock, and Europe/London <-> UTC conversion", () => {
    const now = Date.now();
    const tenMinAhead = new Date(now + 10 * 60 * 1000).toISOString();
    const twentyMinAhead = new Date(now + 20 * 60 * 1000).toISOString();

    expect(validateScheduleTimestamp(tenMinAhead, now).valid).toBe(false);
    expect(validateScheduleTimestamp(twentyMinAhead, now).valid).toBe(true);

    const threeMinAhead = new Date(now + 3 * 60 * 1000).toISOString();
    expect(canCancelScheduledCampaign(threeMinAhead, now).allowed).toBe(false);
    expect(canCancelScheduledCampaign(twentyMinAhead, now).allowed).toBe(true);

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

    // Default scheduler input helper generates Europe/London local string
    const bstBaseMs = Date.parse("2026-07-15T13:00:00Z"); // 14:00 BST
    expect(getFutureDatetimeLocal(30, bstBaseMs)).toBe("2026-07-15T14:30");

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
