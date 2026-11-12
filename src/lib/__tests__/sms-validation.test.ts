import { describe, expect, it, vi, afterEach } from "vitest";
import {
  analyzeSmsSegments,
  canCancelScheduledCampaign,
  evaluateCreditGate,
  isValidE164,
  sanitizeRecipients,
  validateScheduleTimestamp,
} from "../sms-validation";
import { supabase } from "../supabase";
import { calculateMessageDetails, ApiServices } from "../../components/BulkSMSManager";

describe("Dilli Haat SMS Campaign (DHSC) — Guardrail & Validation Suite", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("1. Enforces strict E.164 validation, deduplication, and opt-out stripping", () => {
    expect(isValidE164("+919810012345")).toBe(true);
    expect(isValidE164("+14155552671")).toBe(true);
    expect(isValidE164("98100-12345")).toBe(false);
    expect(isValidE164("+0123456789")).toBe(false);

    const raw = [
      "+919810012345",
      "+919810012345", // duplicate
      "+919810000101", // opted-out
      "98100-INVALID", // invalid E.164
      "+919810054321",
    ];
    const optOuts = ["+919810000101"];

    const res = sanitizeRecipients(raw, optOuts);
    expect(res.validBillableNumbers).toEqual(["+919810012345", "+919810054321"]);
    expect(res.duplicatesRemoved).toEqual(["+919810012345"]);
    expect(res.optedOutStripped).toEqual(["+919810000101"]);
    expect(res.invalidFormatRejected).toEqual(["98100-INVALID"]);
  });

  it("2. Accurately calculates GSM-7 (including extended chars like €) vs UCS-2 and blocks >5 segments", () => {
    const singleGsm = calculateMessageDetails("Hello Dilli Haat €10 voucher");
    expect(singleGsm.encoding).toBe("GSM-7");
    // "Hello Dilli Haat €10 voucher" is 28 chars, but '€' is 2 septets -> 29 effective units
    expect(singleGsm.charCount).toBe(28);
    expect(singleGsm.effectiveUnits).toBe(29);
    expect(singleGsm.segmentCount).toBe(1);

    const backtickUcs2 = calculateMessageDetails("Backtick ` forces UCS-2");
    expect(backtickUcs2.encoding).toBe("UCS-2 (Unicode)");

    const multiGsm = analyzeSmsSegments("A".repeat(161));
    expect(multiGsm.encoding).toBe("GSM-7");
    expect(multiGsm.segments).toBe(2);

    const singleUcs2 = analyzeSmsSegments("Hello 🔥");
    expect(singleUcs2.encoding).toBe("UCS-2");
    expect(singleUcs2.segments).toBe(1);

    const overflowGsm = calculateMessageDetails("A".repeat(153 * 5 + 1));
    expect(overflowGsm.segmentCount).toBe(6);
    expect(overflowGsm.isOverLimit).toBe(true);
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

  it("4. Enforces 15-minute future scheduling buffer and 5-minute cancellation lock", () => {
    const now = Date.now();
    const tenMinAhead = new Date(now + 10 * 60 * 1000).toISOString();
    const twentyMinAhead = new Date(now + 20 * 60 * 1000).toISOString();

    expect(validateScheduleTimestamp(tenMinAhead, now).valid).toBe(false);
    expect(validateScheduleTimestamp(twentyMinAhead, now).valid).toBe(true);

    const threeMinAhead = new Date(now + 3 * 60 * 1000).toISOString();
    expect(canCancelScheduledCampaign(threeMinAhead, now).allowed).toBe(false);
    expect(canCancelScheduledCampaign(twentyMinAhead, now).allowed).toBe(true);
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
