"use client";

import React, { useState, useMemo, useEffect, useRef, useCallback } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabase";
import {
  analyzeSmsSegments,
  canCancelScheduledCampaign,
  E164_REGEX,
  evaluateCreditGate,
  isValidE164,
  MAX_ALLOWED_SEGMENTS,
  MIN_CANCEL_BUFFER_MINUTES,
  MIN_SCHEDULE_BUFFER_MINUTES,
  validateScheduleTimestamp,
} from "../lib/sms-validation";

// --- Icons (Inline SVGs for reliable rendering) ---
const Icons = {
  Wallet: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M21 12V7H5a2 2 0 0 1 0-4h14v4" />
      <path d="M3 5v14a2 2 0 0 0 2 2h16v-5" />
      <path d="M18 12a2 2 0 0 0 0 4h4v-4Z" />
    </svg>
  ),
  AlertTriangle: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
  ),
  CheckCircle: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <path d="m9 11 3 3L22 4" />
    </svg>
  ),
  Clock: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </svg>
  ),
  Trash2: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M3 6h18" />
      <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" />
      <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
      <line x1="10" x2="10" y1="11" y2="17" />
      <line x1="14" x2="14" y1="11" y2="17" />
    </svg>
  ),
  Send: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="m22 2-7 20-4-9-9-4Z" />
      <path d="M22 2 11 13" />
    </svg>
  ),
  Smartphone: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <rect width="14" height="20" x="5" y="2" rx="2" ry="2" />
      <path d="M12 18h.01" />
    </svg>
  ),
  X: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </svg>
  ),
  RefreshCw: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
      <path d="M8 16H3v5" />
    </svg>
  ),
  ShieldBan: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
      <path d="m4.243 5.21 14.39 12.472" />
    </svg>
  ),
  Lock: (props: React.SVGProps<SVGSVGElement>) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
};

// --- Types ---
export type AudienceType = "all" | "random" | "top";

export interface CampaignItem {
  id: string;
  idempotencyKey: string;
  name: string;
  status: "scheduled" | "sent" | "cancelled" | "failed";
  recipientsCount: number;
  optedOutStripped: number;
  duplicatesRemoved: number;
  segmentCount: number;
  encoding: string;
  totalCost: number;
  message: string;
  scheduledAt: string;
  providerCampaignId: string;
}

// --- Utilities ---
export const calculateMessageDetails = (text: string) => {
  const analysis = analyzeSmsSegments(text);
  return {
    encoding: analysis.encoding === "UCS-2" ? "UCS-2 (Unicode)" : "GSM-7",
    charCount: analysis.rawCharacterCount,
    effectiveUnits: analysis.effectiveUnitCount,
    segmentCount: analysis.segments,
    perSegmentLimit: analysis.maxUnitsPerSegment,
    remainingInSegment: analysis.remainingInCurrentSegment,
    isOverLimit: analysis.isOverMaxSegments,
    nonGsmCharacters: analysis.nonGsmCharacters,
  };
};

const toSafeIsoString = (dateStr: string): string | null => {
  if (!dateStr) return null;
  const date = new Date(dateStr);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
};

const formatDate = (isoString: string | null, isMounted: boolean): string => {
  if (!isoString) return "Immediate";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "Invalid Date";
  if (!isMounted) {
    // Deterministic UTC string during SSR to avoid hydration mismatch
    return `${isoString.slice(0, 16).replace("T", " ")} UTC`;
  }
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
};

const getFutureDatetimeLocal = (minutesAhead = 30): string => {
  const d = new Date(Date.now() + minutesAhead * 60 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}`;
};

const generateUUID = (): string => {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
};

// ============================================================================
// 🔌 LIVE SUPABASE EDGE FUNCTION INTEGRATION (`sms-proxy` -> `sms-rest 3.0`)
// ============================================================================
// Strictly calls Supabase Edge Functions -> 'sms-rest 3.0'.
// NEVER EXPOSE API KEYS IN THE FRONTEND.
// ============================================================================
export const ApiServices = {
  // 1. Check Credit Balance (sms-rest 3.0)
  checkCreditBalance: async (): Promise<{
    balance: number;
    liveBalance: number;
    reservedCredits: number;
    effectiveAvailableCredits: number;
  }> => {
    const { data, error } = await supabase.functions.invoke("sms-proxy", {
      body: { action: "check_credit_balance" },
    });
    if (error) {
      throw new Error(error.message || "Failed to check credit balance.");
    }
    if (data?.error) {
      throw new Error(data.error);
    }
    const rawBalance = data?.liveBalance ?? data?.balance;
    const liveBalance =
      rawBalance !== undefined &&
      rawBalance !== null &&
      !Number.isNaN(Number(rawBalance))
        ? Number(rawBalance)
        : 15000;
    const reservedCredits = Number(data?.reservedCredits ?? 0);
    const effectiveAvailableCredits = Number(
      data?.effectiveAvailableCredits ?? liveBalance - reservedCredits
    );
    return {
      balance: liveBalance,
      liveBalance,
      reservedCredits,
      effectiveAvailableCredits,
    };
  },

  // 2. Send Single SMS / Schedule Single SMS (sms-rest 3.0)
  sendSingleSMS: async (payload: {
    idempotencyKey: string;
    phoneNumber: string;
    messageBody: string;
    segments: number;
    scheduledAt: string | null;
  }): Promise<{ success: boolean; messageId: string; newBalance?: number }> => {
    const { data, error } = await supabase.functions.invoke("sms-proxy", {
      body: {
        action: "send_single_sms",
        idempotencyKey: payload.idempotencyKey,
        phoneNumber: payload.phoneNumber,
        messageBody: payload.messageBody,
        segments: payload.segments,
        scheduledAt: payload.scheduledAt,
      },
    });
    if (error) {
      throw new Error(error.message || "Failed to send test SMS.");
    }
    if (data?.error) {
      throw new Error(data.error);
    }
    return {
      success: true,
      messageId:
        data?.messageId ??
        `${payload.scheduledAt ? "sched-msg" : "msg"}-${Date.now()}`,
      newBalance:
        typeof data?.newBalance === "number"
          ? data.newBalance
          : typeof data?.liveBalance === "number"
          ? data.liveBalance
          : undefined,
    };
  },

  // 3. Send Bulk SMS (Immediate) (sms-rest 3.0)
  sendBulkSMS: async (payload: {
    idempotencyKey: string;
    name: string;
    recipientsCount: number;
    segmentCount: number;
    totalCost: number;
    message: string;
    encoding?: string;
    characterCount?: number;
    effectiveUnitCount?: number;
    rawRecipientCount?: number;
    duplicatesRemoved?: number;
    optedOutStripped?: number;
    invalidRejected?: number;
    audienceId?: string;
    audienceName?: string;
  }): Promise<{
    success: boolean;
    campaignId?: string;
    batchId: string;
    newBalance?: number;
  }> => {
    const { data, error } = await supabase.functions.invoke("sms-proxy", {
      body: {
        action: "send_bulk_sms",
        idempotencyKey: payload.idempotencyKey,
        name: payload.name,
        recipientsCount: payload.recipientsCount,
        segmentCount: payload.segmentCount,
        totalCost: payload.totalCost,
        message: payload.message,
        encoding: payload.encoding,
        characterCount: payload.characterCount,
        effectiveUnitCount: payload.effectiveUnitCount,
        rawRecipientCount: payload.rawRecipientCount,
        duplicatesRemoved: payload.duplicatesRemoved,
        optedOutStripped: payload.optedOutStripped,
        invalidRejected: payload.invalidRejected,
        audienceId: payload.audienceId,
        audienceName: payload.audienceName,
      },
    });
    if (error) {
      throw new Error(error.message || "Failed to send bulk SMS.");
    }
    if (data?.error) {
      throw new Error(data.error);
    }
    return {
      success: true,
      campaignId: data?.campaign?.id ?? data?.campaignId,
      batchId:
        data?.batchId ??
        data?.campaign?.provider_campaign_id ??
        `batch-${Date.now()}`,
      newBalance:
        typeof data?.newBalance === "number"
          ? data.newBalance
          : typeof data?.liveBalance === "number"
          ? data.liveBalance
          : undefined,
    };
  },

  // 4. Schedule Bulk SMS (Future) (sms-rest 3.0)
  scheduleBulkSMS: async (payload: {
    idempotencyKey: string;
    name: string;
    recipientsCount: number;
    segmentCount: number;
    totalCost: number;
    message: string;
    scheduledAt: string;
    encoding?: string;
    characterCount?: number;
    effectiveUnitCount?: number;
    rawRecipientCount?: number;
    duplicatesRemoved?: number;
    optedOutStripped?: number;
    invalidRejected?: number;
    audienceId?: string;
    audienceName?: string;
  }): Promise<{
    success: boolean;
    campaignId?: string;
    providerCampaignId: string;
  }> => {
    const { data, error } = await supabase.functions.invoke("sms-proxy", {
      body: {
        action: "schedule_bulk_sms",
        idempotencyKey: payload.idempotencyKey,
        name: payload.name,
        recipientsCount: payload.recipientsCount,
        segmentCount: payload.segmentCount,
        totalCost: payload.totalCost,
        message: payload.message,
        scheduledAt: payload.scheduledAt,
        encoding: payload.encoding,
        characterCount: payload.characterCount,
        effectiveUnitCount: payload.effectiveUnitCount,
        rawRecipientCount: payload.rawRecipientCount,
        duplicatesRemoved: payload.duplicatesRemoved,
        optedOutStripped: payload.optedOutStripped,
        invalidRejected: payload.invalidRejected,
        audienceId: payload.audienceId,
        audienceName: payload.audienceName,
      },
    });
    if (error) {
      throw new Error(error.message || "Failed to schedule bulk SMS.");
    }
    if (data?.error) {
      throw new Error(data.error);
    }
    return {
      success: true,
      campaignId: data?.campaign?.id ?? data?.campaignId,
      providerCampaignId:
        data?.providerCampaignId ??
        data?.campaign?.provider_campaign_id ??
        `sched-${Date.now()}`,
    };
  },

  // 5. Schedule Delete (Two-step cancellation on sms-rest 3.0 -> Supabase cancelled)
  scheduleDelete: async (
    campaignId: string,
    providerCampaignId?: string
  ): Promise<{ success: boolean }> => {
    if (!campaignId) {
      throw new Error("Missing campaignId for Schedule Delete.");
    }
    const { data, error } = await supabase.functions.invoke("sms-proxy", {
      body: {
        action: "schedule_delete",
        campaignId,
        providerCampaignId,
      },
    });
    if (error) {
      throw new Error(error.message || "Failed to cancel scheduled campaign.");
    }
    if (data?.error) {
      throw new Error(data.error);
    }
    return { success: true };
  },

  // 6. Optout Number (Syncs number to sms-rest 3.0 blacklist + Supabase opt_outs)
  optoutNumber: async (phoneNumber: string): Promise<{ success: boolean }> => {
    if (!isValidE164(phoneNumber)) {
      throw new Error("Phone number must be strict E.164 format.");
    }
    const { data, error } = await supabase.functions.invoke("sms-proxy", {
      body: {
        action: "optout_number",
        phoneNumber,
      },
    });
    if (error) {
      throw new Error(error.message || "Failed to sync opt-out number.");
    }
    if (data?.error) {
      throw new Error(data.error);
    }
    return { success: true };
  },
};

export interface BulkSMSManagerProps {
  session?: Session | null;
  onSignOut?: () => Promise<void> | void;
}

// --- Main Application Component ---
export default function BulkSMSManager({
  session: propSession,
  onSignOut,
}: BulkSMSManagerProps = {}) {
  const [internalSession, setInternalSession] = useState<Session | null>(
    propSession ?? null
  );
  const [isCheckingAuth, setIsCheckingAuth] = useState<boolean>(!propSession);
  const [loginEmail, setLoginEmail] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [isSigningIn, setIsSigningIn] = useState<boolean>(false);

  const activeSession = propSession ?? internalSession;

  const [isMounted, setIsMounted] = useState(false);
  const [isLoadingData, setIsLoadingData] = useState<boolean>(true);
  const [totalContacts, setTotalContacts] = useState<number>(0);
  const [liveBalance, setLiveBalance] = useState<number>(0);
  const [isSyncingBalance, setIsSyncingBalance] = useState<boolean>(false);
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);
  const [optOuts, setOptOuts] = useState<string[]>([]);

  // Form State
  const [name, setName] = useState("");
  const [audienceType, setAudienceType] = useState<AudienceType>("all");
  const [audienceSize, setAudienceSize] = useState("500");
  const [message, setMessage] = useState("");
  const [isScheduled, setIsScheduled] = useState(false);
  const [scheduleDate, setScheduleDate] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState<string>(
    "00000000-0000-4000-8000-000000000000"
  );
  const [isSubmitting, setIsSubmitting] = useState(false);

  // UI State
  const [activeTab, setActiveTab] = useState<"queued" | "history">("queued");
  const [toasts, setToasts] = useState<
    Array<{ id: string; message: string; type: "success" | "error" }>
  >([]);
  const toastTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map()
  );

  // Test SMS Modal State
  const [testModalOpen, setTestModalOpen] = useState(false);
  const [testPhone, setTestPhone] = useState("+919810012345");
  const [testScheduled, setTestScheduled] = useState(false);
  const [testScheduleDate, setTestScheduleDate] = useState("");
  const [testIdempotencyKey, setTestIdempotencyKey] = useState("");
  const [isSendingTest, setIsSendingTest] = useState(false);

  // Opt-Out Modal State
  const [optOutModalOpen, setOptOutModalOpen] = useState(false);
  const [newOptOutPhone, setNewOptOutPhone] = useState("");
  const [isAddingOptOut, setIsAddingOptOut] = useState(false);

  // Cancel Confirmation Modal State
  const [confirmCancelCampaign, setConfirmCancelCampaign] =
    useState<CampaignItem | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  // Deterministic 0 during SSR to prevent hydration mismatch; updated on mount
  const [nowMs, setNowMs] = useState<number>(0);

  // --- Toast Helper with proper cleanup ---
  const dismissToast = useCallback((id: string) => {
    const timer = toastTimersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      toastTimersRef.current.delete(id);
    }
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    (msg: string, type: "success" | "error" = "success") => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev, { id, message: msg, type }]);
      const timer = setTimeout(() => {
        toastTimersRef.current.delete(id);
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4500);
      toastTimersRef.current.set(id, timer);
    },
    []
  );

  // Synchronize auth session state before allowing any API or database calls
  useEffect(() => {
    let isMountedFlag = true;
    setIsMounted(true);
    setIdempotencyKey(generateUUID());
    setNowMs(Date.now());

    if (propSession) {
      setInternalSession(propSession);
      setIsCheckingAuth(false);
    } else {
      supabase.auth
        .getSession()
        .then(({ data }) => {
          if (isMountedFlag) {
            setInternalSession(data.session ?? null);
            setIsCheckingAuth(false);
          }
        })
        .catch(() => {
          if (isMountedFlag) {
            setInternalSession(null);
            setIsCheckingAuth(false);
          }
        });
    }

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (isMountedFlag) {
        setInternalSession(nextSession ?? null);
        setIsCheckingAuth(false);
      }
    });

    const interval = setInterval(() => setNowMs(Date.now()), 15000);
    const timersMap = toastTimersRef.current;
    return () => {
      isMountedFlag = false;
      subscription.unsubscribe();
      clearInterval(interval);
      timersMap.forEach((timer) => clearTimeout(timer));
      timersMap.clear();
    };
  }, [propSession]);

  // Fetch live Supabase data and balance ONLY after a valid authenticated session is established
  useEffect(() => {
    if (!activeSession?.access_token) {
      return;
    }

    let isCancelled = false;

    const loadInitialBackendData = async () => {
      setIsLoadingData(true);
      try {
        const [contactsRes, optOutsRes, campaignsRes, balanceRes] =
          await Promise.allSettled([
            supabase
              .from("contacts")
              .select("*", { count: "exact", head: true }),
            supabase
              .from("opt_outs")
              .select("phone")
              .order("created_at", { ascending: false }),
            supabase
              .from("sms_campaigns")
              .select("*")
              .order("created_at", { ascending: false }),
            ApiServices.checkCreditBalance(),
          ]);

        if (isCancelled) return;

        if (contactsRes.status === "fulfilled" && !contactsRes.value.error) {
          setTotalContacts(contactsRes.value.count ?? 0);
        }

        if (optOutsRes.status === "fulfilled" && !optOutsRes.value.error) {
          const blacklist = (optOutsRes.value.data ?? [])
            .map((row: { phone?: string }) =>
              typeof row.phone === "string" ? row.phone.trim() : ""
            )
            .filter(Boolean);
          setOptOuts(blacklist);
        }

        let loadedCampaigns: CampaignItem[] = [];
        if (campaignsRes.status === "fulfilled" && !campaignsRes.value.error) {
          loadedCampaigns = (campaignsRes.value.data ?? []).map(
            (row: Record<string, unknown>) => {
              const rawEnc = String(row.encoding ?? "GSM-7");
              const segments = Number(row.segments ?? 1);
              const validCount = Number(row.valid_recipient_count ?? 0);
              return {
                id: String(row.id ?? ""),
                idempotencyKey: String(row.idempotency_key ?? ""),
                name: String(row.name ?? ""),
                status: (row.status as CampaignItem["status"]) ?? "sent",
                recipientsCount: validCount,
                optedOutStripped: Number(row.opted_out_stripped_count ?? 0),
                duplicatesRemoved: Number(row.duplicates_removed_count ?? 0),
                segmentCount: segments,
                encoding: rawEnc === "UCS-2" ? "UCS-2 (Unicode)" : "GSM-7",
                totalCost: Number(
                  row.estimated_credits ?? validCount * segments
                ),
                message: String(row.message ?? ""),
                scheduledAt: String(
                  row.scheduled_at ??
                    row.dispatched_at ??
                    row.created_at ??
                    new Date().toISOString()
                ),
                providerCampaignId: String(row.provider_campaign_id ?? ""),
              };
            }
          );
          setCampaigns(loadedCampaigns);
        }

        if (balanceRes.status === "fulfilled") {
          setLiveBalance(balanceRes.value.liveBalance);
        } else {
          const sentCost = loadedCampaigns
            .filter((c) => c.status === "sent")
            .reduce((sum, c) => sum + c.totalCost, 0);
          setLiveBalance(Math.max(0, 15000 - sentCost));
        }
      } finally {
        if (!isCancelled) {
          setIsLoadingData(false);
        }
      }
    };

    void loadInitialBackendData();

    return () => {
      isCancelled = true;
    };
  }, [activeSession?.access_token]);

  // --- Derived State: Credits & Queue Health ---
  const reservedCredits = useMemo(() => {
    return campaigns
      .filter((c) => c.status === "scheduled")
      .reduce((sum, c) => sum + c.totalCost, 0);
  }, [campaigns]);

  // --- Derived State: Audience Sanitization (Opt-out Filtering) ---
  const audienceSanitization = useMemo(() => {
    const maxOptedInContacts = Math.max(0, totalContacts - optOuts.length);

    if (audienceType === "all") {
      return {
        rawTotal: totalContacts,
        validCount: maxOptedInContacts,
        duplicateCount: 0,
        optedOutCount: Math.min(totalContacts, optOuts.length),
        invalidCount: 0,
      };
    }

    // "random" or "top" subset of opted-in contacts
    const parsed = parseInt(audienceSize, 10);
    const requested = Number.isNaN(parsed) || parsed <= 0 ? 0 : parsed;
    const cappedRaw = Math.min(requested, totalContacts);
    const validCount = Math.min(cappedRaw, maxOptedInContacts);
    const optedOutCount = Math.max(0, cappedRaw - validCount);

    return {
      rawTotal: cappedRaw,
      validCount,
      duplicateCount: 0,
      optedOutCount,
      invalidCount: 0,
    };
  }, [audienceType, audienceSize, optOuts, totalContacts]);

  const recipientCount = audienceSanitization.validCount;

  // --- Derived State: Message Segments & Cost ---
  const msgDetails = useMemo(() => calculateMessageDetails(message), [message]);
  const estimatedCost = recipientCount * msgDetails.segmentCount;

  const creditGate = useMemo(
    () => evaluateCreditGate(liveBalance, reservedCredits, estimatedCost),
    [liveBalance, reservedCredits, estimatedCost]
  );
  const effectiveCredits = creditGate.effectiveAvailableCredits;

  // --- Derived State: 15-Minute Future Buffer Check ---
  const scheduleValidation = useMemo(() => {
    if (!isScheduled) return { valid: true, diffMinutes: 0, error: null };
    if (!scheduleDate) {
      return {
        valid: false,
        diffMinutes: 0,
        error: "Please select a future delivery date and time.",
      };
    }
    const isoUtc = toSafeIsoString(scheduleDate);
    if (!isoUtc) {
      return {
        valid: false,
        diffMinutes: 0,
        error: "Invalid schedule date and time.",
      };
    }
    const referenceMs = isMounted && nowMs > 0 ? nowMs : Date.now();
    const res = validateScheduleTimestamp(isoUtc, referenceMs);
    return {
      valid: res.valid,
      diffMinutes: res.diffMinutes,
      error: res.error ?? null,
    };
  }, [isScheduled, scheduleDate, nowMs, isMounted]);

  const trimmedNameLength = name.trim().length;
  const canSubmit =
    !isLoadingData &&
    trimmedNameLength >= 3 &&
    trimmedNameLength <= 80 &&
    recipientCount > 0 &&
    msgDetails.segmentCount > 0 &&
    !msgDetails.isOverLimit &&
    creditGate.canAffordCampaign &&
    scheduleValidation.valid;

  // --- Actions ---
  const handleSyncBalance = async () => {
    setIsSyncingBalance(true);
    try {
      const res = await ApiServices.checkCreditBalance();
      setLiveBalance(res.liveBalance);
      showToast(
        `Live credit balance synced: ${res.liveBalance.toLocaleString()} credits`
      );
    } catch (err) {
      showToast(
        err instanceof Error ? err.message : "Failed to sync credit balance.",
        "error"
      );
    } finally {
      setIsSyncingBalance(false);
    }
  };

  const handleOpenTestModal = () => {
    setTestIdempotencyKey(generateUUID());
    setTestScheduled(false);
    setTestScheduleDate(getFutureDatetimeLocal(30));
    setTestModalOpen(true);
  };

  const handleQueueCampaign = async () => {
    if (!canSubmit || isSubmitting) return;
    setIsSubmitting(true);

    try {
      // GUARDRAIL 3: Real-time pre-flight Check Credit Balance before committing
      const liveCheck = await ApiServices.checkCreditBalance();
      setLiveBalance(liveCheck.liveBalance);
      const preflightGate = evaluateCreditGate(
        liveCheck.liveBalance,
        reservedCredits,
        estimatedCost
      );

      if (!preflightGate.canAffordCampaign) {
        showToast(
          `Credit Gatekeeper Blocked: Campaign costs ${estimatedCost.toLocaleString()} credits, but only ${preflightGate.effectiveAvailableCredits.toLocaleString()} effective credits are available.`,
          "error"
        );
        return;
      }

      const scheduledIsoUtc = isScheduled
        ? toSafeIsoString(scheduleDate) ?? new Date().toISOString()
        : new Date().toISOString();

      const dbEncoding = msgDetails.encoding.startsWith("UCS-2")
        ? "UCS-2"
        : "GSM-7";
      const audienceLabel =
        audienceType === "all"
          ? "All Contacts"
          : audienceType === "random"
          ? `Random Contacts Subset (${recipientCount})`
          : `Top Frequent Visitors (${recipientCount})`;

      let providerRef = "";
      let campaignId = generateUUID();

      if (isScheduled) {
        const apiResult = await ApiServices.scheduleBulkSMS({
          idempotencyKey,
          name: name.trim(),
          recipientsCount: recipientCount,
          segmentCount: msgDetails.segmentCount,
          totalCost: estimatedCost,
          message,
          scheduledAt: scheduledIsoUtc,
          encoding: dbEncoding,
          characterCount: msgDetails.charCount,
          effectiveUnitCount: msgDetails.effectiveUnits,
          rawRecipientCount: audienceSanitization.rawTotal,
          duplicatesRemoved: audienceSanitization.duplicateCount,
          optedOutStripped: audienceSanitization.optedOutCount,
          invalidRejected: audienceSanitization.invalidCount,
          audienceId: audienceType,
          audienceName: audienceLabel,
        });
        providerRef = apiResult.providerCampaignId;
        if (apiResult.campaignId) {
          campaignId = apiResult.campaignId;
        }
      } else {
        const apiResult = await ApiServices.sendBulkSMS({
          idempotencyKey,
          name: name.trim(),
          recipientsCount: recipientCount,
          segmentCount: msgDetails.segmentCount,
          totalCost: estimatedCost,
          message,
          encoding: dbEncoding,
          characterCount: msgDetails.charCount,
          effectiveUnitCount: msgDetails.effectiveUnits,
          rawRecipientCount: audienceSanitization.rawTotal,
          duplicatesRemoved: audienceSanitization.duplicateCount,
          optedOutStripped: audienceSanitization.optedOutCount,
          invalidRejected: audienceSanitization.invalidCount,
          audienceId: audienceType,
          audienceName: audienceLabel,
        });
        providerRef = apiResult.batchId;
        if (apiResult.campaignId) {
          campaignId = apiResult.campaignId;
        }
        if (typeof apiResult.newBalance === "number") {
          setLiveBalance(apiResult.newBalance);
        } else {
          setLiveBalance((prev) => Math.max(0, prev - estimatedCost));
        }
      }

      const newCampaign: CampaignItem = {
        id: campaignId,
        idempotencyKey,
        name: name.trim(),
        status: isScheduled ? "scheduled" : "sent",
        recipientsCount: recipientCount,
        optedOutStripped: audienceSanitization.optedOutCount,
        duplicatesRemoved: audienceSanitization.duplicateCount,
        segmentCount: msgDetails.segmentCount,
        encoding: msgDetails.encoding,
        totalCost: estimatedCost,
        message,
        scheduledAt: scheduledIsoUtc,
        providerCampaignId: providerRef,
      };

      setCampaigns((prev) => [newCampaign, ...prev]);
      showToast(
        `Campaign "${newCampaign.name}" ${
          isScheduled ? "scheduled" : "sent"
        } successfully! (${estimatedCost.toLocaleString()} credits)`
      );

      // Reset Form & Rotate Idempotency Key
      setName("");
      setAudienceType("all");
      setAudienceSize("500");
      setMessage("");
      setIsScheduled(false);
      setScheduleDate("");
      setIdempotencyKey(generateUUID());
      setActiveTab(isScheduled ? "queued" : "history");
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : "Failed to process campaign.",
        "error"
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancelCampaign = async (campaign: CampaignItem) => {
    // GUARDRAIL 4: Block cancellation within 5 minutes of scheduled dispatch
    const cancelCheck = canCancelScheduledCampaign(
      campaign.scheduledAt,
      Date.now()
    );
    if (!cancelCheck.allowed) {
      showToast(
        cancelCheck.reason ||
          `Safety Lock: Cannot cancel within ${MIN_CANCEL_BUFFER_MINUTES} minutes of dispatch.`,
        "error"
      );
      setConfirmCancelCampaign(null);
      return;
    }

    setCancellingId(campaign.id);
    try {
      // STEP 1 & 2: Call `sms-proxy` Schedule Delete (deletes on provider first, then marks cancelled in Supabase)
      await ApiServices.scheduleDelete(
        campaign.id,
        campaign.providerCampaignId
      );

      setCampaigns((prev) =>
        prev.map((c) =>
          c.id === campaign.id ? { ...c, status: "cancelled" } : c
        )
      );
      showToast(
        `Cancelled "${campaign.name}" (${campaign.totalCost.toLocaleString()} reserved credits released).`
      );
      setConfirmCancelCampaign(null);
    } catch (error) {
      showToast(
        error instanceof Error
          ? error.message
          : "Provider Schedule Delete failed; campaign remains scheduled.",
        "error"
      );
    } finally {
      setCancellingId(null);
    }
  };

  const handleSendTestSms = async () => {
    const cleanPhone = testPhone.trim().replace(/[\s()-]/g, "");
    if (!isValidE164(cleanPhone)) {
      showToast(
        "Invalid E.164 phone number format. Must start with + and country code (e.g. +919810012345).",
        "error"
      );
      return;
    }
    if (optOuts.includes(cleanPhone)) {
      showToast(
        `Blocked: ${cleanPhone} is on the Opt-Out blacklist and cannot receive SMS.`,
        "error"
      );
      return;
    }
    if (msgDetails.isOverLimit || msgDetails.segmentCount === 0) {
      showToast(
        `Message must be between 1 and ${MAX_ALLOWED_SEGMENTS} segments.`,
        "error"
      );
      return;
    }
    if (msgDetails.segmentCount > effectiveCredits) {
      showToast("Insufficient effective credits for test SMS.", "error");
      return;
    }

    let scheduledIso: string | null = null;
    if (testScheduled) {
      const parsedIso = toSafeIsoString(testScheduleDate);
      if (!parsedIso) {
        showToast("Please select a valid schedule time for the test SMS.", "error");
        return;
      }
      scheduledIso = parsedIso;
      const check = validateScheduleTimestamp(scheduledIso, Date.now());
      if (!check.valid) {
        showToast(
          check.error ||
            `Scheduled single SMS must be at least ${MIN_SCHEDULE_BUFFER_MINUTES} minutes in the future.`,
          "error"
        );
        return;
      }
    }

    setIsSendingTest(true);
    try {
      const res = await ApiServices.sendSingleSMS({
        idempotencyKey: testIdempotencyKey || generateUUID(),
        phoneNumber: cleanPhone,
        messageBody: message,
        segments: msgDetails.segmentCount,
        scheduledAt: scheduledIso,
      });
      if (typeof res.newBalance === "number") {
        setLiveBalance(res.newBalance);
      } else if (!testScheduled) {
        setLiveBalance((prev) => Math.max(0, prev - msgDetails.segmentCount));
      }
      showToast(
        `${testScheduled ? "Scheduled test SMS" : "Test SMS sent"} to ${cleanPhone} (${
          msgDetails.segmentCount
        } credit${msgDetails.segmentCount > 1 ? "s" : ""})`
      );
      setTestModalOpen(false);
    } catch (err) {
      showToast(
        err instanceof Error ? err.message : "Failed to send test SMS.",
        "error"
      );
    } finally {
      setIsSendingTest(false);
    }
  };

  const handleAddOptOut = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newOptOutPhone.trim().replace(/[\s()-]/g, "");
    if (!isValidE164(clean)) {
      showToast("Enter a valid E.164 number (e.g. +919810000109)", "error");
      return;
    }
    if (optOuts.includes(clean)) {
      showToast("Number is already in the Opt-Out list.", "error");
      return;
    }
    setIsAddingOptOut(true);
    try {
      // Insert new opt-out number into the Supabase `opt_outs` table
      const { error: dbError } = await supabase.from("opt_outs").insert([
        {
          phone: clean,
          reason: "User opted out",
          source: "manual_admin",
          provider_synced: true,
        },
      ]);
      if (dbError) {
        throw new Error(dbError.message);
      }

      // Sync with sms-rest 3.0 Optout Number via Edge Function
      await ApiServices.optoutNumber(clean);
      setOptOuts((prev) => (prev.includes(clean) ? prev : [clean, ...prev]));
      setNewOptOutPhone("");
      showToast(`Synced ${clean} to sms-rest 3.0 Opt-Out list.`);
    } catch (err) {
      showToast(
        err instanceof Error ? err.message : "Failed to opt out number.",
        "error"
      );
    } finally {
      setIsAddingOptOut(false);
    }
  };

  // Sort queued campaigns chronologically by scheduledAt and compute cumulative balance coverage
  const queuedCampaignsWithAudit = useMemo(() => {
    const sorted = campaigns
      .filter((c) => c.status === "scheduled")
      .sort(
        (a, b) =>
          new Date(a.scheduledAt).getTime() - new Date(b.scheduledAt).getTime()
      );

    let cumulative = 0;
    return sorted.map((camp) => {
      cumulative += camp.totalCost;
      return {
        campaign: camp,
        isCoveredByBalance: cumulative <= liveBalance,
        cumulativeCost: cumulative,
      };
    });
  }, [campaigns, liveBalance]);

  const historyCampaigns = useMemo(() => {
    return campaigns
      .filter((c) => c.status !== "scheduled")
      .sort(
        (a, b) =>
          new Date(b.scheduledAt).getTime() - new Date(a.scheduledAt).getTime()
      );
  }, [campaigns]);

  const availableOptedInContacts = Math.max(0, totalContacts - optOuts.length);
  const safeScheduleIso = toSafeIsoString(scheduleDate);

  const handleStandaloneLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    const trimmedEmail = loginEmail.trim();
    if (!trimmedEmail || !loginPassword) {
      setLoginError("Please enter both your email and password.");
      return;
    }
    setIsSigningIn(true);
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: trimmedEmail,
        password: loginPassword,
      });
      if (error || !data.session) {
        setLoginError(error?.message || "Invalid email or password.");
        return;
      }
      setInternalSession(data.session);
      setLoginPassword("");
    } catch (err) {
      setLoginError(
        err instanceof Error ? err.message : "Authentication failed."
      );
    } finally {
      setIsSigningIn(false);
    }
  };

  const handleSignOutClick = async () => {
    if (onSignOut) {
      await onSignOut();
    } else {
      await supabase.auth.signOut();
    }
    setInternalSession(null);
  };

  if (isCheckingAuth) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
        <div className="text-sm text-slate-500 font-medium">
          Verifying session…
        </div>
      </div>
    );
  }

  if (!activeSession) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4 font-sans text-slate-900">
        <div className="w-full max-w-sm bg-white border border-slate-200 rounded-xl shadow-sm p-6 space-y-5">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-900">
              Dilli Haat SMS Campaign
            </h1>
            <p className="text-xs text-slate-500 mt-1">
              Sign in with your operator credentials to access the gateway.
            </p>
          </div>

          {loginError && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 font-medium">
              {loginError}
            </div>
          )}

          <form onSubmit={handleStandaloneLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Email Address
              </label>
              <input
                type="email"
                required
                autoComplete="email"
                value={loginEmail}
                onChange={(e) => setLoginEmail(e.target.value)}
                placeholder="operator@dillihaat.gov.in"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Password
              </label>
              <input
                type="password"
                required
                autoComplete="current-password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={isSigningIn}
              className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition disabled:opacity-50"
            >
              {isSigningIn ? "Signing In…" : "Sign In"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans pb-12">
      {/* Navbar / Header */}
      <header className="bg-white border-b border-slate-200 px-4 sm:px-8 py-3 sm:py-4 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-20">
        <div className="flex items-center gap-2.5">
          <div className="bg-blue-600 p-2 rounded-lg text-white shadow-sm">
            <Icons.Send className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">
              Dilli Haat SMS Campaign (DHSC)
            </h1>
            <p className="text-xs text-slate-500 hidden sm:block">
              Supabase Edge Proxy • <span className="font-mono">sms-rest 3.0</span> Fail-Safe Gateway
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <button
            type="button"
            onClick={() => setOptOutModalOpen(true)}
            className="px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-200 rounded-lg text-xs font-medium text-slate-700 flex items-center gap-1.5 shadow-sm transition"
          >
            <Icons.ShieldBan className="w-4 h-4 text-orange-600" />
            <span>Opt-Outs ({optOuts.length})</span>
          </button>

          <button
            type="button"
            onClick={handleSyncBalance}
            disabled={isSyncingBalance}
            className="px-3 py-1.5 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg text-xs font-semibold text-blue-700 flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <Icons.RefreshCw
              className={`w-3.5 h-3.5 ${isSyncingBalance ? "animate-spin" : ""}`}
            />
            <span>Sync Balance</span>
          </button>

          <div className="text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-full flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="hidden sm:inline">Production Environment</span>
            <span className="sm:hidden">Prod</span>
          </div>

          <button
            type="button"
            onClick={handleSignOutClick}
            className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-medium text-slate-700 transition shadow-sm"
          >
            Sign Out
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4 sm:mt-8 space-y-6 sm:space-y-8">
        {/* --- Credit Health Monitor --- */}
        <section>
          {!isLoadingData && creditGate.hasQueueDeficit && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-red-700 animate-pulse">
              <div className="flex items-start gap-3">
                <Icons.AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" />
                <div>
                  <h3 className="font-semibold">
                    Credit Deficit Warning (Shortfall: {creditGate.queueDeficitAmount.toLocaleString()} credits)
                  </h3>
                  <p className="text-sm">
                    Your reserved credits for scheduled campaigns ({reservedCredits.toLocaleString()}) exceed your live balance ({liveBalance.toLocaleString()}). Future campaigns may fail to send unless you top up your account or cancel queued blasts.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleSyncBalance}
                disabled={isSyncingBalance}
                className="shrink-0 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-semibold rounded-lg shadow-sm disabled:opacity-50"
              >
                Re-Sync Live Balance
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
              <div className="p-3 bg-blue-50 text-blue-600 rounded-full">
                <Icons.Wallet className="w-6 h-6" />
              </div>
              <div>
                <p className="text-sm text-slate-500 font-medium">Live API Balance</p>
                <p className="text-2xl font-bold">
                  {isLoadingData ? "—" : liveBalance.toLocaleString()}
                </p>
              </div>
            </div>
            <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
              <div className="p-3 bg-orange-50 text-orange-600 rounded-full">
                <Icons.Clock className="w-6 h-6" />
              </div>
              <div>
                <p className="text-sm text-slate-500 font-medium">Reserved Credits</p>
                <p className="text-2xl font-bold">
                  {isLoadingData ? "—" : reservedCredits.toLocaleString()}
                </p>
              </div>
            </div>
            <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
              <div
                className={`p-3 rounded-full ${
                  !isLoadingData && effectiveCredits < 0
                    ? "bg-red-50 text-red-600"
                    : "bg-green-50 text-green-600"
                }`}
              >
                {!isLoadingData && effectiveCredits < 0 ? (
                  <Icons.AlertTriangle className="w-6 h-6" />
                ) : (
                  <Icons.CheckCircle className="w-6 h-6" />
                )}
              </div>
              <div>
                <p className="text-sm text-slate-500 font-medium">
                  Effective Available
                </p>
                <p
                  className={`text-2xl font-bold ${
                    !isLoadingData && effectiveCredits < 0
                      ? "text-red-600"
                      : "text-slate-900"
                  }`}
                >
                  {isLoadingData ? "—" : effectiveCredits.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* --- Main 2-Column Grid --- */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* LEFT COLUMN: Campaign Form */}
          <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
            <div className="px-6 py-4 border-b border-slate-100 bg-slate-50/50 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold">Create Campaign</h2>
                <p className="text-sm text-slate-500">
                  Draft and schedule your SMS blast.
                </p>
              </div>
              <span
                className="text-[11px] font-mono text-slate-400 bg-white px-2 py-1 rounded border border-slate-200"
                title={`Idempotency Key: ${idempotencyKey}`}
              >
                ID: {idempotencyKey.slice(0, 8)}…
              </span>
            </div>

            <div className="p-4 sm:p-6 space-y-5 flex-1">
              {/* Campaign Name */}
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Campaign Name
                </label>
                <input
                  type="text"
                  maxLength={80}
                  className="w-full px-3 py-3 sm:py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-base sm:text-sm"
                  placeholder="e.g. Handloom Festival Weekend Promo"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                {trimmedNameLength > 0 && trimmedNameLength < 3 && (
                  <p className="text-xs text-red-600 mt-1">
                    Campaign name must be at least 3 characters.
                  </p>
                )}
              </div>

              {/* Recipients Dropdown & Opt-Out Sanitization */}
              <div>
                <div className="flex justify-between items-end mb-1">
                  <label className="block text-sm font-medium text-slate-700">
                    Target Audience
                  </label>
                  <span className="text-xs font-medium text-blue-600 bg-blue-50 px-2 py-0.5 rounded-full">
                    {recipientCount.toLocaleString()} Valid Billable
                  </span>
                </div>
                <select
                  className="w-full px-3 py-3 sm:py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-base sm:text-sm bg-white"
                  value={audienceType}
                  onChange={(e) => setAudienceType(e.target.value as AudienceType)}
                >
                  <option value="all">
                    All Contacts ({totalContacts.toLocaleString()} Raw)
                  </option>
                  <option value="random">Random Contacts Subset</option>
                  <option value="top">Top Frequent Visitors</option>
                </select>

                {/* Conditional Number Input for Random / Top */}
                {(audienceType === "random" || audienceType === "top") && (
                  <div className="mt-3">
                    <label className="block text-sm font-medium text-slate-700 mb-1">
                      Number of Contacts
                    </label>
                    <input
                      type="number"
                      min="1"
                      max={Math.max(1, availableOptedInContacts)}
                      className="w-full px-3 py-3 sm:py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-base sm:text-sm"
                      placeholder="e.g. 500"
                      value={audienceSize}
                      onChange={(e) => setAudienceSize(e.target.value)}
                    />
                    <p className="text-xs text-slate-500 mt-1">
                      Available opted-in contacts:{" "}
                      {availableOptedInContacts.toLocaleString()} (
                      {optOuts.length} opted-out excluded)
                    </p>
                  </div>
                )}

                {/* Sanitization Guardrail Summary Strip */}
                {audienceSanitization.rawTotal > 0 && (
                  <div className="mt-2 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 flex flex-wrap items-center justify-between gap-2">
                    <span>
                      Raw: <strong>{audienceSanitization.rawTotal.toLocaleString()}</strong>
                    </span>
                    {audienceSanitization.optedOutCount > 0 && (
                      <span className="text-orange-600 font-medium">
                        −{audienceSanitization.optedOutCount} Opted-Out
                      </span>
                    )}
                    {audienceSanitization.duplicateCount > 0 && (
                      <span className="text-amber-600 font-medium">
                        −{audienceSanitization.duplicateCount} Duplicates
                      </span>
                    )}
                    {audienceSanitization.invalidCount > 0 && (
                      <span className="text-red-600 font-medium">
                        −{audienceSanitization.invalidCount} Invalid E.164
                      </span>
                    )}
                    <span className="text-emerald-700 font-semibold">
                      = {recipientCount.toLocaleString()} Valid
                    </span>
                  </div>
                )}
              </div>

              {/* Message Body & Real-Time Math */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-sm font-medium text-slate-700">
                    Message Body
                  </label>
                  <span className="text-xs text-slate-500">
                    Max {MAX_ALLOWED_SEGMENTS} segments
                  </span>
                </div>
                <textarea
                  className={`w-full px-3 py-3 sm:py-2 border rounded-lg focus:ring-2 outline-none transition-all resize-none h-32 text-base sm:text-sm ${
                    msgDetails.isOverLimit
                      ? "border-red-400 focus:ring-red-500 focus:border-red-500 bg-red-50/20"
                      : "border-slate-300 focus:ring-blue-500 focus:border-blue-500"
                  }`}
                  placeholder="Type your message here..."
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                />

                {msgDetails.isOverLimit && (
                  <p className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1">
                    <Icons.AlertTriangle className="w-4 h-4 shrink-0" />
                    Message exceeds the maximum limit of {MAX_ALLOWED_SEGMENTS} segments ({msgDetails.segmentCount} segments). Please shorten the message.
                  </p>
                )}

                {/* Real-time Math Panel */}
                <div className="mt-3 bg-slate-50 border border-slate-200 rounded-lg p-3 text-sm grid grid-cols-2 gap-y-2 gap-x-4">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Encoding:</span>
                    <span
                      className={`font-medium ${
                        msgDetails.encoding === "UCS-2 (Unicode)"
                          ? "text-purple-600"
                          : "text-slate-700"
                      }`}
                    >
                      {msgDetails.encoding}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Characters:</span>
                    <span className="font-medium">
                      {msgDetails.charCount}{" "}
                      <span className="text-xs text-slate-400">
                        ({msgDetails.remainingInSegment} left)
                      </span>
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Segments/Msg:</span>
                    <span
                      className={`font-medium ${
                        msgDetails.isOverLimit ? "text-red-600 font-bold" : ""
                      }`}
                    >
                      {msgDetails.segmentCount} / {MAX_ALLOWED_SEGMENTS}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Recipients:</span>
                    <span className="font-medium">
                      {recipientCount.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between border-t border-slate-200 pt-2 col-span-2">
                    <span className="font-semibold text-slate-700">
                      Total Est. Cost:
                    </span>
                    <span
                      className={`font-bold ${
                        !isLoadingData &&
                        !creditGate.canAffordCampaign &&
                        estimatedCost > 0
                          ? "text-red-600"
                          : "text-blue-600"
                      }`}
                    >
                      {estimatedCost.toLocaleString()} credits
                    </span>
                  </div>
                </div>

                {!isLoadingData &&
                  !creditGate.canAffordCampaign &&
                  estimatedCost > 0 && (
                    <p className="mt-2 text-xs text-red-600 font-medium">
                      Insufficient effective credits: Need{" "}
                      {estimatedCost.toLocaleString()}, but only{" "}
                      {Math.max(0, effectiveCredits).toLocaleString()} available
                      after reserved queue.
                    </p>
                  )}
              </div>

              {/* Scheduling Options */}
              <div className="space-y-3 pt-2">
                <label className="block text-sm font-medium text-slate-700">
                  Delivery Schedule
                </label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 cursor-pointer p-2 sm:p-0">
                    <input
                      type="radio"
                      name="schedule"
                      className="w-5 h-5 sm:w-4 sm:h-4 text-blue-600"
                      checked={!isScheduled}
                      onChange={() => setIsScheduled(false)}
                    />
                    <span className="text-base sm:text-sm text-slate-700">
                      Send Immediately
                    </span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer p-2 sm:p-0">
                    <input
                      type="radio"
                      name="schedule"
                      className="w-5 h-5 sm:w-4 sm:h-4 text-blue-600"
                      checked={isScheduled}
                      onChange={() => {
                        setIsScheduled(true);
                        if (!scheduleDate) {
                          setScheduleDate(getFutureDatetimeLocal(30));
                        }
                      }}
                    />
                    <span className="text-base sm:text-sm text-slate-700">
                      Schedule for Later
                    </span>
                  </label>
                </div>
                {isScheduled && (
                  <div className="space-y-1.5">
                    <input
                      type="datetime-local"
                      className={`w-full px-3 py-3 sm:py-2 mt-1 border rounded-lg focus:ring-2 outline-none transition-all text-base sm:text-sm ${
                        !scheduleValidation.valid
                          ? "border-red-400 focus:ring-red-500"
                          : "border-slate-300 focus:ring-blue-500 focus:border-blue-500"
                      }`}
                      value={scheduleDate}
                      onChange={(e) => setScheduleDate(e.target.value)}
                    />
                    {safeScheduleIso && (
                      <p className="text-xs text-slate-500 font-mono">
                        UTC Stored: {safeScheduleIso}
                      </p>
                    )}
                    {!scheduleValidation.valid && (
                      <p className="text-xs text-red-600 font-medium">
                        {scheduleValidation.error}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Actions Footer */}
            <div className="px-4 sm:px-6 py-4 border-t border-slate-100 bg-slate-50 flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                className="px-4 py-3 sm:py-2 bg-white border border-slate-300 rounded-lg text-base sm:text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors flex items-center gap-2 w-full sm:flex-1 justify-center disabled:opacity-50"
                onClick={handleOpenTestModal}
                disabled={!message || msgDetails.isOverLimit || isSubmitting}
              >
                <Icons.Smartphone className="w-5 h-5 sm:w-4 sm:h-4" />
                Test SMS
              </button>
              <button
                type="button"
                className={`px-4 py-3 sm:py-2 rounded-lg text-base sm:text-sm font-medium text-white transition-colors flex items-center gap-2 w-full sm:flex-1 justify-center ${
                  canSubmit
                    ? "bg-blue-600 hover:bg-blue-700"
                    : "bg-slate-300 cursor-not-allowed"
                }`}
                onClick={handleQueueCampaign}
                disabled={!canSubmit || isSubmitting}
              >
                {isSubmitting ? (
                  <span className="w-5 h-5 sm:w-4 sm:h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : isScheduled ? (
                  <>
                    <Icons.Clock className="w-5 h-5 sm:w-4 sm:h-4" /> Queue
                  </>
                ) : (
                  <>
                    <Icons.Send className="w-5 h-5 sm:w-4 sm:h-4" /> Send
                  </>
                )}
              </button>
            </div>
          </div>

          {/* RIGHT COLUMN: Campaign Management */}
          <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden flex flex-col h-[560px] lg:h-[720px]">
            <div className="px-4 sm:px-6 py-4 border-b border-slate-100 bg-slate-50/50 flex gap-6 overflow-x-auto">
              <button
                type="button"
                className={`text-sm font-semibold pb-4 -mb-4 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
                  activeTab === "queued"
                    ? "text-blue-600 border-blue-600"
                    : "text-slate-500 border-transparent hover:text-slate-700"
                }`}
                onClick={() => setActiveTab("queued")}
              >
                <span>Queued (Future)</span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-orange-100 text-orange-700">
                  {queuedCampaignsWithAudit.length}
                </span>
              </button>
              <button
                type="button"
                className={`text-sm font-semibold pb-4 -mb-4 border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === "history"
                    ? "text-blue-600 border-blue-600"
                    : "text-slate-500 border-transparent hover:text-slate-700"
                }`}
                onClick={() => setActiveTab("history")}
              >
                <span>History (Past)</span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-slate-200 text-slate-700">
                  {historyCampaigns.length}
                </span>
              </button>
            </div>

            <div className="p-6 overflow-y-auto flex-1 bg-slate-50/30">
              <div className="space-y-4">
                {activeTab === "queued" ? (
                  queuedCampaignsWithAudit.length === 0 ? (
                    <div className="text-center py-12 text-slate-500 text-sm">
                      No scheduled campaigns found in the queue.
                    </div>
                  ) : (
                    queuedCampaignsWithAudit.map(
                      ({ campaign, isCoveredByBalance }) => {
                        const referenceMs =
                          isMounted && nowMs > 0
                            ? nowMs
                            : Date.parse(campaign.scheduledAt) - 30 * 60 * 1000;
                        const cancelGuard = canCancelScheduledCampaign(
                          campaign.scheduledAt,
                          referenceMs
                        );

                        return (
                          <div
                            key={campaign.id}
                            className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm hover:shadow-md transition-shadow"
                          >
                            <div className="flex flex-wrap justify-between items-start gap-2 mb-3">
                              <div>
                                <div className="flex items-center gap-2">
                                  <h3 className="font-semibold text-slate-900">
                                    {campaign.name}
                                  </h3>
                                  <span className="text-[11px] font-mono text-slate-400">
                                    ({campaign.providerCampaignId})
                                  </span>
                                </div>
                                <p className="text-xs text-slate-500 mt-0.5">
                                  {formatDate(campaign.scheduledAt, isMounted)}
                                </p>
                              </div>

                              <div className="flex items-center gap-2">
                                <span
                                  className={`text-xs px-2 py-0.5 rounded-full font-medium border ${
                                    isCoveredByBalance
                                      ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                                      : "bg-red-50 text-red-700 border-red-200"
                                  }`}
                                >
                                  {isCoveredByBalance
                                    ? "Balance Covered"
                                    : "Deficit Risk"}
                                </span>
                                <span className="text-xs px-2.5 py-1 rounded-full font-medium bg-orange-100 text-orange-700">
                                  Scheduled
                                </span>
                              </div>
                            </div>

                            {campaign.message && (
                              <p className="text-xs text-slate-600 bg-slate-50 border border-slate-100 rounded p-2.5 mb-3 line-clamp-2">
                                {campaign.message}
                              </p>
                            )}

                            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4 text-sm mb-4">
                              <div className="bg-slate-50 p-2 rounded text-center flex sm:block justify-between items-center">
                                <p className="text-xs text-slate-500 sm:mb-0.5">
                                  Valid Recipients
                                </p>
                                <p className="font-semibold text-slate-700">
                                  {campaign.recipientsCount.toLocaleString()}
                                </p>
                              </div>
                              <div className="bg-slate-50 p-2 rounded text-center flex sm:block justify-between items-center">
                                <p className="text-xs text-slate-500 sm:mb-0.5">
                                  Segments ({campaign.encoding})
                                </p>
                                <p className="font-semibold text-slate-700">
                                  {campaign.segmentCount}
                                </p>
                              </div>
                              <div className="bg-slate-50 p-2 rounded text-center flex sm:block justify-between items-center">
                                <p className="text-xs text-slate-500 sm:mb-0.5">
                                  Total Cost
                                </p>
                                <p className="font-semibold text-slate-700">
                                  {campaign.totalCost.toLocaleString()} credits
                                </p>
                              </div>
                            </div>

                            <div className="flex items-center justify-between pt-2 sm:pt-3 border-t border-slate-100">
                              <span className="text-xs text-slate-400">
                                {!cancelGuard.allowed
                                  ? `Dispatching in ${Math.max(
                                      0,
                                      cancelGuard.minutesRemaining
                                    ).toFixed(1)}m (${MIN_CANCEL_BUFFER_MINUTES}m lock active)`
                                  : `Dispatches in ${Math.max(
                                      0,
                                      Math.round(cancelGuard.minutesRemaining)
                                    )} mins`}
                              </span>

                              {!cancelGuard.allowed ? (
                                <span
                                  className="text-xs text-amber-700 bg-amber-50 border border-amber-200 px-2.5 py-1 rounded-md font-medium flex items-center gap-1"
                                  title={cancelGuard.reason}
                                >
                                  <Icons.Lock className="w-3.5 h-3.5" />
                                  Locked (&lt;{MIN_CANCEL_BUFFER_MINUTES}m to send)
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => setConfirmCancelCampaign(campaign)}
                                  disabled={cancellingId === campaign.id}
                                  className="text-sm text-red-600 hover:text-red-700 font-medium flex items-center gap-1.5 disabled:opacity-50"
                                >
                                  {cancellingId === campaign.id ? (
                                    <span className="w-4 h-4 border-2 border-red-600/30 border-t-red-600 rounded-full animate-spin" />
                                  ) : (
                                    <Icons.Trash2 className="w-4 h-4" />
                                  )}
                                  {cancellingId === campaign.id
                                    ? "Cancelling..."
                                    : "Cancel Campaign"}
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      }
                    )
                  )
                ) : historyCampaigns.length === 0 ? (
                  <div className="text-center py-12 text-slate-500 text-sm">
                    No past campaigns found in history.
                  </div>
                ) : (
                  historyCampaigns.map((campaign) => (
                    <div
                      key={campaign.id}
                      className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm hover:shadow-md transition-shadow"
                    >
                      <div className="flex flex-wrap justify-between items-start gap-2 mb-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold text-slate-900">
                              {campaign.name}
                            </h3>
                            <span className="text-[11px] font-mono text-slate-400">
                              ({campaign.providerCampaignId})
                            </span>
                          </div>
                          <p className="text-xs text-slate-500 mt-0.5">
                            {formatDate(campaign.scheduledAt, isMounted)}
                          </p>
                        </div>

                        <span
                          className={`text-xs px-2.5 py-1 rounded-full font-medium ${
                            campaign.status === "sent"
                              ? "bg-green-100 text-green-700"
                              : "bg-slate-100 text-slate-600"
                          }`}
                        >
                          {campaign.status.charAt(0).toUpperCase() +
                            campaign.status.slice(1)}
                        </span>
                      </div>

                      {campaign.message && (
                        <p className="text-xs text-slate-600 bg-slate-50 border border-slate-100 rounded p-2.5 mb-3 line-clamp-2">
                          {campaign.message}
                        </p>
                      )}

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4 text-sm">
                        <div className="bg-slate-50 p-2 rounded text-center flex sm:block justify-between items-center">
                          <p className="text-xs text-slate-500 sm:mb-0.5">
                            Valid Recipients
                          </p>
                          <p className="font-semibold text-slate-700">
                            {campaign.recipientsCount.toLocaleString()}
                          </p>
                        </div>
                        <div className="bg-slate-50 p-2 rounded text-center flex sm:block justify-between items-center">
                          <p className="text-xs text-slate-500 sm:mb-0.5">
                            Segments ({campaign.encoding})
                          </p>
                          <p className="font-semibold text-slate-700">
                            {campaign.segmentCount}
                          </p>
                        </div>
                        <div className="bg-slate-50 p-2 rounded text-center flex sm:block justify-between items-center">
                          <p className="text-xs text-slate-500 sm:mb-0.5">
                            Total Cost
                          </p>
                          <p className="font-semibold text-slate-700">
                            {campaign.totalCost.toLocaleString()} credits
                          </p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* --- Toasts Notifications --- */}
      <div className="fixed bottom-6 right-6 z-50 space-y-3 pointer-events-none">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="bg-slate-800 text-white px-4 py-3 rounded-lg shadow-xl flex items-center justify-between gap-3 w-80 pointer-events-auto"
          >
            <div className="flex items-center gap-3">
              {toast.type === "success" ? (
                <Icons.CheckCircle className="w-5 h-5 text-green-400 shrink-0" />
              ) : (
                <Icons.AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              )}
              <p className="text-sm font-medium">{toast.message}</p>
            </div>
            <button
              type="button"
              onClick={() => dismissToast(toast.id)}
              className="text-slate-400 hover:text-white shrink-0"
              aria-label="Close notification"
            >
              <Icons.X className="w-4 h-4" />
            </button>
          </div>
        ))}
      </div>

      {/* --- Two-Step Cancel Scheduled Campaign Confirmation Modal --- */}
      {confirmCancelCampaign && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center">
              <h3 className="font-semibold text-lg text-slate-900">
                Cancel Scheduled Campaign?
              </h3>
              <button
                type="button"
                onClick={() => setConfirmCancelCampaign(null)}
                className="text-slate-400 hover:text-slate-600"
              >
                <Icons.X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-3 text-sm text-slate-600">
              <p>
                You are cancelling{" "}
                <strong className="text-slate-900">
                  {confirmCancelCampaign.name}
                </strong>{" "}
                (Provider ID:{" "}
                <code className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded">
                  {confirmCancelCampaign.providerCampaignId}
                </code>
                ).
              </p>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs space-y-1">
                <p className="font-semibold text-slate-700">
                  Two-Step Cancellation Safeguard:
                </p>
                <p>
                  1. Calls <code className="font-mono">sms-rest 3.0 Schedule Delete</code> via Edge Function.
                </p>
                <p>
                  2. Marks campaign <code className="font-mono">cancelled</code> in Supabase and releases{" "}
                  <strong>{confirmCancelCampaign.totalCost.toLocaleString()} credits</strong>.
                </p>
              </div>
            </div>
            <div className="px-6 py-4 bg-slate-50 border-t border-slate-100 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setConfirmCancelCampaign(null)}
                disabled={cancellingId === confirmCancelCampaign.id}
                className="px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100 rounded-lg"
              >
                Keep Scheduled
              </button>
              <button
                type="button"
                onClick={() => handleCancelCampaign(confirmCancelCampaign)}
                disabled={cancellingId === confirmCancelCampaign.id}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium flex items-center gap-2 disabled:opacity-50"
              >
                {cancellingId === confirmCancelCampaign.id ? (
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <Icons.Trash2 className="w-4 h-4" />
                )}
                {cancellingId === confirmCancelCampaign.id
                  ? "Deleting on Provider..."
                  : "Confirm Cancel"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- Test SMS Modal --- */}
      {testModalOpen && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center">
              <h3 className="font-semibold text-lg">Send Test SMS</h3>
              <button
                type="button"
                onClick={() => setTestModalOpen(false)}
                className="text-slate-400 hover:text-slate-600"
              >
                <Icons.X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-sm text-slate-500">
                Send the current draft ({msgDetails.segmentCount} segment
                {msgDetails.segmentCount > 1 ? "s" : ""}, {msgDetails.encoding}) to a single number to verify formatting.
              </p>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Test Phone Number (Strict E.164)
                </label>
                <input
                  type="tel"
                  value={testPhone}
                  onChange={(e) => setTestPhone(e.target.value)}
                  className="w-full px-3 py-3 sm:py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-base sm:text-sm font-mono"
                  placeholder="+919810012345"
                />
                {!E164_REGEX.test(testPhone.trim()) && testPhone.trim().length > 0 && (
                  <p className="text-xs text-red-600 mt-1">
                    Must start with + followed by country code and digits (e.g. +919810012345).
                  </p>
                )}
              </div>

              <div className="flex items-center gap-4 text-sm">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    checked={!testScheduled}
                    onChange={() => setTestScheduled(false)}
                    className="text-blue-600"
                  />
                  <span>Send Single Now</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    checked={testScheduled}
                    onChange={() => {
                      setTestScheduled(true);
                      if (!testScheduleDate) {
                        setTestScheduleDate(getFutureDatetimeLocal(30));
                      }
                    }}
                    className="text-blue-600"
                  />
                  <span>Schedule Single SMS</span>
                </label>
              </div>

              {testScheduled && (
                <input
                  type="datetime-local"
                  value={testScheduleDate}
                  onChange={(e) => setTestScheduleDate(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm"
                />
              )}
            </div>
            <div className="px-4 sm:px-6 py-4 bg-slate-50 border-t border-slate-100 flex flex-col-reverse sm:flex-row justify-end gap-3">
              <button
                type="button"
                onClick={() => setTestModalOpen(false)}
                className="px-4 py-3 sm:py-2 w-full sm:w-auto text-base sm:text-sm font-medium text-slate-600 hover:bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSendTestSms}
                disabled={isSendingTest}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isSendingTest ? (
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <Icons.Send className="w-4 h-4" />
                )}
                {isSendingTest ? "Sending..." : "Send Test"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --- Opt-Out Blacklist Modal (`Optout Number` capability) --- */}
      {optOutModalOpen && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center">
              <h3 className="font-semibold text-lg">Opt-Out Blacklist (`opt_outs`)</h3>
              <button
                type="button"
                onClick={() => setOptOutModalOpen(false)}
                className="text-slate-400 hover:text-slate-600"
              >
                <Icons.X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-xs text-slate-500">
                Numbers listed here are synced with <code className="font-mono">sms-rest 3.0 Optout Number</code> and automatically stripped from all campaign audiences.
              </p>
              <form onSubmit={handleAddOptOut} className="flex gap-2">
                <input
                  type="tel"
                  value={newOptOutPhone}
                  onChange={(e) => setNewOptOutPhone(e.target.value)}
                  placeholder="+919810000109"
                  className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 outline-none"
                />
                <button
                  type="submit"
                  disabled={isAddingOptOut}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg disabled:opacity-50"
                >
                  {isAddingOptOut ? "Adding..." : "Add"}
                </button>
              </form>
              <div className="max-h-48 overflow-y-auto divide-y divide-slate-100 border border-slate-200 rounded-lg">
                {optOuts.length === 0 ? (
                  <div className="px-3 py-4 text-xs text-center text-slate-400">
                    No opted-out phone numbers recorded.
                  </div>
                ) : (
                  optOuts.map((num) => (
                    <div
                      key={num}
                      className="px-3 py-2 text-xs font-mono text-slate-700 flex items-center justify-between"
                    >
                      <span>{num}</span>
                      <span className="text-[11px] text-orange-600 bg-orange-50 px-2 py-0.5 rounded">
                        Opted Out
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
