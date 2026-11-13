"use client";

import React, { useState } from "react";
import { supabase } from "@/lib/supabase";
import { isValidE164, normalizeUkPhone } from "@/lib/sms-validation";

export default function PublicOptOutPage() {
  const [phoneNumber, setPhoneNumber] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const cleanPhone = normalizeUkPhone(phoneNumber);
    if (!isValidE164(cleanPhone)) {
      setErrorMessage(
        "Must be a valid UK number starting with +44 or 07 (e.g., +447700900077)."
      );
      return;
    }

    setIsSubmitting(true);
    try {
      const { data, error } = await supabase.functions.invoke("sms-proxy", {
        body: {
          action: "public_optout",
          phoneNumber: cleanPhone,
        },
      });

      if (error) {
        throw new Error(error.message || "Failed to process unsubscribe request.");
      }

      if (data?.error) {
        throw new Error(data.error);
      }

      setIsSuccess(true);
    } catch (err) {
      setErrorMessage(
        err instanceof Error
          ? err.message
          : "Unable to complete your request. Please try again."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-50 flex items-center justify-center p-4 font-sans text-slate-900">
      <div className="w-full max-w-sm bg-white border border-slate-200 rounded-xl shadow-sm p-6 space-y-4">
        <h1 className="text-lg font-bold tracking-tight text-slate-900">
          Dilli Haat SMS Preferences
        </h1>

        {isSuccess ? (
          <div
            role="status"
            className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-sm text-emerald-800 font-medium"
          >
            You have been successfully unsubscribed.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-xs text-slate-600">
              Enter your mobile number below to opt out of future promotional SMS messages from Dilli Haat.
            </p>

            {errorMessage && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700 font-medium">
                {errorMessage}
              </div>
            )}

            <div>
              <label
                htmlFor="optout-phone"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Mobile Number
              </label>
              <input
                id="optout-phone"
                type="tel"
                required
                autoComplete="tel"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                placeholder="+447700900077"
                className="w-full px-3 py-2.5 border border-slate-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold rounded-lg transition disabled:opacity-50"
            >
              {isSubmitting ? "Processing…" : "Unsubscribe"}
            </button>
          </form>
        )}
      </div>
    </main>
  );
}

