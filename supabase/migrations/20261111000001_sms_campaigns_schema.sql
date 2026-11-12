-- ============================================================================
-- SentinelSMS v3.0 — Fail-Safe Bulk SMS Campaign Management Schema (Supabase)
-- Enforces E.164 format, Idempotency Keys, Segment Ceiling, UTC Timestamps,
-- 15-Minute Future Schedule Buffer, and 5-Minute Cancellation Safety Lock.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 0. Customer Contacts Table (`contacts` — uploaded from customer CSV)
CREATE TABLE IF NOT EXISTS public.contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "Customer Name" TEXT,
    "Telephone" TEXT,
    "E-Mail" TEXT,
    "Address" TEXT,
    "City" TEXT,
    "Postcode" TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

-- 1. Opt-Out / Blacklist Registry (`opt_outs`)
CREATE TABLE IF NOT EXISTS public.opt_outs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL DEFAULT 'User opted out',
    source TEXT NOT NULL DEFAULT 'webhook_stop' CHECK (source IN ('webhook_stop', 'manual_admin', 'provider_sync')),
    provider_synced BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    CONSTRAINT opt_outs_phone_e164_chk CHECK (phone ~ '^\+[1-9][0-9]{6,14}$')
);

-- 2. Campaigns Audit & Queue Table (`sms_campaigns`)
CREATE TABLE IF NOT EXISTS public.sms_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key UUID NOT NULL UNIQUE,
    user_id UUID NOT NULL DEFAULT auth.uid(),
    name TEXT NOT NULL CHECK (char_length(trim(name)) BETWEEN 3 AND 80),
    sender_id TEXT NOT NULL CHECK (char_length(trim(sender_id)) BETWEEN 3 AND 15),
    audience_id TEXT NOT NULL,
    audience_name TEXT NOT NULL,
    message TEXT NOT NULL CHECK (char_length(message) > 0),
    encoding TEXT NOT NULL CHECK (encoding IN ('GSM-7', 'UCS-2')),
    character_count INTEGER NOT NULL CHECK (character_count > 0),
    effective_unit_count INTEGER NOT NULL CHECK (effective_unit_count > 0),
    segments INTEGER NOT NULL CHECK (segments BETWEEN 1 AND 5),
    raw_recipient_count INTEGER NOT NULL CHECK (raw_recipient_count >= valid_recipient_count),
    valid_recipient_count INTEGER NOT NULL CHECK (valid_recipient_count > 0),
    duplicates_removed_count INTEGER NOT NULL DEFAULT 0 CHECK (duplicates_removed_count >= 0),
    opted_out_stripped_count INTEGER NOT NULL DEFAULT 0 CHECK (opted_out_stripped_count >= 0),
    invalid_rejected_count INTEGER NOT NULL DEFAULT 0 CHECK (invalid_rejected_count >= 0),
    estimated_credits INTEGER GENERATED ALWAYS AS (valid_recipient_count * segments) STORED,
    dispatch_type TEXT NOT NULL CHECK (dispatch_type IN ('immediate', 'scheduled')),
    status TEXT NOT NULL CHECK (status IN ('scheduled', 'sent', 'cancelled', 'failed')),
    provider_campaign_id TEXT,
    scheduled_at TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    CONSTRAINT scheduled_requires_timestamp_chk CHECK (
        (dispatch_type = 'scheduled' AND scheduled_at IS NOT NULL) OR
        (dispatch_type = 'immediate')
    )
);

CREATE INDEX IF NOT EXISTS idx_sms_campaigns_status_scheduled
    ON public.sms_campaigns (status, scheduled_at)
    WHERE status = 'scheduled';

-- 3. Database Trigger: Enforce 15-Minute Future Buffer on INSERT & 5-Minute Cancel Lock on UPDATE
CREATE OR REPLACE FUNCTION public.enforce_sms_campaign_time_guards()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Guardrail 4a: New scheduled campaigns must be at least 15 minutes in the future (UTC)
    IF TG_OP = 'INSERT' AND NEW.dispatch_type = 'scheduled' THEN
        IF NEW.scheduled_at < (now() + INTERVAL '15 minutes') THEN
            RAISE EXCEPTION 'SCHEDULE_BUFFER_VIOLATION: Scheduled campaign must be at least 15 minutes in the future (UTC).';
        END IF;
    END IF;

    -- Guardrail 4b: Block cancellation if within 5 minutes of scheduled dispatch time
    IF TG_OP = 'UPDATE' AND OLD.status = 'scheduled' AND NEW.status = 'cancelled' THEN
        IF OLD.scheduled_at <= (now() + INTERVAL '5 minutes') THEN
            RAISE EXCEPTION 'CANCELLATION_LOCK_ACTIVE: Cannot cancel a scheduled campaign within 5 minutes of its scheduled dispatch time.';
        END IF;
        NEW.cancelled_at := now();
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforce_sms_campaign_time_guards ON public.sms_campaigns;
CREATE TRIGGER trg_enforce_sms_campaign_time_guards
    BEFORE INSERT OR UPDATE ON public.sms_campaigns
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_sms_campaign_time_guards();

-- 4. Row Level Security (RLS) — Zero-Trust Lockdown (Authenticated Only, Append/Read Only)
ALTER TABLE public.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.opt_outs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sms_campaigns ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.contacts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.opt_outs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.sms_campaigns FORCE ROW LEVEL SECURITY;

-- Explicitly revoke all anonymous access and disallow DELETE for all users (Append/Read/Update only)
REVOKE ALL ON public.contacts, public.opt_outs, public.sms_campaigns FROM anon, PUBLIC;
REVOKE DELETE, TRUNCATE ON public.contacts, public.opt_outs, public.sms_campaigns FROM authenticated;
GRANT SELECT, INSERT, UPDATE ON public.contacts, public.opt_outs, public.sms_campaigns TO authenticated;

-- Contacts Policies (Authenticated Only; No DELETE Policy)
DROP POLICY IF EXISTS "Operators can view contacts" ON public.contacts;
DROP POLICY IF EXISTS "Authenticated users can select contacts" ON public.contacts;
CREATE POLICY "Authenticated users can select contacts"
    ON public.contacts FOR SELECT TO authenticated
    USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "Authenticated users can insert contacts" ON public.contacts;
CREATE POLICY "Authenticated users can insert contacts"
    ON public.contacts FOR INSERT TO authenticated
    WITH CHECK (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "Authenticated users can update contacts" ON public.contacts;
CREATE POLICY "Authenticated users can update contacts"
    ON public.contacts FOR UPDATE TO authenticated
    USING (auth.uid() IS NOT NULL)
    WITH CHECK (auth.uid() IS NOT NULL);

-- Opt-Outs Policies (Authenticated Only; No DELETE Policy)
DROP POLICY IF EXISTS "Authenticated operators can view opt_outs" ON public.opt_outs;
DROP POLICY IF EXISTS "Operators can view opt_outs" ON public.opt_outs;
DROP POLICY IF EXISTS "Authenticated users can select opt_outs" ON public.opt_outs;
CREATE POLICY "Authenticated users can select opt_outs"
    ON public.opt_outs FOR SELECT TO authenticated
    USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "Operators can insert opt_outs" ON public.opt_outs;
DROP POLICY IF EXISTS "Authenticated users can insert opt_outs" ON public.opt_outs;
CREATE POLICY "Authenticated users can insert opt_outs"
    ON public.opt_outs FOR INSERT TO authenticated
    WITH CHECK (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "Authenticated users can update opt_outs" ON public.opt_outs;
CREATE POLICY "Authenticated users can update opt_outs"
    ON public.opt_outs FOR UPDATE TO authenticated
    USING (auth.uid() IS NOT NULL)
    WITH CHECK (auth.uid() IS NOT NULL);

-- SMS Campaigns Policies (Authenticated Only; Append/Read/Update Only — No DELETE Policy)
DROP POLICY IF EXISTS "Authenticated operators can view campaigns" ON public.sms_campaigns;
DROP POLICY IF EXISTS "Operators can view campaigns" ON public.sms_campaigns;
DROP POLICY IF EXISTS "Authenticated users can select campaigns" ON public.sms_campaigns;
CREATE POLICY "Authenticated users can select campaigns"
    ON public.sms_campaigns FOR SELECT TO authenticated
    USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "Operators can insert campaigns" ON public.sms_campaigns;
DROP POLICY IF EXISTS "Authenticated users can insert campaigns" ON public.sms_campaigns;
CREATE POLICY "Authenticated users can insert campaigns"
    ON public.sms_campaigns FOR INSERT TO authenticated
    WITH CHECK (auth.uid() IS NOT NULL AND user_id = auth.uid());

DROP POLICY IF EXISTS "Operators can update campaigns" ON public.sms_campaigns;
DROP POLICY IF EXISTS "Authenticated users can update campaigns" ON public.sms_campaigns;
CREATE POLICY "Authenticated users can update campaigns"
    ON public.sms_campaigns FOR UPDATE TO authenticated
    USING (auth.uid() IS NOT NULL)
    WITH CHECK (auth.uid() IS NOT NULL);
