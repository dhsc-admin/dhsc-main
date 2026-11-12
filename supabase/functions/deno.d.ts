declare namespace Deno {
  export interface Env {
    get(key: string): string | undefined;
    set(key: string, value: string): void;
    delete(key: string): void;
    toObject(): Record<string, string>;
  }
  export const env: Env;
  export function serve(
    handler: (req: Request) => Response | Promise<Response>
  ): void;
}

declare module "https://deno.land/std@0.224.0/http/server.ts" {
  export function serve(
    handler: (req: Request) => Response | Promise<Response>
  ): void;
}

declare module "https://esm.sh/@supabase/supabase-js@2.47.0" {
  export {
    createClient,
    SupabaseClient,
    AuthClient,
    AuthError,
    User,
    Session,
    PostgrestError,
    PostgrestResponse,
    PostgrestSingleResponse,
    PostgrestFilterBuilder,
    PostgrestQueryBuilder,
  } from "@supabase/supabase-js";
}
