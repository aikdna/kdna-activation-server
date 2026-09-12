import type { Buffer } from 'node:buffer';
import type { HostPolicy, HostPolicyObservation } from '@aikdna/kdna-web-server';
declare const activationContext: unique symbol;
/** An in-process bearer-possession reference; not an account/device identity or portable credential. */
export interface ActivationContext { readonly [activationContext]: never; }
export interface ActivationBinding {
  readonly licenseId: string; readonly legacyDomain: string;
  /** Must be a genuine snapshot admitted by this process's exact public Core instance. */
  readonly snapshot: unknown;
  readonly scope: readonly string[]; readonly epoch: string; readonly policyId: string;
}
export interface LicenseSecretVerifier {
  readonly profile: 'scrypt'; readonly version: '1'; readonly salt: string; readonly derived_key: string;
  readonly parameters: { readonly N: 16384; readonly r: 8; readonly p: 1; readonly key_length: 32 };
}
export interface EntitlementRecord {
  readonly license_id: string; readonly domain: string; readonly license_secret_verifier: LicenseSecretVerifier;
  readonly issued_at: string; readonly updated_at: string; readonly expires_at: string | null;
  readonly status: string; readonly revoked: boolean; readonly revoked_at: string | null;
  readonly revocation_reason: string | null; readonly require_machine_binding: boolean;
  readonly require_online_check: boolean; readonly allowed_agents: readonly string[] | null;
  readonly [field: string]: unknown;
}
export interface ActivationObserverOptions {
  readonly store: { get(licenseId: string): unknown | Promise<unknown> };
  readonly binding: ActivationBinding;
  readonly readBinding: () => ActivationBinding | Promise<ActivationBinding>;
  readonly clock?: () => number; readonly timeoutMs?: number;
  readonly contextTtlMs?: number; readonly maxContexts?: number;
}
export interface ActivationObserver {
  authenticate(secret: unknown): Promise<ActivationContext | null>;
  verifyContext(context: unknown): Promise<boolean>;
  observePolicy(observation: Pick<HostPolicyObservation<unknown>, 'context' | 'snapshot'>): Promise<HostPolicy>;
  dispose(): void;
}
export interface CreateLicenseOptions {
  domain: string; license_key: string; license_id?: string; issued_to?: string;
  require_machine_binding?: boolean; require_online_check?: boolean; offline_grace_days?: number;
  allowed_agents?: readonly string[] | null; ttl_days?: number; issued_at?: string;
}
/** Server administration API. Never expose this object or its records to an HTTP client. */
export interface ActivationStore {
  readonly dataDir: string;
  get(licenseId: string): EntitlementRecord | null;
  create(options: CreateLicenseOptions): EntitlementRecord & { readonly license_key: string };
  put(record: EntitlementRecord): EntitlementRecord;
  revoke(licenseId: string, options?: { reason?: string; revoked_by?: string }): EntitlementRecord | null;
  list(): EntitlementRecord[];
  getByKey(secret: string, domain: string): EntitlementRecord | null;
  updateSync(licenseId: string): EntitlementRecord | null;
  compareAndBindMachine(licenseId: string, binding?: { bindingDigest: string; allowInitialBinding?: boolean; deriveLegacyDigest?: (fingerprint: unknown) => string | null }): unknown;
}
export declare function createActivationObserver(options: ActivationObserverOptions): ActivationObserver;
export declare function makeStore(dataDir: string): ActivationStore;
export declare function createLicenseSecretVerifier(secret: string, salt?: Buffer): LicenseSecretVerifier;
export declare function verifyLicenseSecret(secret: unknown, verifier: unknown): boolean;
