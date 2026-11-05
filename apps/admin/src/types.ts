export type * from '../../../packages/core/src/types';

import type { Finding, Principal } from '../../../packages/core/src/types';

export type Session = { principal: Principal | null; csrfToken: string; mode: string };
export type ApplicationObservation = {
  appId: string; releaseId: string; publicationOperationId: string; checkedAt: string;
  status: 'healthy' | 'unhealthy' | 'unavailable' | 'superseded'; detail: string;
  consecutiveFailures: string[]; recoveryStatus: 'monitoring' | 'needs_attention' | 'pending' | 'recovered'; recoveryReason?: string;
  recoveryOperationId?: string;
};
export type ServiceTelemetry = {
  name?: string; status?: string; detail?: string;
  cpuPercent?: string; memoryUsage?: string; memoryPercent?: string; networkIO?: string; blockIO?: string; pids?: string;
  cpuCount?: number; loadAverage?: number[]; memoryTotalBytes?: number; memoryAvailableBytes?: number;
  diskTotalBytes?: number; diskFreeBytes?: number; uptimeSeconds?: number; encryptedDataMounted?: boolean;
};
export type Telemetry = {
  mode: string;
  uptimeSeconds: number;
  counts: { apps: number; jobs: number; runningJobs: number; publishedApps: number };
  costUsd: number;
  broker: { available: boolean; detail: string };
  services: ServiceTelemetry[];
  observations?: ApplicationObservation[];
};
export type SecurityReport = {
  findings: Finding[];
  unclassifiedFindings?: Finding[];
  scans: { releaseId: string; appId: string; status: string; checkedAt: string; feedUpdatedAt: string; stale?: boolean; coverage?: { name: string; status?: string; passed?: boolean; detail: string }[] }[];
  vm: { status: string; detail?: string; checkedAt?: string; feedUpdatedAt?: string; stale?: boolean };
};
export type ReleaseAction = 'publish' | 'rollback' | 'emergency_rollback';
export type Budget = {
  currency: 'USD';
  requestLimitUsd: number;
  monthlyLimitUsd: number;
  spentUsd: number;
  reservedUsd: number;
  remainingUsd: number;
  workflowSpentUsd?: number;
  externalConfirmedUsd?: number;
  externalConservativeUsd?: number;
  authorityId?: string | null;
  authorityLimitUsd?: number | null;
  authorityExpired?: boolean;
  month: string;
};
