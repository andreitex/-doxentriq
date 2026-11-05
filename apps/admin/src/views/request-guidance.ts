import type { AppRecord, JobRecord } from '../types';

export function requestGuidance(job: JobRecord, app?: AppRecord): { title: string; description: string } | undefined {
  if (job.stage === 'awaiting_approval') return {
    title: 'Your next step: try the preview',
    description: 'Check the tasks your team needs to do, then choose Review releases. Publishing requires your approval. If something needs changing, describe it in the conversation.'
  };
  if (job.stage === 'preview') return {
    title: 'Preparing your preview',
    description: 'AutoSoft is checking the candidate application. Wait for Ready for your review before approving publication.'
  };
  if (job.stage === 'completed') return app?.activeReleaseId && app.activeReleaseId === job.result?.releaseId ? {
    title: 'This version is live',
    description: 'Open Releases to launch the application. Set up its users and roles in Access; a platform administrator account does not automatically grant access inside the app.'
  } : {
    title: 'Check the current version in Releases',
    description: 'This request has finished. Releases shows which version is live and which candidate still needs review.'
  };
  if (job.stage === 'cancelled') return {
    title: 'This request has stopped',
    description: 'Its recorded progress remains available. Describe your next change when you are ready.'
  };
  if (job.stage === 'failed') return {
    title: 'Review the last recorded error',
    description: 'Ask your IT contact for help if the error concerns setup, security checks, or recovery. Include the application name and request time; keep passwords and API keys out of chat.'
  };
  if (['queued', 'specification', 'implementation', 'verification', 'deployment', 'observation'].includes(job.stage)) return {
    title: 'You can return to this conversation later',
    description: 'The request continues on the server if you close this page. Recorded progress will load when you return. AutoSoft will pause when your input or approval is needed.'
  };
  return undefined;
}
