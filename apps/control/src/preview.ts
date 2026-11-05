import type { AppRecord, ReleaseRecord } from '../../../packages/core/src/types.ts';

/** This first release has one current preview per application. Historical code remains retained. */
export function requireCurrentCandidatePreview(app: AppRecord, release: ReleaseRecord): void {
  if (!release.publishedAt && ['ready', 'preview'].includes(release.status) && app.previewReleaseId !== release.id) {
    throw Object.assign(new Error('This unpublished candidate no longer has the current verified preview. Review the latest candidate or request a new verification before publication.'), { statusCode: 409 });
  }
}
