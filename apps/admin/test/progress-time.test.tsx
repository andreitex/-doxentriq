import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import Elapsed from '../src/components/Elapsed';
import { formatElapsed, progressTiming } from '../src/progress-time';
import type { JobRecord, ProgressEvent } from '../src/types';

const start = '2026-10-11T08:00:00Z';
const job: JobRecord = { id: 'request-one', appId: 'app-one', request: 'Build documents', stage: 'verification', baseReleaseId: null,
  costUsd: 0, budgetUsd: 1, attempts: 0, createdAt: start, updatedAt: '2026-10-11T08:02:00Z' };
const event = (id: number, stage: ProgressEvent['stage'], seconds: number): ProgressEvent => ({ id, jobId: job.id, stage,
  kind: 'status', message: 'Recorded action', createdAt: new Date(Date.parse(start) + seconds * 1000).toISOString() });

test('replayed and unsorted progress keeps request and current stage clocks', () => {
  const events = [event(4, 'verification', 120), event(2, 'implementation', 30), event(3, 'verification', 90), event(1, 'specification', 5)];
  assert.deepEqual(progressTiming(job, events, Date.parse(start) + 150000), { requestMs: 150000, stageMs: 60000 });
  assert.deepEqual(events.map(item => item.id), [4, 2, 3, 1]);
  assert.deepEqual(progressTiming(job, events, Date.parse(start) + 300000), { requestMs: 300000, stageMs: 210000 });
});

test('a repaired stage starts at its latest occurrence and foreign jobs cannot move the clock', () => {
  const events = [event(1, 'verification', 10), event(2, 'implementation', 30), event(3, 'verification', 60),
    { ...event(4, 'verification', 1), jobId: 'other-request' }];
  assert.deepEqual(progressTiming(job, events, Date.parse(start) + 90000), { requestMs: 90000, stageMs: 30000 });
});

test('completed failed and cancelled requests stop at their persisted timestamp', () => {
  for (const stage of ['completed', 'failed', 'cancelled'] as const) {
    assert.deepEqual(progressTiming({ ...job, stage }, [], Date.parse(start) + 3600000), { requestMs: 120000, stageMs: null });
  }
});

test('waiting remains elapsed time while missing retained transitions cannot invent stage time', () => {
  assert.deepEqual(progressTiming({ ...job, stage: 'queued' }, [], Date.parse(start) + 10000), { requestMs: 10000, stageMs: null });
  assert.deepEqual(progressTiming({ ...job, stage: 'awaiting_approval' }, [event(1, 'preview', 10), event(2, 'awaiting_approval', 20)], Date.parse(start) + 90000), { requestMs: 90000, stageMs: 70000 });
  assert.deepEqual(progressTiming({ ...job, stage: 'awaiting_approval' }, [event(2, 'awaiting_approval', 20)], Date.parse(start) + 90000), { requestMs: 90000, stageMs: null });
});

test('unavailable or inconsistent timestamps do not invent current stage durations', () => {
  const now = Date.parse(start) + 90000;
  for (const createdAt of ['invalid', '2026-10-12T08:00:00Z']) assert.deepEqual(progressTiming({ ...job, createdAt }, [], now), { requestMs: null, stageMs: null });
  for (const createdAt of ['invalid', '2026-10-10T08:00:00Z', '2026-10-12T08:00:00Z'])
    assert.deepEqual(progressTiming(job, [{ ...event(1, 'verification', 60), createdAt }], now), { requestMs: 90000, stageMs: null });
  assert.deepEqual(progressTiming(job, [event(1, 'implementation', 60)], now), { requestMs: 90000, stageMs: null });
});

test('elapsed labels use readable boundaries without negative or nonfinite values', () => {
  for (const [milliseconds, expected] of [[0, '0s'], [59999, '59s'], [60000, '1m 0s'], [3599999, '59m 59s'], [3600000, '1h 0m'], [86400000, '1d 0h']] as const)
    assert.equal(formatElapsed(milliseconds), expected);
  for (const value of [-1, NaN, Infinity]) assert.equal(formatElapsed(value), 'unavailable');
});

test('the rendered completed clock is accessible and discloses included waiting time', () => {
  const html = renderToStaticMarkup(createElement(Elapsed, { job: { ...job, stage: 'completed' }, events: [] }));
  assert.match(html, /role="timer"/); assert.match(html, /aria-live="off"/);
  assert.match(html, /waiting for input and approval/); assert.match(html, /2m 0s/);
});
