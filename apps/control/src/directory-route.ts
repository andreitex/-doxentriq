// This endpoint authenticates the exact app token itself. It is served only on
// the private control service host, never the public portal or admin proxy.
export const directoryAuthorizationPath = (path: string | undefined): boolean =>
  !!path && /^\/api\/public\/v1\/apps\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\/directory\/authorize$/.test(path);
