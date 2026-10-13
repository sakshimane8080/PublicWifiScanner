import { getUser } from '@netlify/identity';
import type { Config } from '@netlify/functions';
import { handleApi, jsonResponse } from '../lib/api.mts';

export default async function (request: Request) {
  try {
    return await handleApi(request, getUser);
  } catch {
    return jsonResponse({ success: false, message: 'The service is temporarily unavailable. Please try again.' }, 503);
  }
}

export const config: Config = { path: ['/api/*', '/health'] };
