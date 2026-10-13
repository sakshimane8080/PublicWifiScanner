type Account = { name?: string; email?: string };

export function buildRiskPayload(wifiType: string) {
  const profiles = {
    open: {
      network: 'Open Public WiFi', risk: 85, level: 'HIGH RISK', color: '#fb7185',
      threats: ['Possible data interception', 'Fake WiFi hotspot risks', 'Man-in-the-Middle attack risks', 'Packet sniffing risks'],
      advice: 'Avoid sensitive activities on unknown open networks.',
    },
    weak: {
      network: 'Weak Secured WiFi', risk: 50, level: 'MEDIUM RISK', color: '#fbbf24',
      threats: ['Weak password risks', 'Unauthorized access risks', 'Suspicious login page risks'],
      advice: 'Use a strong password and verify the network.',
    },
    strong: {
      network: 'Strong Secured WiFi', risk: 15, level: 'LOWER RISK', color: '#4ade80',
      threats: ['Misconfigured security risks', 'Fake network name risks', 'Risks from outdated devices'],
      advice: 'Keep devices updated and continue safe browsing.',
    },
  };
  if (wifiType !== 'open' && wifiType !== 'weak' && wifiType !== 'strong') return null;
  return profiles[wifiType];
}

export function jsonResponse(payload: unknown, status = 200, headers: Record<string, string> = {}) {
  return Response.json(payload, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

export async function handleApi(request: Request, loadUser: () => Promise<Account | null>) {
  const path = new URL(request.url).pathname;
  if (path === '/health' && request.method === 'GET') return jsonResponse({ status: 'ok' });
  const expectedMethod = path === '/api/me' ? 'GET' : path === '/api/risk' || path === '/api/report' ? 'POST' : null;
  if (!expectedMethod) return jsonResponse({ success: false, message: 'API route not found.' }, 404);
  if (request.method !== expectedMethod) {
    return jsonResponse({ success: false, message: 'Method not allowed.' }, 405, { Allow: expectedMethod });
  }
  if (request.method === 'POST') {
    const origin = request.headers.get('Origin');
    if (!origin || origin !== new URL(request.url).origin) {
      return jsonResponse({ success: false, message: 'Request origin is not allowed.' }, 403);
    }
  }
  const user = await loadUser();
  if (!user) return jsonResponse({ success: false, message: 'Please log in again.' }, 401);
  if (path === '/api/me') return jsonResponse({ name: user.name || user.email || 'Member', email: user.email });
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) {
    return jsonResponse({ success: false, message: 'Send a JSON request.' }, 415);
  }
  const declaredLength = Number(request.headers.get('Content-Length'));
  if (declaredLength > 16384) return jsonResponse({ success: false, message: 'Request body is too large.' }, 413);
  const body = await request.text();
  if (Buffer.byteLength(body) > 16384) return jsonResponse({ success: false, message: 'Request body is too large.' }, 413);
  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    return jsonResponse({ success: false, message: 'Send valid JSON.' }, 400);
  }
  const risk = typeof payload?.wifiType === 'string' ? buildRiskPayload(payload.wifiType.trim().toLowerCase()) : null;
  if (!risk) return jsonResponse({ success: false, message: 'Choose a valid network type.' }, 400);
  if (path === '/api/risk') return jsonResponse(risk);
  const report = `PUBLIC WIFI RISK SCANNER REPORT\n\nWiFi Type: ${risk.network}\nRisk Level: ${risk.level}\nSimulated Risk Score: ${risk.risk}%\n\nSafety Tips:\n1. Avoid banking on public WiFi.\n2. Use HTTPS websites.\n3. Disable automatic WiFi connection.\n4. Use a trusted VPN when appropriate.\n\nEducational simulation only. This is not a real network scan.`;
  return new Response(report, {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'attachment; filename="WiFi_Risk_Report.txt"',
    },
  });
}
