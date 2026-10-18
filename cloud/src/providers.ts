import { HttpError, scrub } from "./security";
import { googleTools, googleAccounts } from "./native-google";
export const catalog = [
  {slug:"gmail",name:"Gmail",category:"Email",description:"Read, search and send email through Google's own API.",auth:"oauth",logo_url:"https://www.gstatic.com/images/branding/product/2x/gmail_2020q4_48dp.png"},
  {slug:"googledrive",name:"Google Drive",category:"Files and docs",description:"Find and read your Google Drive files directly.",auth:"oauth",logo_url:"https://www.gstatic.com/images/branding/product/2x/drive_2020q4_48dp.png"},
];
export const toolSpecs: Record<string,{slug:string;read:boolean}> = googleTools;
export function nativeToolList() {
  return Object.entries(googleTools).map(([name,t])=>({name,description:t.description,input_schema:t.input_schema,needs_approval:!t.read,version:"native-v1"}));
}
export const connectionTests: Record<string,{tool:string;args:Record<string,unknown>}> = {
 gmail:{tool:"GMAIL_FETCH_EMAILS",args:{query:"in:inbox",max_results:1}},
 googledrive:{tool:"GOOGLEDRIVE_GET_ABOUT",args:{}}
};
export const accounts = googleAccounts;
export function accountView(a: any) {
  return {
    id: a.id,
    label: a.alias || a.word_id || a.id,
    status:
      a.status === "ACTIVE"
        ? "active"
        : ["INITIATED", "INITIALIZING"].includes(a.status)
          ? "pending"
          : "error",
    connected_at: a.created_at,
  };
}
export function testSummary(slug: string, result: any, secrets: string[] = []) {
  // Field names must still be available when scrubbing, before any text conversion.
  result = scrub(result, secrets);
  if (result.successful === false) return "Connection test failed";
  if (slug === "gmail") {
    const message = result.data?.messages?.[0] || result.data?.emails?.[0];
    if (!message) return "Gmail connected. No inbox messages found.";
    return `Latest email: ${message.subject || "(no subject)"}. From: ${message.sender || message.from || "unknown"}. Date: ${message.messageTimestamp || message.receivedAt || message.date || "unknown"}.`;
  }
  return JSON.stringify(result.data ?? {}).slice(0, 1600);
}
export async function workos(
  env: any,
  path: string,
  data?: unknown,
): Promise<any> {
  if (!env.WORKOS_API_KEY) throw new HttpError(503, "WorkOS setup is pending");
  const r = await fetch("https://api.workos.com/" + path, {
    method: data ? "POST" : "GET",
    headers: {
      Authorization: `Bearer ${env.WORKOS_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: data ? JSON.stringify(data) : undefined,
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok)
    throw new HttpError(502, `WorkOS authentication failed (${r.status})`);
  return r.json();
}
