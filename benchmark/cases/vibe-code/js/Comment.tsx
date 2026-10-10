// Browser-side React/TypeScript patterns.
import DOMPurify from "dompurify";
import { marked } from "marked";

const serviceKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY; // expect[VIBE035]
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL; // safe[VIBE035]
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY; // safe[VIBE035] anon key is designed to be public
const publishable = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY; // safe[VIBE035]
const openaiKey = import.meta.env.VITE_OPENAI_API_KEY; // expect[VIBE035] a paid API key shipped to every visitor

export function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: marked(body) }} />; // expect[VIBE031]
}

export function SafeComment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(marked(body)) }} />; // safe[VIBE031]
}

export function render(el: HTMLElement, userComment: string) {
  el.innerHTML = userComment; // expect[VIBE031]
  el.innerHTML = ""; // safe[VIBE031] clearing an element
  el.textContent = userComment; // safe[VIBE031]
  el.insertAdjacentHTML("beforeend", userComment); // expect[VIBE031]
}

export async function askModel(req: { body: { role: string } }, client: any) {
  const systemPrompt = `Act as ${req.body.role}`; // expect[VIBE002]
  const out = await client.chat(systemPrompt);
  eval(out.choices[0].message.content); // expect[VIBE001]
  return [serviceKey, supabaseUrl, anonKey, publishable, openaiKey];
}
