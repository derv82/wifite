const fetchFn = globalThis.fetch ? globalThis.fetch.bind(globalThis) : require('node-fetch');

async function queryOpenAI(prompt) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) throw new Error('OPENAI_API_KEY environment variable is not set');

  const res = await fetchFn('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 800
    })
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`OpenAI error: ${res.status} ${body}`);
  }

  const data = await res.json();
  const msg = data?.choices?.[0]?.message?.content || '';
  return msg.trim();
}

module.exports = { queryOpenAI };
