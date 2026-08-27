const messagesEl = document.getElementById('messages');
const promptEl = document.getElementById('prompt');
const sendBtn = document.getElementById('send');

function append(role, text) {
  const div = document.createElement('div');
  div.className = 'msg ' + (role === 'user' ? 'user' : 'assistant');
  div.textContent = (role === 'user' ? 'You: ' : 'Assistant: ') + text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

sendBtn.addEventListener('click', async () => {
  const prompt = promptEl.value.trim();
  if (!prompt) return;
  append('user', prompt);
  promptEl.value = '';
  append('assistant', '...');
  const response = await window.api.ask(prompt);
  // remove the trailing '...' assistant message
  const last = messagesEl.lastChild;
  if (last && last.textContent.startsWith('Assistant: ...')) messagesEl.removeChild(last);

  if (response.ok) append('assistant', response.text);
  else append('assistant', 'Error: ' + response.error);
});

// allow Enter+Ctrl/Cmd to send
promptEl.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') sendBtn.click();
});
