/* Teaching illustration only. No engine, model, network or storage calls. */
(() => {
  'use strict';
  const scenarios = Object.freeze({
    act: {
      signal: 'A trusted source revision changed.',
      scope: 'One create-only local evidence audit.',
      verdict: 'ACT',
      mark: '↗',
      title: 'Take the bounded next step.',
      reason: 'The signal is new, the goal is relevant, and an existing permission covers the local audit. Check the result before recording success.',
      outside: 'Running a shell command or publishing the result.'
    },
    wait: {
      signal: 'The same revision was already handled.',
      scope: 'One create-only local evidence audit.',
      verdict: 'WAIT',
      mark: '—',
      title: 'No new signal. No new effect.',
      reason: 'The last audit already covers this source state. Deduplication and cooldown favor waiting rather than another artifact or another interruption.',
      outside: 'Repeating the same effect just to look busy.'
    },
    ask: {
      signal: 'A new result could be useful to share.',
      scope: 'Local audit only; publishing is not granted.',
      verdict: 'ASK',
      mark: '?',
      title: 'Surface the missing authority.',
      reason: 'Relevance is not authorization. Ask for a scoped decision; do not publish. A conversational “yes” still needs the separate host authorization path.',
      outside: 'Treating interest, confidence or past success as a grant.'
    }
  });
  const fields = {
    signal: document.querySelector('#signal-text'),
    scope: document.querySelector('#scope-text'),
    verdict: document.querySelector('#verdict'),
    mark: document.querySelector('#verdict-mark'),
    title: document.querySelector('#decision-title'),
    reason: document.querySelector('#decision-reason'),
    outside: document.querySelector('#outside-scope')
  };
  const controls = document.querySelector('.scenario-controls');
  const result = document.querySelector('#docket-result');
  const buttons = Array.from(document.querySelectorAll('[data-scenario]'));
  if (controls && result && Object.values(fields).every(Boolean)) {
    buttons.forEach(button => {
      button.addEventListener('click', () => {
        const name = button.dataset.scenario;
        const scenario = scenarios[name];
        if (!scenario) return;
        Object.entries(fields).forEach(([key, element]) => {
          element.textContent = scenario[key];
        });
        result.dataset.state = name;
        buttons.forEach(item => {
          item.setAttribute('aria-pressed', String(item === button));
        });
      });
    });
    controls.hidden = false;
  }
  const copyButton = document.querySelector('.copy-button');
  const commands = document.querySelector('#setup-commands');
  const status = document.querySelector('#copy-status');
  if (copyButton && commands && status && navigator.clipboard?.writeText) {
    copyButton.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(commands.textContent);
        status.textContent = 'Commands copied. Review them before running.';
      } catch {
        status.textContent = 'Clipboard unavailable. Select and copy the commands above.';
      }
    });
    copyButton.hidden = false;
  }
})();
