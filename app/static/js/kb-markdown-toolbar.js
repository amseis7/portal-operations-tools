(function () {
  function fireInput(textarea) {
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  }

  // Deliberately uses the deprecated execCommand("insertText", ...) instead
  // of a plain `textarea.value = ...` assignment: assigning .value directly
  // wipes the browser's native undo buffer, so Ctrl+Z stops working after a
  // toolbar click. execCommand("insertText") is treated as a real editing
  // action and is pushed onto that same native undo stack. Falls back to
  // setRangeText() (no undo-buffer guarantee, but still correct text) for
  // browsers where insertText isn't supported. This is the ONLY place in
  // this file allowed to touch textarea.value — every action goes through
  // this one helper so the execCommand usage stays in one spot.
  function replaceRangePreservingUndo(textarea, start, end, replacement) {
    textarea.focus();
    textarea.setSelectionRange(start, end);

    let usedInsertText = false;
    try {
      if (document.queryCommandSupported && document.queryCommandSupported('insertText')) {
        usedInsertText = document.execCommand('insertText', false, replacement);
      }
    } catch (e) {
      usedInsertText = false;
    }

    if (!usedInsertText) {
      textarea.setRangeText(replacement, start, end, 'end');
    }
  }

  function wrapSelection(textarea, before, after) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.slice(start, end);

    replaceRangePreservingUndo(textarea, start, end, before + selected + after);

    if (start === end) {
      textarea.setSelectionRange(start + before.length, start + before.length);
    } else {
      const cursor = start + before.length + selected.length + after.length;
      textarea.setSelectionRange(cursor, cursor);
    }

    fireInput(textarea);
    textarea.focus();
  }

  function prefixLines(textarea, prefixForLine) {
    const value = textarea.value;
    let lineStart = value.lastIndexOf('\n', textarea.selectionStart - 1) + 1;
    let lineEnd = value.indexOf('\n', textarea.selectionEnd);
    if (lineEnd === -1) lineEnd = value.length;

    const span = value.slice(lineStart, lineEnd);
    const lines = span.split('\n');
    const prefixed = lines.map(function (line, i) { return prefixForLine(line, i); }).join('\n');

    replaceRangePreservingUndo(textarea, lineStart, lineEnd, prefixed);
    textarea.setSelectionRange(lineStart, lineStart + prefixed.length);

    fireInput(textarea);
    textarea.focus();
  }

  function insertBlock(textarea, builder) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.slice(start, end);
    const result = builder(selected);

    replaceRangePreservingUndo(textarea, start, end, result.text);
    textarea.setSelectionRange(start + result.selectStart, start + result.selectEnd);

    fireInput(textarea);
    textarea.focus();
  }

  const ACTIONS = {
    heading: function (textarea, level) {
      const marker = '#'.repeat(Number(level)) + ' ';
      prefixLines(textarea, function (line) {
        return marker + line.replace(/^#{1,6}\s+/, '');
      });
    },
    bold: function (textarea) { wrapSelection(textarea, '**', '**'); },
    italic: function (textarea) { wrapSelection(textarea, '*', '*'); },
    'bold-italic': function (textarea) { wrapSelection(textarea, '***', '***'); },
    'list-bullet': function (textarea) {
      prefixLines(textarea, function (line) {
        return '- ' + line.replace(/^-\s+/, '');
      });
    },
    'list-number': function (textarea) {
      prefixLines(textarea, function (line, i) {
        return (i + 1) + '. ' + line.replace(/^\d+\.\s+/, '');
      });
    },
    quote: function (textarea) {
      prefixLines(textarea, function (line) {
        return '> ' + line.replace(/^>\s?/, '');
      });
    },
    hr: function (textarea) {
      insertBlock(textarea, function () {
        const text = '\n\n---\n\n';
        return { text: text, selectStart: text.length, selectEnd: text.length };
      });
    },
    'code-inline': function (textarea) { wrapSelection(textarea, '`', '`'); },
    'code-block': function (textarea) {
      insertBlock(textarea, function (selected) {
        if (selected) {
          const text = '```\n' + selected + '\n```';
          return { text: text, selectStart: text.length, selectEnd: text.length };
        }
        const text = '```\n\n```';
        return { text: text, selectStart: 4, selectEnd: 4 };
      });
    },
    link: function (textarea) {
      insertBlock(textarea, function (selected) {
        if (selected) {
          const text = '[' + selected + '](https://)';
          const urlStart = text.indexOf('https://');
          return { text: text, selectStart: urlStart, selectEnd: urlStart + 'https://'.length };
        }
        const text = '[texto](https://)';
        return { text: text, selectStart: 1, selectEnd: 1 + 'texto'.length };
      });
    },
    table: function (textarea) {
      insertBlock(textarea, function () {
        const text = '| Columna 1 | Columna 2 |\n| --- | --- |\n| Valor 1 | Valor 2 |';
        const colStart = text.indexOf('Columna 1');
        return { text: text, selectStart: colStart, selectEnd: colStart + 'Columna 1'.length };
      });
    },
  };

  document.addEventListener('DOMContentLoaded', function () {
    const toolbar = document.querySelector('[data-markdown-toolbar]');
    if (!toolbar) return;

    const LABELS = { problem_md: 'Problema', solution_md: 'Solución' };
    const targets = toolbar.dataset.markdownTargets.split(',')
      .map(function (id) { return document.getElementById(id); })
      .filter(Boolean);
    const indicator = document.getElementById('kb-md-current-field');
    let currentTarget = targets[0] || null;

    targets.forEach(function (ta) {
      ta.addEventListener('focus', function () {
        currentTarget = ta;
        if (indicator) indicator.textContent = 'Editando: ' + (LABELS[ta.id] || ta.id);
      });
    });

    toolbar.querySelectorAll('button[data-md-action]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (!currentTarget) return;
        const action = ACTIONS[btn.dataset.mdAction];
        if (action) action(currentTarget, btn.dataset.mdLevel);
      });
    });
  });
})();
