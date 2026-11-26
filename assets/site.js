(function () {
  'use strict';

  // ---------------------------------------------------------------- log
  // Construído via DOM (textContent), nunca innerHTML — sem superfície de XSS.
  var entries = [
    ['ok', '✓', 'svc-backup-financeiro', 'senha rotacionada → key vault'],
    ['crit', '✗', 'app "Script de Provisionamento"', 'Directory.ReadWrite.All · sem dono'],
    ['warn', '⚠', 'fornecedor.vpn.acme', 'inativa há 210 dias · desabilitar'],
    ['ok', '✓', 'admin-generico-ti', 'papel removido · PIM ativado'],
    ['warn', '⚠', 'acesso condicional', 'autenticação legada liberada'],
    ['info', '…', 'pacote de evidências', 'ISO 27001 · PCI DSS · SOX'],
    ['ok', '✓', 'svc-integracao-erp', 'segredo renovado (expirava em 12 d)'],
    ['warn', '⚠', 'conta-terceirizada-suporte', 'sem MFA · sinalizado'],
    ['info', '…', 'alerta enviado', 'Microsoft Teams · #seguranca'],
    ['ok', '✓', 'log de auditoria', 'cadeia sha-256 íntegra · 1.204 eventos']
  ];

  function renderLog() {
    var track = document.getElementById('log-track');
    if (!track) return;
    for (var pass = 0; pass < 2; pass++) { // duplicado para rolagem contínua
      entries.forEach(function (e) {
        var row = document.createElement('div');
        row.className = 'log-row';
        if (pass === 1) row.setAttribute('aria-hidden', 'true');
        [['status ' + e[0], e[1]], ['msg', e[2]], ['meta', e[3]]].forEach(function (p) {
          var s = document.createElement('span');
          s.className = p[0];
          s.textContent = p[1];
          row.appendChild(s);
        });
        track.appendChild(row);
      });
    }
  }

  // ---------------------------------------------------------------- quiz
  var QUESTIONS = [
    { q: 'Vocês têm inventário das contas de serviço, genéricas e de terceiros?',
      o: ['Não sei quantas existem', 'Parcial', 'Completo e atualizado'],
      rec: 'Faça um inventário: classifique contas de serviço, genéricas e de terceiros e atribua um responsável a cada uma.' },
    { q: 'Com que frequência as senhas dessas contas são trocadas?',
      o: ['Nunca / não sei', 'Uma vez por ano', 'A cada 90 dias ou automático'],
      rec: 'Implante rotação automática (≤ 90 dias) — exigência explícita do PCI DSS 4.0 (8.3.9 e 8.6.3).' },
    { q: 'Onde ficam guardadas as senhas compartilhadas?',
      o: ['Planilha, e-mail ou chat', 'Gerenciador de senhas', 'Cofre (Key Vault / PAM)'],
      rec: 'Tire as senhas de planilhas e chats: entregue-as direto num cofre com controle de acesso e trilha.' },
    { q: 'Alguma conta genérica ou de serviço tem papel de administrador?',
      o: ['Sim', 'Não sei', 'Não'],
      rec: 'Remova papéis administrativos de contas não nominais; use contas admin nominais com PIM.' },
    { q: 'Os acessos de fornecedores e convidados são revisados?',
      o: ['Nunca', 'Quando alguém lembra', 'Revisão periódica formal'],
      rec: 'Crie revisões de acesso periódicas para terceiros e desabilite contas inativas há mais de 90 dias.' },
    { q: 'Vocês revisam as permissões de apps e integrações (OAuth)?',
      o: ['Nunca', 'Às vezes', 'Periodicamente'],
      rec: 'Revise apps com permissões amplas (ex.: Mail.ReadWrite, Directory.ReadWrite.All) — é o vetor de ataque que mais cresce.' },
    { q: 'Autenticação legada está bloqueada e admins usam MFA resistente a phishing?',
      o: ['Não / não sei', 'Parcialmente', 'Sim, FIDO2/passkey para admins'],
      rec: 'Bloqueie autenticação legada e exija FIDO2/passkey para administradores — SMS e push caem em phishing AiTM.' },
    { q: 'Como vocês comprovam rotação e revisão numa auditoria?',
      o: ['Prints e planilhas', 'Relatórios manuais do portal', 'Evidência automatizada'],
      rec: 'Automatize a evidência: log imutável e relatórios mapeados para ISO 27001, SOX e PCI DSS.' }
  ];
  var GRADES = [[85, 'Controlado', '#5FAE86'], [70, 'Atenção', '#9CC46A'], [50, 'Exposto', '#F2A93B'],
                [30, 'Alto risco', '#E07B3B'], [0, 'Crítico', '#E0565B']];
  var quizScore = null;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function buildQuiz() {
    var form = document.getElementById('quiz');
    if (!form) return;
    QUESTIONS.forEach(function (item, i) {
      var fs = el('fieldset', 'q');
      var lg = el('legend');
      lg.appendChild(el('span', 'qn', String(i + 1).padStart(2, '0')));
      lg.appendChild(document.createTextNode(item.q));
      fs.appendChild(lg);
      var opts = el('div', 'opts');
      item.o.forEach(function (label, v) {
        var l = el('label');
        var input = document.createElement('input');
        input.type = 'radio';
        input.name = 'q' + i;
        input.value = String(v);
        l.appendChild(input);
        l.appendChild(el('span', null, label));
        opts.appendChild(l);
      });
      fs.appendChild(opts);
      form.appendChild(fs);
    });
    form.addEventListener('change', updateResult);
  }

  function updateResult() {
    var form = document.getElementById('quiz');
    var box = document.getElementById('quiz-result');
    var total = 0, answered = 0, gaps = [];
    QUESTIONS.forEach(function (item, i) {
      var c = form.querySelector('input[name="q' + i + '"]:checked');
      if (!c) return;
      answered++;
      var v = Number(c.value);
      if (i === 3 && v === 1) v = 0; // "não sei" sobre admin conta como risco
      total += v;
      if (v < 2) gaps.push([v, item.rec]);
    });
    if (!answered) return;
    var score = Math.round(100 * total / (answered * 2));
    var grade = GRADES.filter(function (g) { return score >= g[0]; })[0];
    quizScore = answered === QUESTIONS.length ? score : null;

    box.textContent = '';
    var s = el('div', 'qr-score', String(score));
    s.style.color = grade[2];
    box.appendChild(s);
    box.appendChild(el('div', 'qr-label', 'Nível: ' + grade[1]));
    box.appendChild(el('div', 'qr-progress', answered + ' de ' + QUESTIONS.length + ' respondidas'));
    var bar = el('div', 'qr-bar'), fill = el('span');
    fill.style.width = score + '%';
    fill.style.background = grade[2];
    bar.appendChild(fill);
    box.appendChild(bar);

    if (gaps.length) {
      box.appendChild(el('h4', null, 'Prioridades'));
      var ul = el('ul');
      gaps.sort(function (a, b) { return a[0] - b[0]; }).slice(0, 3).forEach(function (g) {
        ul.appendChild(el('li', null, g[1]));
      });
      box.appendChild(ul);
    }
    var cta = el('a', 'btn', 'Quero o diagnóstico real do meu tenant');
    cta.href = '#contato';
    box.appendChild(cta);
  }

  // ---------------------------------------------------------------- lead form
  // Envia para um Google Apps Script que grava numa planilha.
  var WAITLIST_ENDPOINT = 'https://script.google.com/macros/s/AKfycbyJlOlPSbfKD1Msu7uJ3rpdZvb7bdBgS5qjw6lFZRzSaIcMJO3czLj-ubJvmDfLolTM/exec';
  var EMAIL_RE = /^[^\s@<>"']{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$/;
  var FREE_MAIL = /@(gmail|hotmail|outlook|live|yahoo|icloud|bol|uol|terra)\./i;

  function setMsg(form, text, kind) {
    var m = form.querySelector('[data-role="msg"]');
    m.textContent = text;
    m.className = 'fine-print' + (kind ? ' ' + kind : '');
  }

  function wireForm() {
    var form = document.getElementById('waitlist-form');
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var email = form.elements.email, empresa = form.elements.empresa;
      var value = email.value.trim();

      if (form.elements.website.value) { // honeypot preenchido = bot; finge sucesso
        setMsg(form, 'Prontinho — você está na lista.', 'success');
        return;
      }
      if (!EMAIL_RE.test(value)) {
        email.setAttribute('aria-invalid', 'true');
        setMsg(form, 'Confira o e-mail informado.', 'error');
        email.focus();
        return;
      }
      email.removeAttribute('aria-invalid');
      if (!form.elements.consent.checked) {
        setMsg(form, 'Para continuar, marque a autorização de contato.', 'error');
        return;
      }
      try {
        var last = Number(localStorage.getItem('gc_lead_ts') || 0);
        if (Date.now() - last < 60 * 1000) {
          setMsg(form, 'Recebemos seu cadastro há pouco. Obrigado!', 'success');
          return;
        }
      } catch (err) { /* storage bloqueado: segue */ }

      var btn = form.querySelector('button');
      var original = btn.textContent;
      btn.disabled = true;
      btn.textContent = 'Enviando...';

      var body = new URLSearchParams();
      body.set('email', value.slice(0, 254));
      body.set('empresa', empresa.value.trim().slice(0, 120));
      body.set('score', quizScore == null ? '' : String(quizScore));
      body.set('origem', 'landing');

      var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 15000) : null;

      fetch(WAITLIST_ENDPOINT, {
        method: 'POST',
        mode: 'no-cors', // Apps Script não devolve CORS; a gravação acontece mesmo sem lermos a resposta
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        signal: ctrl ? ctrl.signal : undefined
      }).then(function () {
        try { localStorage.setItem('gc_lead_ts', String(Date.now())); } catch (err) {}
        form.reset();
        Array.prototype.forEach.call(form.querySelectorAll('input,button'), function (n) { n.disabled = true; });
        btn.textContent = 'Inscrito ✓';
        setMsg(form, FREE_MAIL.test(value)
          ? 'Prontinho! Dica: um e-mail corporativo agiliza o convite para o diagnóstico.'
          : 'Prontinho — você está na lista. Entraremos em contato para agendar o diagnóstico.', 'success');
      }).catch(function () {
        btn.disabled = false;
        btn.textContent = original;
        setMsg(form, 'Não foi possível enviar agora. Tente novamente em instantes.', 'error');
      }).finally(function () { if (timer) clearTimeout(timer); });
    });
  }

  renderLog();
  buildQuiz();
  wireForm();
})();
