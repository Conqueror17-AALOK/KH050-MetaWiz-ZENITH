(function () {
  'use strict';

  /* ========================================================
     1. INTERACTIVE ATTACK PATH SIMULATOR
  ======================================================== */

  const SCENARIOS = {
    rdp: {
      nodes: [
        { name: 'user-3', type: 'User' },
        { name: 'HOST-5', type: 'Machine' },
        { name: 'svc-account-0', type: 'ServiceAccount' },
        { name: 'Domain Admins', type: 'Tier-0 Group', critical: true },
      ],
      edges: [
        { rel: 'CanRDP', cost: 3 },
        { rel: 'HasSession', cost: 2, chokepoint: true },
        { rel: 'CanResetPasswordOf', cost: 4 },
      ],
      hops: 3,
      cost: 9,
      risk: 61,
      level: 'HIGH THREAT',
      desc: 'Attacker leverages low-privilege RDP access, extracts cached credentials of a backup account, and forces a password reset on Domain Admins.',
      chokeDesc: "Severing the cached session on 'HOST-5' eliminates the lateral bridge to Tier-0 Domain Admins.",
    },
    gpo: {
      nodes: [
        { name: 'user-42', type: 'User' },
        { name: 'GPO-Lockdown', type: 'GPO Policy' },
        { name: 'WKSTN-12', type: 'Machine' },
        { name: 'svc-gitlab-runner', type: 'ServiceAccount' },
        { name: 'Domain Admins', type: 'Tier-0 Group', critical: true },
      ],
      edges: [
        { rel: 'GenericAll', cost: 1 },
        { rel: 'GPOAppliedTo', cost: 3, chokepoint: true },
        { rel: 'HasSession', cost: 2 },
        { rel: 'AdminTo', cost: 2 },
      ],
      hops: 4,
      cost: 8,
      risk: 62,
      level: 'HIGH THREAT',
      desc: 'Adversary abuses GenericAll ACL rights over a Group Policy Object, propagating malicious local admin tasks to workstations upon policy refresh.',
      chokeDesc: "Restricting GPO deployment links isolates workstation machines from unauthorized administrative policy push.",
    },
    kerb: {
      nodes: [
        { name: 'user-29', type: 'User' },
        { name: 'svc-scanner', type: 'ServiceAccount' },
        { name: 'DC-01.corp.local', type: 'Domain Controller', critical: true },
        { name: 'Domain Admins', type: 'Tier-0 Group', critical: true },
      ],
      edges: [
        { rel: 'Kerberoastable', cost: 2, chokepoint: true },
        { rel: 'AdminTo', cost: 2 },
        { rel: 'AdminTo', cost: 2 },
      ],
      hops: 3,
      cost: 6,
      risk: 71,
      level: 'CRITICAL THREAT',
      desc: 'Adversary requests offline Kerberos TGS tickets for SPN-bearing accounts, cracks the hash, and escalates directly to the Primary Domain Controller.',
      chokeDesc: "Migrating service account 'svc-scanner' to Group Managed Service Accounts (gMSA) fully neutralizes offline Kerberoasting.",
    },
  };

  let currentScenarioKey = 'rdp';
  let isRemediated = false;

  const chainContainer = document.getElementById('sim-chain-container');
  const riskBadge = document.getElementById('sim-risk-badge');
  const gaugeFill = document.getElementById('sim-gauge-fill');
  const hopsVal = document.getElementById('sim-hops-val');
  const costVal = document.getElementById('sim-cost-val');
  const descVal = document.getElementById('sim-desc-val');
  const chokeBtn = document.getElementById('sim-choke-btn');
  const remedyMsg = document.getElementById('sim-remedy-message');

  function renderSimulator() {
    const sc = SCENARIOS[currentScenarioKey];
    hopsVal.textContent = sc.hops;
    costVal.textContent = sc.cost;
    descVal.textContent = sc.desc;

    if (isRemediated) {
      riskBadge.textContent = 'NEUTRALIZED';
      riskBadge.style.background = 'rgba(16, 185, 129, 0.2)';
      riskBadge.style.color = '#34d399';
      riskBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      gaugeFill.style.width = '0%';
      gaugeFill.style.background = '#10b981';

      chokeBtn.classList.add('remediated');
      chokeBtn.innerHTML = '✓ Chokepoint Severed (Click to Restore)';

      remedyMsg.style.display = 'block';
      remedyMsg.style.background = 'rgba(16, 185, 129, 0.15)';
      remedyMsg.style.border = '1px solid rgba(16, 185, 129, 0.4)';
      remedyMsg.style.color = '#34d399';
      remedyMsg.innerHTML = `<strong>REMEDIATION VERIFIED:</strong> ${sc.chokeDesc} Attack path eliminated with zero disruption.`;
    } else {
      const isCritical = sc.risk >= 70;
      riskBadge.textContent = sc.level;
      riskBadge.style.background = isCritical ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)';
      riskBadge.style.color = isCritical ? '#f87171' : '#fbbf24';
      riskBadge.style.borderColor = isCritical ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)';
      gaugeFill.style.width = `${sc.risk}%`;
      gaugeFill.style.background = isCritical
        ? 'linear-gradient(90deg, #f59e0b, #ef4444)'
        : 'linear-gradient(90deg, #3b82f6, #f59e0b)';

      chokeBtn.classList.remove('remediated');
      chokeBtn.innerHTML = '⚡ Sever Chokepoint Privilege';
      remedyMsg.style.display = 'none';
    }

    // Build visual chain HTML
    let html = '';
    for (let i = 0; i < sc.nodes.length; i++) {
      const node = sc.nodes[i];
      const isLast = i === sc.nodes.length - 1;
      const edge = sc.edges[i];

      const nodeClass = ['sim-node'];
      if (node.critical) nodeClass.push('critical');
      if (isRemediated && edge && edge.chokepoint) nodeClass.push('chokepoint');

      html += `
        <div class="${nodeClass.join(' ')}">
          <div class="sim-node-title">${node.name}</div>
          <div class="sim-node-type">${node.type}</div>
        </div>
      `;

      if (!isLast && edge) {
        const isCut = isRemediated && edge.chokepoint;
        html += `
          <div class="sim-arrow" style="${isCut ? 'opacity: 0.35;' : ''}">
            <span class="sim-arrow-label" style="${isCut ? 'text-decoration: line-through; color: #ef4444;' : ''}">
              ${isCut ? '✂️ SEVERED' : edge.rel}
            </span>
            <span class="sim-arrow-line">${isCut ? '✕' : '→'}</span>
          </div>
        `;
      }
    }

    chainContainer.innerHTML = html;
  }

  // Simulator Tab clicks
  document.querySelectorAll('.sim-tab-btn').forEach((btn) => {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.sim-tab-btn').forEach((b) => b.classList.remove('active'));
      this.classList.add('active');
      currentScenarioKey = this.dataset.scenario;
      isRemediated = false;
      renderSimulator();
    });
  });

  // Chokepoint Toggle click
  if (chokeBtn) {
    chokeBtn.addEventListener('click', function () {
      isRemediated = !isRemediated;
      renderSimulator();
    });
  }

  // Initial render
  if (chainContainer) {
    renderSimulator();
  }

  /* ========================================================
     2. INTERACTIVE RISK SCORE CALCULATOR
  ======================================================== */

  const hopsSlider = document.getElementById('calc-hops-slider');
  const costSlider = document.getElementById('calc-cost-slider');
  const critSelect = document.getElementById('calc-crit-select');

  const hopsDisplay = document.getElementById('calc-hops-display');
  const costDisplay = document.getElementById('calc-cost-display');
  const critDisplay = document.getElementById('calc-crit-display');

  const scoreVal = document.getElementById('calc-score-val');
  const levelBadge = document.getElementById('calc-level-badge');

  function calculateRisk() {
    if (!hopsSlider || !costSlider || !critSelect) return;
    const hops = parseInt(hopsSlider.value, 10);
    const cost = parseInt(costSlider.value, 10);
    const critBonus = parseInt(critSelect.value, 10);

    hopsDisplay.textContent = `${hops} hop${hops > 1 ? 's' : ''}`;
    costDisplay.textContent = `${cost} points`;
    critDisplay.textContent = critBonus > 0 ? 'Tier-0 (Critical Asset)' : 'Standard Workstation';

    // Formula: max(5, min(100, 85 + Crit - (Cost * 3.5) - (Hops * 2.5)))
    const raw = 85 + critBonus - cost * 3.5 - hops * 2.5;
    const score = Math.max(5, Math.min(100, Math.round(raw)));

    scoreVal.textContent = score;

    if (score >= 70) {
      scoreVal.style.color = 'var(--accent-red)';
      levelBadge.className = 'badge badge-critical';
      levelBadge.textContent = 'CRITICAL THREAT';
    } else if (score >= 45) {
      scoreVal.style.color = 'var(--accent-amber)';
      levelBadge.className = 'badge badge-high';
      levelBadge.textContent = 'HIGH THREAT';
    } else {
      scoreVal.style.color = 'var(--accent-cyan)';
      levelBadge.className = 'badge badge-medium';
      levelBadge.textContent = 'MEDIUM RISK';
    }
  }

  if (hopsSlider && costSlider && critSelect) {
    hopsSlider.addEventListener('input', calculateRisk);
    costSlider.addEventListener('input', calculateRisk);
    critSelect.addEventListener('change', calculateRisk);
    calculateRisk();
  }

  /* ========================================================
     3. INTERACTIVE FAQ ACCORDION
  ======================================================== */

  document.querySelectorAll('.faq-trigger').forEach((trigger) => {
    trigger.addEventListener('click', function () {
      const item = this.parentElement;
      const isOpen = item.classList.contains('open');

      // Close all other items
      document.querySelectorAll('.faq-item').forEach((i) => i.classList.remove('open'));

      if (!isOpen) {
        item.classList.add('open');
      }
    });
  });

  /* ========================================================
     4. COUNT-UP ANIMATED METRICS
  ======================================================== */

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  function animateStat(el) {
    const target = parseFloat(el.dataset.target);
    const suffix = el.dataset.suffix || '';
    const numEl = el.querySelector('.num');
    if (!numEl) return;

    const duration = 1400;
    let startTime = null;

    function step(timestamp) {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = easeOutCubic(progress);
      const current = Math.round(target * eased);
      numEl.textContent = current;

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        numEl.textContent = target;
      }
    }

    requestAnimationFrame(step);
  }

  const statEls = document.querySelectorAll('.stat');
  let hasAnimatedStats = false;

  if ('IntersectionObserver' in window && statEls.length > 0) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && !hasAnimatedStats) {
            hasAnimatedStats = true;
            statEls.forEach(animateStat);
            observer.disconnect();
          }
        });
      },
      { threshold: 0.2 }
    );
    observer.observe(statEls[0].parentElement);
  } else {
    statEls.forEach(animateStat);
  }

  /* ========================================================
     5. SMOOTH NAV ACTIVE STATE ON SCROLL
  ======================================================== */

  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('.section');

  window.addEventListener('scroll', () => {
    let current = 'hero';
    sections.forEach((section) => {
      const sectionTop = section.offsetTop - 120;
      if (window.scrollY >= sectionTop) {
        current = section.getAttribute('id');
      }
    });

    navLinks.forEach((link) => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${current}`) {
        link.classList.add('active');
      }
    });
  });
})();
