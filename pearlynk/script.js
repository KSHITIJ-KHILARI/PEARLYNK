/* Pearlynk — Cinematic UI Engine 2026 */
(function () {
  'use strict';

  const RM = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isMobile = /Mobi|Android/i.test(navigator.userAgent);

  /* ══════════════════════════════
     1. SCROLL PROGRESS BAR
  ══════════════════════════════ */
  const progressBar = document.getElementById('scroll-progress');
  if (progressBar) {
    function updateProgress() {
      const s = document.documentElement;
      const pct = (s.scrollTop / (s.scrollHeight - s.clientHeight)) * 100;
      progressBar.style.width = pct + '%';
    }
    window.addEventListener('scroll', updateProgress, { passive: true });
  }

  /* ══════════════════════════════
     2. CURSOR GLOW
  ══════════════════════════════ */
  const cursorGlow = document.getElementById('cursor-glow');
  if (cursorGlow && !RM && !isMobile) {
    let cx = window.innerWidth / 2, cy = window.innerHeight / 2;
    let tx = cx, ty = cy;
    document.addEventListener('mousemove', e => { tx = e.clientX; ty = e.clientY; }, { passive: true });
    (function loop() {
      cx += (tx - cx) * 0.07;
      cy += (ty - cy) * 0.07;
      cursorGlow.style.transform = `translate(${cx - 240}px,${cy - 240}px)`;
      requestAnimationFrame(loop);
    })();
  }

  /* ══════════════════════════════
     3. CANVAS — Multi-layer BG
  ══════════════════════════════ */
  (function initCanvas() {
    if (RM) return;
    const canvas = document.getElementById('bgCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H;

    function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
    resize();
    window.addEventListener('resize', resize, { passive: true });

    /* ── Particles ── */
    const PARTICLE_COUNT = Math.min(70, Math.floor(window.innerWidth * window.innerHeight / 20000));
    const particles = [];

    class Particle {
      constructor() { this.reset(true); }
      reset(init) {
        this.x = init ? Math.random() * W : Math.random() * W;
        this.y = init ? Math.random() * H : H + 4;
        this.r = 0.4 + Math.random() * 1.4;
        this.vx = (Math.random() - 0.5) * 0.2;
        this.vy = -(0.1 + Math.random() * 0.3);
        this.alpha = 0.05 + Math.random() * 0.3;
        this.da = (Math.random() - 0.5) * 0.003;
        this.hue = 200 + Math.random() * 40; // blue-cyan range
      }
      update() {
        this.x += this.vx; this.y += this.vy;
        this.alpha += this.da;
        if (this.alpha < 0.03) this.da = Math.abs(this.da);
        if (this.alpha > 0.35) this.da = -Math.abs(this.da);
        if (this.y < -4 || this.x < -4 || this.x > W + 4) this.reset(false);
      }
      draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${this.hue},80%,65%,${this.alpha})`;
        ctx.fill();
      }
    }
    for (let i = 0; i < PARTICLE_COUNT; i++) particles.push(new Particle());

    /* ── Connection lines ── */
    function drawLinks() {
      const maxD = 110;
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const d2 = dx * dx + dy * dy;
          if (d2 < maxD * maxD) {
            const a = (1 - Math.sqrt(d2) / maxD) * 0.07;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(59,130,246,${a})`;
            ctx.lineWidth = 0.6;
            ctx.stroke();
          }
        }
      }
    }

    /* ── Light streaks ── */
    const streaks = Array.from({ length: 4 }, (_, i) => ({
      x: Math.random() * W, y: Math.random() * H,
      len: 60 + Math.random() * 100,
      speed: 0.4 + Math.random() * 0.8,
      angle: -Math.PI / 4 + (Math.random() - 0.5) * 0.5,
      alpha: 0, maxAlpha: 0.06 + Math.random() * 0.1,
      phase: i * 0.7
    }));

    function drawStreaks(t) {
      streaks.forEach(s => {
        const a = s.maxAlpha * (0.5 + 0.5 * Math.sin(t * s.speed * 0.002 + s.phase));
        const ex = s.x + Math.cos(s.angle) * s.len;
        const ey = s.y + Math.sin(s.angle) * s.len;
        const g = ctx.createLinearGradient(s.x, s.y, ex, ey);
        g.addColorStop(0, `rgba(34,211,238,0)`);
        g.addColorStop(0.5, `rgba(34,211,238,${a})`);
        g.addColorStop(1, `rgba(34,211,238,0)`);
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(ex, ey);
        ctx.strokeStyle = g;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        // slowly drift
        s.x += Math.cos(s.angle + Math.PI / 2) * 0.05;
        s.y += Math.sin(s.angle + Math.PI / 2) * 0.05;
        if (s.x < -200 || s.x > W + 200 || s.y < -200 || s.y > H + 200) {
          s.x = Math.random() * W; s.y = Math.random() * H;
        }
      });
    }

    /* ── Pulsing nodes ── */
    const nodes = Array.from({ length: 6 }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      phase: Math.random() * Math.PI * 2,
      speed: 0.5 + Math.random() * 0.5,
    }));

    function drawNodes(t) {
      nodes.forEach(n => {
        const pulse = 0.5 + 0.5 * Math.sin(t * n.speed * 0.001 + n.phase);
        const r = 2 + pulse * 3;
        const a = 0.08 + pulse * 0.15;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(59,130,246,${a})`;
        ctx.fill();
        // outer ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, r * (2 + pulse), 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(59,130,246,${a * 0.3})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      });
    }

    /* ── Main loop ── */
    let t0 = null;
    function loop(ts) {
      if (!t0) t0 = ts;
      const t = ts - t0;
      ctx.clearRect(0, 0, W, H);
      drawLinks();
      particles.forEach(p => { p.update(); p.draw(); });
      drawStreaks(t);
      drawNodes(t);
      requestAnimationFrame(loop);
    }
    requestAnimationFrame(loop);
  })();

  /* ══════════════════════════════
     4. NAV — scroll class
  ══════════════════════════════ */
  const nav = document.getElementById('nav');
  function syncNav() { nav && nav.classList.toggle('scrolled', window.scrollY > 24); }
  window.addEventListener('scroll', syncNav, { passive: true });
  syncNav();

  /* ══════════════════════════════
     5. MOBILE NAV
  ══════════════════════════════ */
  const navToggle = document.getElementById('navToggle');
  const navMenu = document.getElementById('navMenu');
  if (navToggle && navMenu) {
    navToggle.addEventListener('click', () => {
      const open = navMenu.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', String(open));
    });
    navMenu.querySelectorAll('.nav__link, .btn').forEach(el =>
      el.addEventListener('click', () => {
        navMenu.classList.remove('open');
        navToggle.setAttribute('aria-expanded', 'false');
      })
    );
    document.addEventListener('click', e => {
      if (!nav.contains(e.target) && navMenu.classList.contains('open')) {
        navMenu.classList.remove('open');
        navToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /* ══════════════════════════════
     6. SMOOTH SCROLL
  ══════════════════════════════ */
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', function (e) {
      const id = this.getAttribute('href');
      if (id === '#') return;
      const target = document.querySelector(id);
      if (!target) return;
      e.preventDefault();
      const navH = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--nav-h')) || 68;
      window.scrollTo({ top: target.getBoundingClientRect().top + scrollY - navH - 16, behavior: RM ? 'auto' : 'smooth' });
    });
  });

  /* ══════════════════════════════
     7. SCROLL REVEAL  (directional)
  ══════════════════════════════ */
  function assignRevealDirection() {
    document.querySelectorAll('.reveal').forEach((el, i) => {
      if (el.classList.contains('from-left') || el.classList.contains('from-right') ||
          el.classList.contains('from-top') || el.classList.contains('scale-in')) return;
      // Alternate or use position
      const rect = el.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      if (el.closest('.timeline__item')) el.classList.add('from-left');
      else if (cx < window.innerWidth * 0.33) el.classList.add('from-left');
      else if (cx > window.innerWidth * 0.66) el.classList.add('from-right');
      else el.classList.add('from-bottom');
    });
  }
  assignRevealDirection();

  if ('IntersectionObserver' in window) {
    const obs = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } });
    }, { threshold: 0.07, rootMargin: '0px 0px -24px 0px' });
    document.querySelectorAll('.reveal').forEach(el => obs.observe(el));
  } else {
    document.querySelectorAll('.reveal').forEach(el => el.classList.add('is-visible'));
  }

  /* ══════════════════════════════
     8. GAUGE REVEAL
  ══════════════════════════════ */
  if ('IntersectionObserver' in window) {
    const gObs = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); gObs.unobserve(e.target); } });
    }, { threshold: 0.25 });
    document.querySelectorAll('.gauge-card').forEach(el => gObs.observe(el));
  } else {
    document.querySelectorAll('.gauge-card').forEach(el => el.classList.add('is-visible'));
  }

  /* ══════════════════════════════
     9. RIPPLE EFFECT
  ══════════════════════════════ */
  document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', function (e) {
      if (RM) return;
      const r = this.getBoundingClientRect();
      const size = Math.max(r.width, r.height);
      const span = document.createElement('span');
      span.className = 'ripple';
      span.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - r.left - size / 2}px;top:${e.clientY - r.top - size / 2}px`;
      this.appendChild(span);
      span.addEventListener('animationend', () => span.remove());
    });
  });

  /* ══════════════════════════════
     10. 3-D CARD TILT
  ══════════════════════════════ */
  if (!RM && !isMobile) {
    document.querySelectorAll('.card, .install-card, .gauge-card').forEach(card => {
      card.addEventListener('mousemove', e => {
        const r = card.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width - 0.5;
        const y = (e.clientY - r.top) / r.height - 0.5;
        const ry = x * 8, rx = -y * 8;
        card.style.transform = `translateY(-6px) rotateX(${rx}deg) rotateY(${ry}deg) scale(1.01)`;
        // Moving glow point
        card.style.setProperty('--mx', `${(x + 0.5) * 100}%`);
        card.style.setProperty('--my', `${(y + 0.5) * 100}%`);
      });
      card.addEventListener('mouseleave', () => { card.style.transform = ''; });
    });
  }


  /* ══════════════════════════════
     11. ACTIVE NAV LINK
  ══════════════════════════════ */
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav__link');
  let tick = false;
  function syncActiveLink() {
    const navH = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--nav-h')) || 68;
    let cur = '';
    sections.forEach(s => { if (s.getBoundingClientRect().top <= navH + 80) cur = s.id; });
    navLinks.forEach(l => l.classList.toggle('active', l.getAttribute('href') === `#${cur}`));
    tick = false;
  }
  window.addEventListener('scroll', () => { if (!tick) { requestAnimationFrame(syncActiveLink); tick = true; } }, { passive: true });
  syncActiveLink();

  /* ══════════════════════════════
     12. COPY BUTTONS
  ══════════════════════════════ */
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const url = btn.getAttribute('data-url');
      if (!url) return;
      try {
        await navigator.clipboard.writeText(url);
        const orig = btn.innerHTML;
        btn.innerHTML = `
          <svg class="btn__icon" width="14" height="14" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/></svg>Copied!`;
        btn.classList.add('is-copied');
        setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('is-copied'); }, 2200);
      } catch (_) {}
    });
  });

  /* ══════════════════════════════
     13. FAQ — inject icons safely
  ══════════════════════════════ */
  document.querySelectorAll('.faq__question').forEach(q => {
    if (!q.querySelector('.faq__icon')) {
      const icon = document.createElement('span');
      icon.className = 'faq__icon';
      icon.setAttribute('aria-hidden', 'true');
      q.appendChild(icon);
    }
  });

  /* ══════════════════════════════
     14. MAGNETIC BUTTONS
  ══════════════════════════════ */
  if (!RM && !isMobile) {
    document.querySelectorAll('.btn--primary, .btn--lg').forEach(btn => {
      btn.addEventListener('mousemove', e => {
        const r = btn.getBoundingClientRect();
        const dx = e.clientX - (r.left + r.width / 2);
        const dy = e.clientY - (r.top + r.height / 2);
        btn.style.transform = `translate(${dx * 0.18}px,${dy * 0.18}px) translateY(-2px) scale(1.03)`;
      });
      btn.addEventListener('mouseleave', () => { btn.style.transform = ''; });
    });
  }

})();