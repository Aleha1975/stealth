// Loophole hero: wormhole funnel, plain canvas 2D, no libraries.
const cv = document.getElementById("funnel");
if (cv) {
  const ctx = cv.getContext("2d", { alpha: false });
  const hero = cv.parentElement;
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const TAU = Math.PI * 2, SEG = 44, TILT = 0.34, cT = Math.cos(TILT), sT = Math.sin(TILT);
  let W = 0, H = 0, dpr = 1, strands = [], dots = [], visible = true, raf = 0, t0 = performance.now(), running = false;
  const rnd = (() => { let s = 7; return () => (s = (s * 16807) % 2147483647) / 2147483647; })();

  function build() {
    const small = W < 700, area = Math.min(1, (W * H) / (1440 * 900));
    const n = Math.round((small ? 380 : 620) * Math.max(.7, area) / (dpr > 1.5 && small ? 1.1 : 1));
    strands = []; for (let i = 0; i < n; i++) strands.push({ th: rnd() * TAU, tw: 1.1 + rnd() * .9, sp: .6 + rnd() * .8, off: (rnd() - .5) * .07, a: .35 + rnd() * .65 });
    dots = []; const nd = small ? 260 : 700;
    for (let i = 0; i < nd; i++) dots.push({ th: rnd() * TAU, s: rnd() * 2 - 1, j: 1 + (rnd() - .5) * .5, sp: .6 + rnd() * .8, a: .2 + rnd() * .7, z: rnd() });
  }
  // s in [-1,1]: top .. bottom. Returns radius and height (world units, funnel radius ~1 at the top).
  function prof(s, off) {
    const u = (s + 1) / 2, neck = .045;
    let r = Math.sqrt(neck * neck + Math.pow((u - .46) * 1.25, 2) * 1.1) * (1 + off);
    let y = -1 + u * 2;
    const d = Math.max(0, (u - .62) / .38), f = d * d * (3 - 2 * d);
    r += f * f * 2.4 + f * .5; y = y * (1 - f * .9) + .62 * f * .9 + 0;
    return [r, y];
  }
  function size() {
    dpr = Math.min(2, devicePixelRatio || 1);
    const r = hero.getBoundingClientRect(); W = r.width; H = r.height;
    cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); cv.style.width = W + "px"; cv.style.height = H + "px";
    build(); draw(t0);
  }
  const B = 5, paths = [];
  function draw(now) {
    const t = reduce ? 3.2 : (now - t0) / 1000;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = "#000"; ctx.fillRect(0, 0, W, H);
    const cx = W * .5, sc = Math.min(W * .4, H * .62) * (W < 700 ? 1.8 : 1), cy = H * (W < 700 ? .44 : .47);
    const proj = (th, rr, y, out) => { const x = Math.cos(th) * rr, z = Math.sin(th) * rr; out[0] = cx + x * sc; out[1] = cy + (y * cT + z * sT) * sc * .72; out[2] = z; };
    const p = [0, 0, 0];
    for (let b = 0; b < B; b++) paths[b] = new Path2D();
    for (const st of strands) {
      let px = 0, py = 0;
      for (let k = 0; k <= SEG; k++) {
        const s = -1 + 2 * k / SEG, [r, y] = prof(s, st.off);
        const th = st.th + st.tw * s * 1.2 + t * .09 * st.sp / (.35 + r * .6);
        proj(th, r, y, p);
        if (k) {
          const dep = Math.max(0, Math.min(.999, (p[2] / (r + .01)) * .5 + .5)), bi = Math.min(B - 1, (dep * st.a * B) | 0);
          paths[bi].moveTo(px, py); paths[bi].lineTo(p[0], p[1]);
        }
        px = p[0]; py = p[1];
      }
    }
    ctx.lineWidth = .7; ctx.lineCap = "round";
    for (let b = 0; b < B; b++) { ctx.strokeStyle = "rgba(255,255,255," + (.05 + b * .075).toFixed(3) + ")"; ctx.stroke(paths[b]); }
    for (const d of dots) {
      const [r, y] = prof(d.s, 0), th = d.th + t * .09 * d.sp / (.35 + r * .6) + d.s * 1.4;
      proj(th, r * d.j, y, p);
      ctx.fillStyle = "rgba(255,255,255," + (d.a * (.3 + d.z * .6) * (p[2] > 0 ? 1 : .55)).toFixed(2) + ")";
      ctx.fillRect(p[0], p[1], d.z > .85 ? 1.6 : 1, d.z > .85 ? 1.6 : 1);
    }
    // soft glow at the waist and edge vignette
    const g = ctx.createRadialGradient(cx, cy - sc * .1, 0, cx, cy - sc * .1, sc * .22);
    g.addColorStop(0, "rgba(255,255,255,.10)"); g.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
    const v = ctx.createLinearGradient(0, H * .78, 0, H); v.addColorStop(0, "rgba(0,0,0,0)"); v.addColorStop(1, "rgba(0,0,0,1)");
    ctx.fillStyle = v; ctx.fillRect(0, H * .78, W, H * .22);
  }
  function frame(now) { raf = 0; if (!running) return; draw(now); raf = requestAnimationFrame(frame); }
  function update() {
    const go = !reduce && visible && !document.hidden;
    if (go && !running) { running = true; raf = requestAnimationFrame(frame); }
    else if (!go && running) { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
  }
  new IntersectionObserver(es => { visible = es[0].isIntersecting; update(); }).observe(hero);
  document.addEventListener("visibilitychange", update);
  let rt = 0; new ResizeObserver(() => { clearTimeout(rt); rt = setTimeout(() => { size(); update(); }, 120); }).observe(hero);
  size(); update();
}
