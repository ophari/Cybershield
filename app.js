/**
 * CyberShield — Sistem Simulasi Keamanan Jaringan & Firewall Logis
 * Mata Kuliah : Keamanan Jaringan
 * Nama        : Muhamad Yusuf
 * NIM         : 242502040108
 * Kelas       : 3TI01
 * Integrasi   : Supabase Cloud PostgreSQL (Realtime Sync)
 */

"use strict";

// ========================================================
// UTILITAS PEMBANTU
// ========================================================
const $ = (id) => document.getElementById(id);
const ri = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const pad2 = (n) => String(n).padStart(2, "0");
const fmt = (n) => Number(n).toLocaleString("id-ID");
const nowTime = () => {
  const d = new Date();
  return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
};
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));

// Pemetaan Port ke Nama Layanan Jaringan
const PORT_NAMES = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  993: "IMAPS",
  1433: "MSSQL",
  3306: "MySQL",
  3389: "RDP",
  4444: "Malware C2",
  8080: "HTTP-Alt",
};

const SENSITIVE_PORTS = [21, 22, 23, 445, 1433, 3306, 3389, 4444];
const isInternal = (ip) =>
  ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.");

// ========================================================
// EFEK SUARA SINTESIS (WEB AUDIO API)
// ========================================================
let audioEnabled = false;
let audioCtx = null;

function playTone(freq, type, duration, vol = 0.08) {
  if (!audioEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(vol, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch (e) {}
}

function playAllowedSound() {
  playTone(880, "sine", 0.06, 0.03);
}

function playBlockedSound() {
  playTone(220, "sawtooth", 0.14, 0.07);
}

// ========================================================
// KONFIGURASI SUPABASE CLOUD & REPLIKASI ONLINE
// ========================================================
const DEFAULT_SUPABASE_URL = "";
let supabaseClient = null;
let isSupabaseOnline = false;
let supabaseRealtimeChannel = null;

const DEFAULT_RULES = [
  { id: 1, name: "Izinkan HTTP Publik", ip: "*", port: 80, proto: "TCP", action: "Izinkan", active: true },
  { id: 2, name: "Izinkan HTTPS Publik", ip: "*", port: 443, proto: "TCP", action: "Izinkan", active: true },
  { id: 3, name: "Blokir Telnet", ip: "*", port: 23, proto: "TCP", action: "Blokir", active: true },
  { id: 4, name: "Blokir RDP Eksternal", ip: "203.0.113.0/24", port: 3389, proto: "TCP", action: "Blokir", active: true },
];

const DEFAULT_BLACKLIST = [
  { ip: "45.135.210.19", reason: "Serangan DDoS", added: "28 Okt 2026", hits: 412 },
  { ip: "103.75.196.44", reason: "Brute Force SSH", added: "30 Okt 2026", hits: 268 },
  { ip: "185.220.101.7", reason: "Port Scan", added: "01 Nov 2026", hits: 187 },
  { ip: "91.240.118.12", reason: "Malware C2", added: "03 Nov 2026", hits: 96 },
  { ip: "193.142.59.88", reason: "Percobaan SQL Injection", added: "05 Nov 2026", hits: 74 },
];

// ========================================================
// STATUS GLOBAL (STATE)
// ========================================================
const state = {
  total: 124580,
  allowed: 118920,
  blocked: 5660,
  running: false,
  firewallOn: true,

  // Metrik Kesehatan Sistem
  cpu: 18,
  mem: 42,
  bw: 1.4,
  cpuTarget: 18,
  memTarget: 42,
  bwTarget: 1.4,

  // Penghitung per detik untuk grafik
  tickAllowed: 0,
  tickBlocked: 0,

  // Metrik Sesi Saat Ini
  sessTotal: 0,
  sessAllowed: 0,
  sessBlocked: 0,

  // Aturan Firewall & Blacklist
  rules: JSON.parse(JSON.stringify(DEFAULT_RULES)),
  nextRuleId: 5,
  blacklist: JSON.parse(JSON.stringify(DEFAULT_BLACKLIST)),

  // Log & Peringatan Keamanan
  logs: [],
  alerts: [],

  // Frekuensi port yang diblokir
  portBlocks: { 22: 1842, 445: 1318, 3389: 976, 23: 751, 1433: 508, 4444: 265 },

  // Data Deret Waktu untuk Canvas Chart (40 titik)
  seriesA: [], // Paket Diizinkan
  seriesB: [], // Paket Diblokir

  sshAttempts: {},
  activeAttacks: {},
};

// Prefill grafik awal
for (let i = 0; i < 40; i++) {
  state.seriesA.push(ri(2, 6));
  state.seriesB.push(ri(0, 2));
}

// ========================================================
// TOAST NOTIFIKASI
// ========================================================
function toast(title, sub, kind = "cyan") {
  const container = $("toasts");
  if (!container) return;

  const t = document.createElement("div");
  t.className = "pointer-events-auto p-3.5 rounded-xl bg-cyber-900/95 border backdrop-blur-md shadow-2xl transition-all duration-300 flex items-start gap-3 animate-feed-in text-xs";

  let borderClass = "border-neon-cyan/40 shadow-glow-cyan";
  let iconSvg = `<svg class="w-4 h-4 text-neon-cyan flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`;

  if (kind === "red") {
    borderClass = "border-neon-red/40 shadow-glow-red";
    iconSvg = `<svg class="w-4 h-4 text-neon-red flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
  } else if (kind === "green") {
    borderClass = "border-neon-green/40 shadow-glow-green";
    iconSvg = `<svg class="w-4 h-4 text-neon-green flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
  } else if (kind === "amber") {
    borderClass = "border-amber-400/40";
    iconSvg = `<svg class="w-4 h-4 text-amber-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
  }

  t.className += " " + borderClass;
  t.innerHTML = `
    ${iconSvg}
    <div class="flex-1 min-w-0">
      <b class="text-white block font-medium">${esc(title)}</b>
      ${sub ? `<span class="text-slate-400 block mt-0.5 text-[11px]">${esc(sub)}</span>` : ""}
    </div>
  `;

  container.appendChild(t);

  setTimeout(() => {
    t.style.opacity = "0";
    t.style.transform = "translateY(8px)";
    setTimeout(() => t.remove(), 320);
  }, 3500);
}

// ========================================================
// GENERATOR & VALIDASI IP JARINGAN
// ========================================================
function randPublicIp() {
  let a = ri(11, 223);
  if (a === 192 || a === 172 || a === 10 || a === 127) a = 45;
  return a + "." + ri(0, 255) + "." + ri(0, 255) + "." + ri(2, 254);
}

const randInternalIp = () => pick(["192.168.1.", "192.168.0.", "10.10.1."]) + ri(2, 120);

const validIpOrCidr = (s) => {
  if (s === "*") return true;
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/;
  if (!cidrRegex.test(s)) return false;
  const parts = s.split("/")[0].split(".");
  return parts.every((p) => +p >= 0 && +p <= 255);
};

function ipToLong(ip) {
  if (!ip || typeof ip !== "string") return 0;
  const parts = ip.split(".");
  if (parts.length !== 4) return 0;
  return parts.reduce((acc, oct) => ((acc << 8) + (parseInt(oct, 10) || 0)) >>> 0, 0);
}

function matchIp(ruleIp, packetIp) {
  if (!ruleIp || !packetIp) return false;
  if (ruleIp === "*" || ruleIp === "0.0.0.0/0") return true;
  if (ruleIp === packetIp) return true;
  if (ruleIp.includes("/")) {
    const [baseIp, mask] = ruleIp.split("/");
    const m = parseInt(mask, 10);
    if (isNaN(m) || m < 0 || m > 32) return false;
    if (m === 0) return true;
    // Hitung bitmask 32-bit (unsigned 32-bit integer)
    const maskBits = m === 32 ? 0xffffffff : ((0xffffffff << (32 - m)) >>> 0);
    return (ipToLong(packetIp) & maskBits) === (ipToLong(baseIp) & maskBits);
  }
  return false;
}

// ========================================================
// MESIN EVALUASI JARINGAN (CORE NETWORK FIREWALL & IDS)
// ========================================================
function evaluatePacket(pkt) {
  // 1. Lapisan Pertama: Evaluasi Blacklist IP (Drop Immediately)
  const bl = state.blacklist.find((b) => b.ip === pkt.src);
  if (bl) {
    bl.hits++;
    if (isSupabaseOnline && supabaseClient && (pkt.attack || pkt.manualTest)) {
      supabaseClient.from("blacklist_ips").update({ hits: bl.hits }).eq("ip_address", bl.ip).then();
    }
    return { action: "Blokir", reason: "Blacklist IP (" + bl.reason + ")", by: "blacklist" };
  }

  // 2. Lapisan Kedua: Mitigasi Rate Limiting DDoS & Anti-Spoofing
  if (pkt.forceBlock) {
    return { action: "Blokir", reason: pkt.forceReason || "Rate Limit DDoS", by: "ratelimit" };
  }
  if (pkt.spoofed || (pkt.interface === "WAN" && isInternal(pkt.src))) {
    return { action: "Blokir", reason: "Anti-Spoofing: IP Internal Terdeteksi di Ingress Luar (RFC 2827)", by: "antispoof" };
  }

  // 3. Lapisan Ketiga: Deteksi Intrusi (Deep Packet Inspection / IDS)
  // Payload berbahaya dicegat sebelum diberi izin akses port
  if (pkt.malicious) {
    return { action: "Blokir", reason: "Deteksi IDS: Signature Payload Berbahaya", by: "ids" };
  }

  // 4. Lapisan Keempat: Evaluasi Aturan Firewall Aktif (Top-Down)
  if (state.firewallOn) {
    for (const r of state.rules) {
      if (!r.active) continue;
      const ipMatch = matchIp(r.ip, pkt.src);
      const portMatch = r.port === "Semua" || String(r.port) === String(pkt.port);
      const protoMatch = r.proto === "TCP/UDP" || r.proto === pkt.proto;

      if (ipMatch && portMatch && protoMatch) {
        return {
          action: r.action,
          reason: "Aturan Firewall: " + r.name,
          by: "rule",
        };
      }
    }
  }

  // 5. Lapisan Kelima: Kebijakan Port Sensitif Eksternal
  if (SENSITIVE_PORTS.includes(pkt.port) && !isInternal(pkt.src)) {
    return { action: "Blokir", reason: "Kebijakan Default: Port Sensitif Eksternal", by: "policy" };
  }

  // 6. Default: Izinkan Koneksi Sah
  return { action: "Izinkan", reason: "Kebijakan Default: Traffic Terverifikasi", by: "default" };
}

// ========================================================
// PENCATATAN & FEED PAKET REAL-TIME
// ========================================================
function addLogEntry(entry) {
  state.logs.unshift(entry);
  if (state.logs.length > 500) state.logs.length = 500;
  $("badgeLogs").textContent = state.logs.length;
  if (currentView === "logs") renderLogs();
}

function addAlertEntry(pkt, verdict) {
  state.alerts.unshift({
    time: pkt.time,
    src: pkt.src,
    port: pkt.port,
    desc: pkt.desc,
    reason: verdict.reason,
  });
  if (state.alerts.length > 40) state.alerts.length = 40;
  renderAlerts();
}

function processPacket(pkt) {
  pkt.time = nowTime();
  const verdict = evaluatePacket(pkt);

  state.total++;
  state.sessTotal++;

  if (verdict.action === "Blokir") {
    state.blocked++;
    state.sessBlocked++;
    state.tickBlocked++;

    if (state.portBlocks[pkt.port] !== undefined) {
      state.portBlocks[pkt.port]++;
      renderPorts();
    } else {
      state.portBlocks[pkt.port] = 1;
      renderPorts();
    }
    addAlertEntry(pkt, verdict);
    playBlockedSound();
  } else {
    state.allowed++;
    state.sessAllowed++;
    state.tickAllowed++;
    if (Math.random() < 0.25) playAllowedSound();
  }

  const jenis = pkt.attack
    ? "Serangan"
    : pkt.suspicious
    ? "Traffic Mencurigakan"
    : "Traffic Normal";

  addLogEntry({
    time: pkt.time,
    src: pkt.src,
    port: pkt.port,
    proto: pkt.proto,
    jenis: jenis,
    desc: pkt.desc,
    action: verdict.action,
    reason: verdict.reason,
  });

  pushFeedItem(pkt, verdict);

  // Sync Log ke Supabase HANYA jika ancaman serangan terdeteksi atau pengujian manual
  // (Lalu lintas simulasi normal rutin TIDAK di-spam ke database agar kuota Supabase hemat & aman)
  if (isSupabaseOnline && supabaseClient && (pkt.attack || pkt.malicious || pkt.manualTest || (verdict.action === "Blokir" && verdict.by === "blacklist"))) {
    supabaseClient
      .from("security_logs")
      .insert([
        {
          source_ip: pkt.src,
          dest_port: String(pkt.port),
          activity_type: jenis,
          action: verdict.action,
          description: pkt.desc,
          reason: verdict.reason,
        },
      ])
      .then();
  }

  // Update Last Inspected Banner
  $("lastConn").textContent = `${pkt.src} → :${pkt.port} (${PORT_NAMES[pkt.port] || "Port"}) · ${pkt.proto} · ${pkt.desc}`;
  $("lastConnChip").innerHTML =
    verdict.action === "Blokir"
      ? `<span class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-neon-red/15 text-neon-red border border-neon-red/30">DIBLOKIR — ${esc(verdict.reason)}</span>`
      : `<span class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-neon-green/15 text-neon-green border border-neon-green/30">DIIZINKAN — ${esc(verdict.reason)}</span>`;

  renderStats();
  renderSession();
  return verdict;
}

function pushFeedItem(pkt, verdict) {
  const empty = $("feedEmpty");
  if (empty) empty.remove();

  const el = document.createElement("div");
  el.className = "flex items-baseline justify-between gap-2 p-2 rounded-lg hover:bg-cyber-850/60 transition text-[11px] animate-feed-in border-b border-cyber-border-subtle/30";

  const isBlocked = verdict.action === "Blokir";
  const badgeHtml = isBlocked
    ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-neon-red/20 text-neon-red border border-neon-red/30 flex-shrink-0">DIBLOKIR</span>`
    : `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-neon-green/20 text-neon-green border border-neon-green/30 flex-shrink-0">DIIZINKAN</span>`;

  el.innerHTML = `
    <div class="flex items-center gap-2 truncate">
      <span class="text-slate-500 font-mono text-[10px] flex-shrink-0">${esc(pkt.time || nowTime())}</span>
      <span class="text-neon-cyan font-mono flex-shrink-0">${esc(pkt.src)}:${esc(pkt.port)}</span>
      <span class="text-slate-400 truncate">${esc(pkt.desc)} <span class="text-slate-500 text-[10px]">(${esc(pkt.proto)})</span></span>
    </div>
    ${badgeHtml}
  `;

  const feed = $("feedList");
  feed.prepend(el);
  while (feed.children.length > 45) {
    feed.removeChild(feed.lastChild);
  }
}

// ========================================================
// GENERATOR LALU LINTAS DATA NORMAL & PROBE
// ========================================================
const LEGIT_TRAFFIC = [
  { port: 443, proto: "TCP", desc: "Akses HTTPS ke Server Web", weight: 6 },
  { port: 80, proto: "TCP", desc: "Akses HTTP ke Portal Web", weight: 4 },
  { port: 53, proto: "UDP", desc: "Resolusi Nama Domain (DNS Query)", weight: 3 },
  { port: 8080, proto: "TCP", desc: "Akses Aplikasi Web Internal API", weight: 2 },
  { port: 25, proto: "TCP", desc: "Pertukaran Email Relay (SMTP)", weight: 1 },
  { port: 993, proto: "TCP", desc: "Sinkronisasi Kotak Surat (IMAPS)", weight: 1 },
];

const LEGIT_POOL = LEGIT_TRAFFIC.flatMap((t) => Array(t.weight).fill(t));

const PROBE_ATTEMPTS = [
  { port: 22, desc: "Percobaan Probe Port SSH Eksternal" },
  { port: 445, desc: "Probe Port SMB Windows File Sharing" },
  { port: 1433, desc: "Probe Koneksi Database MSSQL" },
  { port: 3306, desc: "Probe Koneksi Database MySQL" },
  { port: 23, desc: "Percobaan Akses Konsol Telnet" },
  { port: 3389, desc: "Percobaan Probe Remote Desktop (RDP)" },
];

function generateNormalPacket() {
  if (Math.random() < 0.16) {
    const pr = pick(PROBE_ATTEMPTS);
    const src = Math.random() < 0.35 && state.blacklist.length
      ? pick(state.blacklist).ip
      : randPublicIp();
    return { src: src, port: pr.port, proto: "TCP", desc: pr.desc, suspicious: true };
  }

  const l = pick(LEGIT_POOL);
  const src = l.port === 8080 ? randInternalIp() : Math.random() < 0.6 ? randInternalIp() : randPublicIp();
  return { src: src, port: l.port, proto: l.proto, desc: l.desc, suspicious: false };
}

// ========================================================
// SKENARIO SIMULASI SERANGAN SIBER
// ========================================================
function setThreatLevel() {
  const atk = Object.keys(state.activeAttacks);
  let lvl = "RENDAH",
    colorClass = "bg-neon-green shadow-[0_0_8px_rgba(52,211,153,0.8)]";

  if (atk.includes("ddos")) {
    lvl = "TINGGI";
    colorClass = "bg-neon-red shadow-[0_0_8px_rgba(248,113,113,0.8)]";
  } else if (atk.length > 0) {
    lvl = "SEDANG";
    colorClass = "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]";
  }

  $("threatLevel").textContent = lvl;
  const dot = $("threatDot");
  dot.className = "w-2.5 h-2.5 rounded-full transition-colors duration-300 " + colorClass;
}

function boostSystemMetrics(cpu, mem, bw, durationMs) {
  state.cpuTarget = cpu;
  state.memTarget = mem;
  state.bwTarget = bw;
  setTimeout(() => {
    if (!Object.keys(state.activeAttacks).length) {
      state.cpuTarget = 18;
      state.memTarget = 42;
      state.bwTarget = 1.4;
    }
  }, durationMs);
}

function autoBlacklistIp(ip, reason) {
  if (state.blacklist.some((b) => b.ip === ip)) return;
  state.blacklist.unshift({
    ip: ip,
    reason: reason,
    added: "Hari ini (Otomatis IDS)",
    hits: 1,
  });
  renderBlacklist();

  if (isSupabaseOnline && supabaseClient) {
    supabaseClient.from("blacklist_ips").upsert([{ ip_address: ip, reason: reason, hits: 1 }]).then();
  }

  addLogEntry({
    time: nowTime(),
    src: ip,
    port: "—",
    proto: "—",
    jenis: "Sistem",
    desc: reason,
    action: "Diblokir",
    reason: "Ditambahkan ke Blacklist Otomatis oleh IDS",
  });
  toast("IP Diblacklist Otomatis", `${ip} — ${reason}`, "red");
}

function runAttackScenario(key, cfg) {
  if (state.activeAttacks[key]) return;
  if (!state.running) toggleSimulation(true);

  state.activeAttacks[key] = true;
  setThreatLevel();

  const btn = document.querySelector(`[data-attack="${key}"]`);
  let origLabel = "";
  if (btn) {
    btn.disabled = true;
    const bEl = btn.querySelector("b");
    origLabel = bEl.textContent;
    bEl.textContent = `${cfg.label} — Berjalan...`;
    btn.classList.add("ring-1", "ring-rose-500", "opacity-80");
  }

  toast("Simulasi Serangan Dimulai", cfg.label, "red");

  let count = 0;
  const timer = setInterval(() => {
    if (!state.running) return;
    if (count >= cfg.count) {
      clearInterval(timer);
      delete state.activeAttacks[key];
      setThreatLevel();
      if (btn) {
        btn.disabled = false;
        btn.querySelector("b").textContent = origLabel;
        btn.classList.remove("ring-1", "ring-rose-500", "opacity-80");
      }
      toast("Simulasi Selesai", `Serangan ${cfg.label} berhasil ditangani sistem.`, "green");
      if (cfg.onDone) cfg.onDone();
      return;
    }
    count++;
    cfg.emit(count);
  }, cfg.interval);

  if (cfg.boost) {
    boostSystemMetrics(cfg.boost[0], cfg.boost[1], cfg.boost[2], cfg.count * cfg.interval + 1000);
  }
}

const ATTACK_CONFIGS = {
  ddos: {
    label: "DDoS Flood",
    count: 36,
    interval: 110,
    boost: [94, 79, 36.8],
    emit: (n) => {
      const src = Math.random() < 0.25 && state.blacklist.length ? pick(state.blacklist).ip : randPublicIp();
      const pkt = {
        src: src,
        port: pick([80, 443]),
        proto: "TCP",
        desc: "Banjir SYN Packet — Serangan DDoS Masif",
        attack: "DDoS",
      };
      if (n > 8) {
        pkt.forceBlock = true;
        pkt.forceReason = "Mitigasi DDoS: Rate Limiting Terlampaui";
      }
      processPacket(pkt);
    },
  },
  portscan: {
    label: "Port Scan",
    count: 15,
    interval: 200,
    boost: [48, 56, 3.6],
    emit: (n) => {
      const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 1433, 3306, 3389, 8080];
      const targetPort = ports[n - 1] || 80;
      processPacket({
        src: "185.220.101.7",
        port: targetPort,
        proto: "TCP",
        desc: `Pemindaian Port Terorganisir (Port Scanning :${targetPort})`,
        attack: "Port Scan",
      });
      if (n === 8) {
        autoBlacklistIp("185.220.101.7", "Pemindaian Port Beruntun Terdeteksi");
      }
    },
  },
  bruteforce: {
    label: "Brute Force SSH",
    count: 10,
    interval: 320,
    boost: [40, 52, 2.2],
    emit: (n) => {
      const ip = "103.75.196.44";
      processPacket({
        src: ip,
        port: 22,
        proto: "TCP",
        desc: "Percobaan Login Kredensial SSH Berulang Kali (Brute Force)",
        attack: "Brute Force SSH",
      });
      if (!state.blacklist.some((b) => b.ip === ip)) {
        state.sshAttempts[ip] = (state.sshAttempts[ip] || 0) + 1;
        if (state.sshAttempts[ip] >= 5) {
          autoBlacklistIp(ip, "Eksploitasi Brute Force SSH Terdeteksi");
          state.sshAttempts[ip] = 0;
        }
      }
    },
  },
  sqli: {
    label: "SQL Injection",
    count: 6,
    interval: 350,
    boost: [36, 54, 1.8],
    emit: () => {
      processPacket({
        src: "193.142.59.88",
        port: pick([443, 80]),
        proto: "TCP",
        desc: "Payload Injeksi SQL Terdeteksi: ' OR 1=1; DROP TABLE users;--",
        attack: "SQL Injection",
        malicious: true,
      });
    },
  },
  malware: {
    label: "Malware C2",
    count: 8,
    interval: 400,
    boost: [42, 60, 2.8],
    emit: () => {
      processPacket({
        src: "91.240.118.12",
        port: 4444,
        proto: "TCP",
        desc: "Beaconing Terenkripsi ke Server Command & Control (C2)",
        attack: "Malware C2",
        malicious: true,
      });
    },
  },
};

document.querySelectorAll("[data-attack]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const k = btn.dataset.attack;
    if (ATTACK_CONFIGS[k]) runAttackScenario(k, ATTACK_CONFIGS[k]);
  });
});

// ========================================================
// RENDER KOMPONEN UI
// ========================================================
function activeRuleCount() {
  return state.rules.filter((r) => r.active).length;
}

function renderStats() {
  $("statTotal").textContent = fmt(state.total);
  $("statAllowed").textContent = fmt(state.allowed);
  $("statBlocked").textContent = fmt(state.blocked);
  $("statRules").textContent = activeRuleCount();

  const pct = state.total > 0 ? ((state.allowed / state.total) * 100).toFixed(1).replace(".", ",") : "0";
  $("statAllowedSub").textContent = `${pct}% dari total paket`;
  $("statRulesSub").textContent = state.firewallOn
    ? `dari ${state.rules.length} aturan terdaftar`
    : `Firewall nonaktif — aturan dilewati`;

  $("sidePackets").textContent = fmt(state.total);
  $("badgeRules").textContent = activeRuleCount();
}

function renderSession() {
  $("sessTotal").textContent = fmt(state.sessTotal);
  $("sessAllowed").textContent = fmt(state.sessAllowed);
  $("sessBlocked").textContent = fmt(state.sessBlocked);
}

function renderPorts() {
  const container = $("portsList");
  if (!container) return;

  const entries = Object.entries(state.portBlocks).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 1;

  container.innerHTML = entries
    .slice(0, 5)
    .map(([port, count]) => {
      const widthPct = Math.max(5, Math.round((count / max) * 100));
      return `
        <div class="py-2 cursor-pointer hover:bg-cyber-850/40 rounded px-1 transition" data-port="${port}" title="Klik untuk filter log port ${port}">
          <div class="flex items-center justify-between mb-1">
            <span class="font-mono font-semibold text-white">Port ${port} <span class="font-sans text-[11px] font-normal text-slate-400">(${PORT_NAMES[port] || "Custom"})</span></span>
            <span class="font-mono text-neon-red font-medium">${fmt(count)} blok</span>
          </div>
          <div class="h-1.5 w-full bg-cyber-950 border border-cyber-border-subtle rounded-full overflow-hidden">
            <div class="h-full bg-neon-red/80 rounded-full transition-all duration-500" style="width: ${widthPct}%"></div>
          </div>
        </div>
      `;
    })
    .join("");
}

// Klik port di dashboard untuk filter log otomatis
$("portsList").addEventListener("click", (e) => {
  const row = e.target.closest("[data-port]");
  if (!row) return;
  const p = row.dataset.port;
  switchView("logs");
  $("logSearch").value = p;
  renderLogs();
  toast("Filter Port", `Menampilkan catatan audit untuk Port ${p}.`, "cyan");
});

function renderAlerts() {
  const body = $("alertsBody");
  if (!body) return;

  if (!state.alerts.length) {
    body.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500">Belum ada peringatan keamanan — ancaman yang diblokir akan dicatat di sini.</td></tr>`;
    return;
  }

  body.innerHTML = state.alerts
    .slice(0, 6)
    .map(
      (a) => `
      <tr class="hover:bg-cyber-850/50 transition border-b border-cyber-border-subtle/40">
        <td data-label="Waktu" class="py-2.5 px-3 font-mono text-slate-400">${a.time}</td>
        <td data-label="IP Asal" class="py-2.5 px-3 font-mono text-neon-cyan font-medium">${esc(a.src)}</td>
        <td data-label="Port Target" class="py-2.5 px-3 font-mono text-slate-300">${a.port} <span class="text-slate-500 font-sans">(${PORT_NAMES[a.port] || "—"})</span></td>
        <td data-label="Deskripsi Serangan" class="py-2.5 px-3 text-slate-200">${esc(a.desc)}</td>
        <td data-label="Tindakan" class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-neon-red/15 text-neon-red border border-neon-red/30">DIBLOKIR</span>
          <span class="text-slate-400 text-[11px] ml-1.5">${esc(a.reason)}</span>
        </td>
      </tr>
    `
    )
    .join("");
}

function renderRules() {
  const body = $("rulesBody");
  if (!body) return;

  $("rulesInfo").textContent = `${activeRuleCount()} aktif dari ${state.rules.length} aturan`;

  if (!state.rules.length) {
    body.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-slate-500">Belum ada aturan firewall terdaftar. Silakan tambahkan aturan baru di atas.</td></tr>`;
    renderStats();
    return;
  }

  body.innerHTML = state.rules
    .map((r, idx) => {
      const isAllowed = r.action === "Izinkan" || r.action === "ALLOW";
      const actionBadge = isAllowed
        ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-neon-green/15 text-neon-green border border-neon-green/30">IZINKAN</span>`
        : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-neon-red/15 text-neon-red border border-neon-red/30">BLOKIR</span>`;

      return `
        <tr class="hover:bg-cyber-850/50 transition border-b border-cyber-border-subtle/40 ${r.active ? "" : "opacity-45"}">
          <td data-label="Nama Aturan" class="py-3 px-3 font-medium text-white flex items-center gap-2">
            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyber-800 text-slate-400 border border-cyber-border">#${idx + 1}</span>
            ${esc(r.name)}
          </td>
          <td data-label="Alamat IP" class="py-3 px-3 font-mono text-neon-cyan">${esc(r.ip === "*" ? "* (Semua)" : r.ip)}</td>
          <td data-label="Port" class="py-3 px-3 font-mono text-slate-300">${r.port === "Semua" ? "Semua" : esc(r.port) + " (" + esc(PORT_NAMES[r.port] || "Custom") + ")"}</td>
          <td data-label="Protokol" class="py-3 px-3 font-mono text-slate-400"><span class="px-2 py-0.5 rounded bg-cyber-800 border border-cyber-border">${esc(r.proto)}</span></td>
          <td data-label="Aksi" class="py-3 px-3">${actionBadge}</td>
          <td data-label="Status" class="py-3 px-3 text-center">
            <label class="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" data-toggle-rule="${esc(r.id)}" ${r.active ? "checked" : ""} class="sr-only peer">
              <div class="w-9 h-5 bg-cyber-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-300 after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-neon-green/30 peer-checked:after:bg-neon-green"></div>
            </label>
          </td>
          <td class="py-3 px-3 text-right cell-actions">
            <div class="inline-flex items-center gap-1">
              <button type="button" data-move-up="${esc(r.id)}" class="p-1 rounded text-slate-400 hover:text-neon-cyan hover:bg-cyber-750 transition" title="Naikkan Prioritas (Evaluasi Lebih Dulu)">
                ▲
              </button>
              <button type="button" data-move-down="${esc(r.id)}" class="p-1 rounded text-slate-400 hover:text-neon-cyan hover:bg-cyber-750 transition" title="Turunkan Prioritas">
                ▼
              </button>
              <button type="button" data-delete-rule="${esc(r.id)}" class="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition" title="Hapus Aturan">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");

  renderStats();
}

function renderBlacklist() {
  const body = $("blBody");
  if (!body) return;

  $("blInfo").textContent = `${state.blacklist.length} IP diblokir`;
  $("badgeBlacklist").textContent = state.blacklist.length;

  if (!state.blacklist.length) {
    body.innerHTML = `<tr><td colspan="5" class="text-center py-8 text-slate-500">Blacklist kosong — tidak ada IP yang dicekal secara permanen.</td></tr>`;
    return;
  }

  body.innerHTML = state.blacklist
    .map(
      (b) => `
      <tr class="hover:bg-cyber-850/50 transition border-b border-cyber-border-subtle/40">
        <td data-label="Alamat IP" class="py-3 px-3 font-mono font-bold text-neon-red">${esc(b.ip)}</td>
        <td data-label="Alasan Pemblokiran" class="py-3 px-3 text-slate-300">${esc(b.reason)}</td>
        <td data-label="Waktu Ditambahkan" class="py-3 px-3 text-slate-400 text-xs">${esc(b.added)}</td>
        <td data-label="Paket Diblokir" class="py-3 px-3 font-mono text-neon-red">${fmt(b.hits)}</td>
        <td class="py-3 px-3 text-right cell-actions">
          <button type="button" data-delete-bl="${esc(b.ip)}" class="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition" title="Hapus dari Blacklist">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </button>
        </td>
      </tr>
    `
    )
    .join("");
}

function renderLogs() {
  const body = $("logBody");
  if (!body) return;

  const q = $("logSearch").value.trim().toLowerCase();
  const fa = $("logFilterAction").value;
  const ft = $("logFilterType").value;

  const filtered = state.logs.filter((l) => {
    if (fa && l.action !== fa) return false;
    if (ft && l.jenis !== ft) return false;
    if (q) {
      const haystack = `${l.src} ${l.port} ${l.jenis} ${l.desc} ${l.action} ${l.reason}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });

  $("logCount").textContent = `Menampilkan ${Math.min(filtered.length, 150)} dari ${filtered.length} entri (Total tersimpan: ${state.logs.length})`;

  if (!filtered.length) {
    body.innerHTML = `<tr><td colspan="5" class="text-center py-8 text-slate-500">Tidak ada log aktivitas yang cocok dengan kriteria pencarian/filter.</td></tr>`;
    return;
  }

  body.innerHTML = filtered
    .slice(0, 150)
    .map((l) => {
      const isBlocked = l.action === "Blokir" || l.action === "DIBLOKIR";
      const actionBadge = isBlocked
        ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-neon-red/15 text-neon-red border border-neon-red/30">DIBLOKIR</span>`
        : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-neon-green/15 text-neon-green border border-neon-green/30">DIIZINKAN</span>`;

      let jenisBadgeColor = "text-slate-400";
      if (l.jenis === "Serangan") jenisBadgeColor = "text-neon-red font-semibold";
      else if (l.jenis === "Traffic Mencurigakan") jenisBadgeColor = "text-amber-400";
      else if (l.jenis === "Sistem") jenisBadgeColor = "text-neon-cyan";

      return `
        <tr class="hover:bg-cyber-850/50 transition border-b border-cyber-border-subtle/40">
          <td data-label="Waktu" class="py-2.5 px-3 font-mono text-slate-400 text-xs">${esc(l.time)}</td>
          <td data-label="IP Sumber" class="py-2.5 px-3 font-mono text-neon-cyan font-medium">${esc(l.src)}</td>
          <td data-label="Port Tujuan" class="py-2.5 px-3 font-mono text-slate-300">${l.port === "—" ? "—" : esc(l.port) + " (" + esc(PORT_NAMES[l.port] || "—") + ")"}</td>
          <td data-label="Jenis Aktivitas" class="py-2.5 px-3">
            <span class="${jenisBadgeColor}">${esc(l.jenis)}</span>
            <span class="text-slate-400 ml-1.5">— ${esc(l.desc)}</span>
          </td>
          <td data-label="Tindakan Sistem" class="py-2.5 px-3">
            ${actionBadge}
            <span class="text-slate-400 text-[11px] ml-1.5">${esc(l.reason)}</span>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderHealthGauges() {
  const setGauge = (barId, valId, val, text, maxScale = 100) => {
    const bar = $(barId);
    if (!bar) return;
    const pct = Math.min(100, Math.max(0, (val / maxScale) * 100));
    bar.style.width = pct + "%";

    if (val >= 85) {
      bar.className = "h-full bg-neon-red transition-all duration-700 shadow-glow-red";
    } else if (val >= 60) {
      bar.className = "h-full bg-amber-400 transition-all duration-700";
    } else {
      bar.className = "h-full bg-neon-cyan transition-all duration-700 shadow-glow-cyan";
    }

    const valEl = $(valId);
    if (valEl) valEl.textContent = text;
  };

  setGauge("cpuBar", "cpuVal", state.cpu, Math.round(state.cpu) + "%");
  setGauge("memBar", "memVal", state.mem, Math.round(state.mem) + "%");
  setGauge("bwBar", "bwVal", state.bw, state.bw.toFixed(1).replace(".", ",") + " Mb/s", 40);
}

// ========================================================
// GRAFIK TRAFFIC MENGGUNAKAN HTML5 CANVAS (RETINA READY)
// ========================================================
const chart = $("trafficChart");
const ctx = chart ? chart.getContext("2d") : null;

function drawTrafficChart() {
  if (!chart || !ctx) return;

  const w = chart.clientWidth;
  const h = chart.clientHeight;
  if (!w || !h) return;

  const dpr = window.devicePixelRatio || 1;
  if (chart.width !== Math.round(w * dpr) || chart.height !== Math.round(h * dpr)) {
    chart.width = Math.round(w * dpr);
    chart.height = Math.round(h * dpr);
  }

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const A = state.seriesA;
  const B = state.seriesB;

  const maxVal = Math.max(8, ...A, ...B) * 1.25;
  const padL = 32,
    padR = 12,
    padT = 12,
    padB = 22;
  const iw = w - padL - padR;
  const ih = h - padT - padB;

  ctx.strokeStyle = "rgba(31, 51, 94, 0.4)";
  ctx.fillStyle = "#64748b";
  ctx.font = "10px 'IBM Plex Mono', monospace";
  ctx.lineWidth = 1;

  for (let i = 0; i <= 4; i++) {
    const y = padT + ih - (ih * i) / 4;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();

    const labelVal = Math.round((maxVal * i) / 4);
    ctx.fillText(String(labelVal), 4, y + 3);
  }

  const stepX = iw / (A.length - 1);

  const drawLine = (data, color, fillGrad) => {
    ctx.beginPath();
    data.forEach((v, idx) => {
      const x = padL + idx * stepX;
      const y = padT + ih - (v / maxVal) * ih;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });

    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();

    if (fillGrad) {
      ctx.lineTo(padL + (data.length - 1) * stepX, padT + ih);
      ctx.lineTo(padL, padT + ih);
      ctx.closePath();
      ctx.fillStyle = fillGrad;
      ctx.fill();
    }

    const lastIdx = data.length - 1;
    const lx = padL + lastIdx * stepX;
    const ly = padT + ih - (data[lastIdx] / maxVal) * ih;
    ctx.beginPath();
    ctx.arc(lx, ly, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = "#070c18";
    ctx.lineWidth = 1.5;
    ctx.stroke();
  };

  const gradA = ctx.createLinearGradient(0, padT, 0, padT + ih);
  gradA.addColorStop(0, "rgba(52, 211, 153, 0.25)");
  gradA.addColorStop(1, "rgba(52, 211, 153, 0.0)");

  drawLine(A, "#34d399", gradA);
  drawLine(B, "#f87171", null);

  ctx.fillStyle = "#64748b";
  ctx.fillText("-40 dtk", padL, h - 6);
  const nowTxt = "sekarang (live)";
  ctx.fillText(nowTxt, w - padR - ctx.measureText(nowTxt).width, h - 6);
}

window.addEventListener("resize", drawTrafficChart);

// ========================================================
// NAVIGASI ANTAR HALAMAN (VIEWS)
// ========================================================
let currentView = "dashboard";

function switchView(viewName) {
  currentView = viewName;

  document.querySelectorAll(".nav-item").forEach((btn) => {
    const isTarget = btn.dataset.view === viewName;
    btn.classList.toggle("active", isTarget);
    if (isTarget) {
      btn.classList.add("bg-neon-cyan/15", "text-neon-cyan", "border", "border-neon-cyan/30");
      btn.classList.remove("text-slate-400");
    } else {
      btn.classList.remove("bg-neon-cyan/15", "text-neon-cyan", "border", "border-neon-cyan/30");
      btn.classList.add("text-slate-400");
    }
  });

  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.classList.toggle("hidden", panel.id !== "view-" + viewName);
  });

  if (viewName === "logs") renderLogs();
  if (viewName === "dashboard") requestAnimationFrame(drawTrafficChart);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

$("btnGotoLogs").addEventListener("click", () => switchView("logs"));

// ========================================================
// KONTROL SIMULASI & FIREWALL
// ========================================================
function renderSimulationState() {
  const label = state.running ? "Jeda Simulasi" : "Mulai Simulasi";
  $("btnToggleSim").textContent = label;
  $("btnToggleSimDash").textContent = label;
  $("simStateText").textContent = state.running ? "Simulasi Berjalan (Aktif)" : "Simulasi Standby (Manual)";

  const dot = $("simStateDot");
  dot.className = "w-3 h-3 rounded-full transition-all " +
    (state.running
      ? "bg-neon-green animate-pulse-dot shadow-[0_0_8px_rgba(52,211,153,0.8)]"
      : "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]");

  $("simDot").className = "w-2 h-2 rounded-full flex-shrink-0 transition-all " +
    (state.running
      ? "bg-neon-green animate-pulse-dot shadow-[0_0_6px_rgba(52,211,153,0.9)]"
      : "bg-amber-400");

  $("feedStatus").textContent = state.running ? "LIVE" : "STANDBY";
  $("feedStatus").className = "px-2 py-0.5 rounded-full text-[11px] font-mono font-semibold " +
    (state.running ? "bg-neon-green/15 text-neon-green border border-neon-green/30" : "bg-amber-400/15 text-amber-400 border border-amber-400/30");
}

function toggleSimulation(force) {
  state.running = typeof force === "boolean" ? force : !state.running;
  renderSimulationState();
  toast(
    state.running ? "Simulasi Diaktifkan" : "Simulasi Dijeda",
    state.running ? "Lalu lintas paket jaringan kembali mengalir." : "Pemrosesan paket data dihentikan sementara.",
    state.running ? "green" : "amber"
  );
}

$("btnToggleSim").addEventListener("click", () => toggleSimulation());
$("btnToggleSimDash").addEventListener("click", () => toggleSimulation());

$("btnFirewallToggle").addEventListener("click", () => {
  state.firewallOn = !state.firewallOn;

  const btn = $("btnFirewallToggle");
  if (state.firewallOn) {
    btn.textContent = "Nonaktifkan Firewall";
    btn.className = "px-3 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 font-medium transition active:scale-95";
    $("fwState").textContent = "AKTIF";
    $("fwState").className = "text-neon-green font-semibold";
    $("fwDot").className = "w-2.5 h-2.5 rounded-full bg-neon-green shadow-[0_0_8px_rgba(52,211,153,0.8)]";
    $("fwOffNotice").classList.add("hidden");
    $("fwOffNotice").classList.remove("flex");
  } else {
    btn.textContent = "Aktifkan Firewall";
    btn.className = "px-3 py-1.5 rounded-lg bg-neon-green/15 hover:bg-neon-green/25 border border-neon-green/30 text-neon-green font-medium transition active:scale-95";
    $("fwState").textContent = "NONAKTIF";
    $("fwState").className = "text-neon-red font-semibold";
    $("fwDot").className = "w-2.5 h-2.5 rounded-full bg-neon-red shadow-[0_0_8px_rgba(248,113,113,0.8)]";
    $("fwOffNotice").classList.remove("hidden");
    $("fwOffNotice").classList.add("flex");
  }

  renderStats();
  toast(
    state.firewallOn ? "Firewall Diaktifkan" : "Firewall Dinonaktifkan",
    state.firewallOn
      ? "Aturan firewall kembali diterapkan pada seluruh paket masuk."
      : "Aturan firewall dinonaktifkan! Blacklist dan IDS tetap memblokir ancaman fatal.",
    state.firewallOn ? "green" : "red"
  );
});

// Audio Toggle Listener
const btnAudio = $("btnAudioToggle");
if (btnAudio) {
  btnAudio.addEventListener("click", () => {
    audioEnabled = !audioEnabled;
    if (audioEnabled) {
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      if (audioCtx.state === "suspended") audioCtx.resume();
      $("audioText").textContent = "Audio ON";
      btnAudio.className = "px-2.5 py-1.5 rounded-lg bg-neon-cyan/20 text-neon-cyan border border-neon-cyan/40 transition flex items-center gap-1.5";
      $("audioIcon").innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />`;
      playTone(523, "sine", 0.12, 0.05);
      toast("Audio Aktif", "Efek suara cyber ops diaktifkan.", "cyan");
    } else {
      $("audioText").textContent = "Mute";
      btnAudio.className = "px-2.5 py-1.5 rounded-lg bg-cyber-850 hover:bg-cyber-800 text-slate-400 hover:text-white border border-cyber-border-subtle transition flex items-center gap-1.5";
      $("audioIcon").innerHTML = `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2" />`;
      toast("Audio Dibisukan", "Efek suara dimatikan.", "amber");
    }
  });
}

// ========================================================
// MANAJEMEN ATURAN FIREWALL
// ========================================================
function showFormError(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
}

function hideFormError(id) {
  const el = $(id);
  if (!el) return;
  el.classList.add("hidden");
}

$("ruleForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  hideFormError("ruleError");

  const name = $("rName").value.trim();
  const ipRaw = $("rIp").value.trim();
  const portRaw = $("rPort").value.trim();
  const proto = $("rProto").value;
  const action = $("rAction").value;

  if (!name) return showFormError("ruleError", "Nama aturan wajib diisi.");
  if (!ipRaw) return showFormError("ruleError", "Alamat IP wajib diisi (gunakan * untuk semua IP).");
  if (!validIpOrCidr(ipRaw)) {
    return showFormError("ruleError", "Format IP tidak valid. Contoh: 203.0.113.10, 192.168.1.0/24, atau *");
  }

  let port;
  if (/^(semua|\*)$/i.test(portRaw)) {
    port = "Semua";
  } else if (/^\d+$/.test(portRaw) && +portRaw >= 1 && +portRaw <= 65535) {
    port = +portRaw;
  } else {
    return showFormError("ruleError", "Port tidak valid. Isi angka 1-65535 atau ketik 'Semua'.");
  }

  const newRule = {
    id: state.nextRuleId++,
    name: name,
    ip: ipRaw,
    port: port,
    proto: proto,
    action: action,
    active: true,
  };

  state.rules.push(newRule);
  renderRules();
  $("ruleForm").reset();

  // Dual-write ke Supabase jika online
  if (isSupabaseOnline && supabaseClient) {
    const { data, error } = await supabaseClient.from("firewall_rules").insert([
      {
        rule_name: name,
        ip_address: ipRaw,
        port: String(port),
        protocol: proto,
        action: action,
        is_active: true,
      },
    ]).select();
    if (data && data.length) newRule.id = data[0].id;
  }

  toast("Aturan Ditambahkan", `${name} — ${action} ${proto} Port ${port}`, "green");
});

$("rulesBody").addEventListener("change", async (ev) => {
  const id = ev.target.dataset.toggleRule;
  if (!id) return;
  const rule = state.rules.find((r) => r.id === +id);
  if (rule) {
    rule.active = ev.target.checked;
    renderRules();

    if (isSupabaseOnline && supabaseClient) {
      await supabaseClient.from("firewall_rules").update({ is_active: rule.active }).eq("id", rule.id);
    }

    toast(rule.active ? "Aturan Diaktifkan" : "Aturan Dinonaktifkan", rule.name, rule.active ? "green" : "amber");
  }
});

$("rulesBody").addEventListener("click", async (ev) => {
  // Move Up
  const upBtn = ev.target.closest("[data-move-up]");
  if (upBtn) {
    const id = +upBtn.dataset.moveUp;
    const idx = state.rules.findIndex((r) => r.id === id);
    if (idx > 0) {
      const temp = state.rules[idx];
      state.rules[idx] = state.rules[idx - 1];
      state.rules[idx - 1] = temp;
      renderRules();
      toast("Prioritas Aturan Naik", `Aturan ${temp.name} dievaluasi lebih awal.`, "cyan");
    }
    return;
  }

  // Move Down
  const downBtn = ev.target.closest("[data-move-down]");
  if (downBtn) {
    const id = +downBtn.dataset.moveDown;
    const idx = state.rules.findIndex((r) => r.id === id);
    if (idx < state.rules.length - 1) {
      const temp = state.rules[idx];
      state.rules[idx] = state.rules[idx + 1];
      state.rules[idx + 1] = temp;
      renderRules();
      toast("Prioritas Aturan Turun", `Aturan ${temp.name} dievaluasi setelahnya.`, "cyan");
    }
    return;
  }

  // Delete
  const btn = ev.target.closest("[data-delete-rule]");
  if (!btn) return;
  const id = +btn.dataset.deleteRule;
  const rule = state.rules.find((r) => r.id === id);
  state.rules = state.rules.filter((r) => r.id !== id);
  renderRules();

  if (isSupabaseOnline && supabaseClient) {
    await supabaseClient.from("firewall_rules").delete().eq("id", id);
  }

  if (rule) toast("Aturan Dihapus", rule.name, "red");
});

// Reset Aturan ke Default
const btnResetRules = $("btnResetRules");
if (btnResetRules) {
  btnResetRules.addEventListener("click", async () => {
    state.rules = JSON.parse(JSON.stringify(DEFAULT_RULES));
    state.nextRuleId = 5;
    renderRules();

    if (isSupabaseOnline && supabaseClient) {
      toast("Reset Cloud", "Mengatur ulang aturan di Supabase...", "amber");
      await supabaseClient.from("firewall_rules").delete().neq("id", 0);
      await supabaseClient.from("firewall_rules").insert(
        DEFAULT_RULES.map((r) => ({
          rule_name: r.name,
          ip_address: r.ip,
          port: String(r.port),
          protocol: r.proto,
          action: r.action,
          is_active: r.active,
        }))
      );
    }

    toast("Reset Berhasil", "Aturan firewall dikembalikan ke data awal default.", "green");
  });
}

// ========================================================
// MANAJEMEN BLACKLIST IP
// ========================================================
$("blForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  hideFormError("blError");

  const ip = $("bIp").value.trim();
  const reason = $("bReason").value.trim();

  if (!validIpOrCidr(ip) || ip === "*") {
    return showFormError("blError", "Alamat IP tidak valid. Contoh format: 198.51.100.23");
  }
  if (!reason) {
    return showFormError("blError", "Alasan pemblokiran wajib dicantumkan.");
  }
  if (state.blacklist.some((b) => b.ip === ip)) {
    return showFormError("blError", `Alamat IP ${ip} sudah terdaftar di Blacklist.`);
  }

  state.blacklist.unshift({
    ip: ip,
    reason: reason,
    added: "Hari ini (Manual)",
    hits: 0,
  });

  renderBlacklist();
  $("blForm").reset();

  if (isSupabaseOnline && supabaseClient) {
    await supabaseClient.from("blacklist_ips").upsert([{ ip_address: ip, reason: reason, hits: 0 }]);
  }

  toast("IP Ditambahkan ke Blacklist", `${ip} akan langsung diblokir secara permanen.`, "red");
});

$("blBody").addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-delete-bl]");
  if (!btn) return;
  const ip = btn.dataset.deleteBl;
  state.blacklist = state.blacklist.filter((b) => b.ip !== ip);
  renderBlacklist();

  if (isSupabaseOnline && supabaseClient) {
    await supabaseClient.from("blacklist_ips").delete().eq("ip_address", ip);
  }

  toast("IP Dihapus dari Blacklist", `${ip} tidak lagi diblokir otomatis.`, "green");
});

// ========================================================
// INSPEKSI & PENGUJIAN PAKET MANUAL (PACKET TRACER)
// ========================================================
const tracerForm = $("tracerForm");
if (tracerForm) {
  tracerForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const ip = $("trIp").value.trim();
    const port = parseInt($("trPort").value, 10);
    const proto = $("trProto").value;
    const desc = $("trDesc").value.trim() || "Manual Test Packet";

    if (!validIpOrCidr(ip) || ip === "*") {
      toast("Validasi Gagal", "Masukkan IP Sumber yang valid (cth: 198.51.100.23)", "red");
      return;
    }
    if (isNaN(port) || port < 1 || port > 65535) {
      toast("Validasi Gagal", "Masukkan Port antara 1 dan 65535", "red");
      return;
    }

    const trace = [];
    trace.push({ step: 1, name: "Pemeriksaan Tabel Blacklist IP", detail: `Mengecek apakah ${ip} terdaftar dalam database blacklist...` });
    const bl = state.blacklist.find((b) => b.ip === ip);
    let finalVerdict = null;

    if (bl) {
      trace[0].status = "MATCH";
      trace[0].result = `DITOLAK: IP terdaftar di Blacklist (${bl.reason})`;
      finalVerdict = { action: "Blokir", reason: `Blacklist IP (${bl.reason})` };
    } else {
      trace[0].status = "PASS";
      trace[0].result = "LOLOS: IP bersih dari blacklist.";

      trace.push({ step: 2, name: "Mitigasi Rate Limiting Anti-DDoS", detail: "Mengecek ambang batas koneksi per detik...", status: "PASS", result: "LOLOS: Volume paket dalam batas wajar." });

      trace.push({ step: 3, name: "Evaluasi Aturan Firewall (Top-to-Bottom)", detail: `Mengevaluasi ${state.rules.length} aturan aktif...` });
      let matchedRule = null;
      if (state.firewallOn) {
        for (let i = 0; i < state.rules.length; i++) {
          const r = state.rules[i];
          if (!r.active) continue;
          const ipMatch = matchIp(r.ip, ip);
          const portMatch = r.port === "Semua" || String(r.port) === String(port);
          const protoMatch = r.proto === "TCP/UDP" || r.proto === proto;
          if (ipMatch && portMatch && protoMatch) {
            matchedRule = r;
            break;
          }
        }
      }

      if (matchedRule) {
        trace[2].status = "MATCH";
        trace[2].result = `COCOK dengan Aturan #${matchedRule.id} [${matchedRule.name}] → Aksi: ${matchedRule.action.toUpperCase()}`;
        finalVerdict = { action: matchedRule.action, reason: `Aturan Firewall: ${matchedRule.name}` };
      } else {
        trace[2].status = "PASS";
        trace[2].result = state.firewallOn ? "Tidak ada aturan firewall spesifik yang cocok. Melanjutkan ke kebijakan default..." : "Firewall sedang NONAKTIF, aturan dilewati.";

        trace.push({ step: 4, name: "Deteksi Signature IDS", detail: "Inspeksi payload data terhadap pola eksploitasi...", status: "PASS", result: "LOLOS: Tidak ditemukan tanda tangan serangan berbahaya." });

        trace.push({ step: 5, name: "Kebijakan Port Sensitif Eksternal", detail: `Mengecek apakah port ${port} termasuk port sensitif non-publik...` });
        if (SENSITIVE_PORTS.includes(port) && !isInternal(ip)) {
          trace[4].status = "MATCH";
          trace[4].result = `DITOLAK: Port ${port} adalah port sensitif tertutup untuk jaringan luar.`;
          finalVerdict = { action: "Blokir", reason: "Kebijakan Default: Port Sensitif Eksternal" };
        } else {
          trace[4].status = "PASS";
          trace[4].result = "LOLOS: Port sah untuk koneksi.";
          finalVerdict = { action: "Izinkan", reason: "Kebijakan Default: Traffic Terverifikasi" };
        }
      }
    }

    const out = $("tracerResult");
    out.classList.remove("hidden");
    const isBlocked = finalVerdict.action === "Blokir" || finalVerdict.action === "BLOCK";

    let html = `
      <div class="flex items-center justify-between pb-2 border-b border-cyber-border-subtle">
        <span class="text-white font-bold">Hasil Diagnostik Inspeksi: ${esc(ip)} → :${esc(port)} (${esc(proto)})</span>
        <span class="px-2.5 py-1 rounded-full text-xs font-bold ${isBlocked ? "bg-neon-red/20 text-neon-red border border-neon-red/40" : "bg-neon-green/20 text-neon-green border border-neon-green/40"}">
          HASIL AKHIR: ${esc(finalVerdict.action.toUpperCase())}
        </span>
      </div>
      <div class="space-y-1.5 pt-2 text-[11px]">
    `;

    trace.forEach((t) => {
      const isMatch = t.status === "MATCH";
      const badge = isMatch
        ? `<span class="text-neon-red font-bold">[MATCH/TRIGGER]</span>`
        : `<span class="text-neon-green font-bold">[PASS]</span>`;
      html += `
        <div class="p-2 rounded bg-cyber-900 border border-cyber-border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <div>
            <span class="text-slate-400 font-semibold">Tahap ${esc(t.step)}: ${esc(t.name)}</span>
            <p class="text-slate-300">${esc(t.result)}</p>
          </div>
          <div class="flex-shrink-0">${badge}</div>
        </div>
      `;
    });

    html += `
      </div>
      <div class="pt-2 text-slate-400 text-[11px]">
        <b>Keterangan Sistem:</b> ${esc(finalVerdict.reason)}
      </div>
    `;

    out.innerHTML = html;

    processPacket({
      src: ip,
      port: port,
      proto: proto,
      desc: desc + " (Uji Manual)",
      suspicious: isBlocked,
    });

    toast("Uji Diagnostik Selesai", `Paket ${ip}:${port} dievaluasi → ${finalVerdict.action.toUpperCase()}`, isBlocked ? "red" : "green");
  });
}

// ========================================================
// LOG KEAMANAN: FILTER, PENCARIAN, EXPORT CSV, HAPUS
// ========================================================
["logSearch", "logFilterAction", "logFilterType"].forEach((id) => {
  $(id).addEventListener("input", renderLogs);
  $(id).addEventListener("change", renderLogs);
});

let clearArmed = false;
let clearTimer = null;

$("btnClearLogs").addEventListener("click", async () => {
  const btn = $("btnClearLogs");
  if (!clearArmed) {
    clearArmed = true;
    btn.textContent = "Konfirmasi Hapus Sekarang?";
    btn.classList.add("bg-rose-500", "text-white");
    clearTimer = setTimeout(() => {
      clearArmed = false;
      btn.textContent = "Hapus Semua Log";
      btn.classList.remove("bg-rose-500", "text-white");
    }, 3000);
    return;
  }

  clearTimeout(clearTimer);
  clearArmed = false;
  btn.textContent = "Hapus Semua Log";
  btn.classList.remove("bg-rose-500", "text-white");

  state.logs = [];
  state.alerts = [];
  $("badgeLogs").textContent = "0";
  renderLogs();
  renderAlerts();

  if (isSupabaseOnline && supabaseClient) {
    await supabaseClient.from("security_logs").delete().neq("id", 0);
  }

  toast("Log Dikosongkan", "Seluruh riwayat audit dan log keamanan telah dihapus.", "red");
});

// Export CSV Feature
$("btnExportLogs").addEventListener("click", () => {
  if (!state.logs.length) {
    toast("Gagal Export", "Belum ada log yang dapat diekspor.", "amber");
    return;
  }

  let csv = "Waktu,IP_Sumber,Port_Tujuan,Jenis_Aktivitas,Deskripsi,Tindakan,Alasan\n";
  state.logs.forEach((l) => {
    const row = [
      `"${l.time}"`,
      `"${l.src}"`,
      `"${l.port}"`,
      `"${l.jenis}"`,
      `"${l.desc.replace(/"/g, '""')}"`,
      `"${l.action}"`,
      `"${l.reason.replace(/"/g, '""')}"`,
    ];
    csv += row.join(",") + "\n";
  });

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `CyberShield_SecurityLogs_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  toast("Export Berhasil", "File CSV log keamanan berhasil diunduh.", "green");
});

// ========================================================
// MODAL & POPUP KONTROL
// ========================================================
function toggleModal(modalId, show) {
  const m = $(modalId);
  if (!m) return;
  if (show) {
    m.classList.remove("hidden");
    m.classList.add("flex");
  } else {
    m.classList.add("hidden");
    m.classList.remove("flex");
  }
}

// Student Info Modal
$("btnStudentInfo").addEventListener("click", () => toggleModal("studentModal", true));
$("btnCloseStudentModal").addEventListener("click", () => toggleModal("studentModal", false));
$("btnDismissStudentModal").addEventListener("click", () => toggleModal("studentModal", false));

// Supabase Modal
$("btnSupabaseConfig").addEventListener("click", () => toggleModal("supabaseModal", true));
$("btnCloseSupabaseModal").addEventListener("click", () => toggleModal("supabaseModal", false));
$("btnDismissSupabaseModal").addEventListener("click", () => toggleModal("supabaseModal", false));

["studentModal", "supabaseModal"].forEach((id) => {
  const el = $(id);
  if (el) {
    el.addEventListener("click", (e) => {
      if (e.target.id === id) toggleModal(id, false);
    });
  }
});

// ========================================================
// KONEKSI & SINKRONISASI SUPABASE
// ========================================================
function updateSupabaseStatus(online, message) {
  isSupabaseOnline = online;
  const dot = $("supabaseDot");
  const txt = $("supabaseStatusText");
  const boxDot = $("sbBoxDot");
  const boxTitle = $("sbBoxTitle");
  const boxDesc = $("sbBoxDesc");
  const modalBadge = $("modalSbBadge");

  if (online) {
    if (dot) dot.className = "w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]";
    if (txt) {
      txt.textContent = "ONLINE";
      txt.className = "text-emerald-400 font-semibold";
    }
    if (modalBadge) {
      modalBadge.textContent = "Online Cloud";
      modalBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40";
    }
    if (boxDot) boxDot.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 mt-1 flex-shrink-0 animate-pulse";
    if (boxTitle) boxTitle.textContent = "Terhubung ke Supabase Cloud (Live)";
    if (boxDesc) boxDesc.textContent = message || "Semua aturan, blacklist, dan log audit disinkronkan secara real-time ke Supabase database.";
  } else {
    if (dot) dot.className = "w-2 h-2 rounded-full bg-slate-500";
    if (txt) {
      txt.textContent = "LOKAL";
      txt.className = "text-slate-400 font-semibold";
    }
    if (modalBadge) {
      modalBadge.textContent = "Lokal";
      modalBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700";
    }
    if (boxDot) boxDot.className = "w-2.5 h-2.5 rounded-full bg-slate-500 mt-1 flex-shrink-0";
    if (boxTitle) boxTitle.textContent = "Mode Penyimpanan Lokal Aktif";
    if (boxDesc) boxDesc.textContent = message || "Data tersimpan di memori browser. Masukkan Anon Key Supabase Anda di bawah agar sinkron ke server online.";
  }
}

async function initSupabase(customUrl, customKey) {
  const cfg = window.CYBERSHIELD_CONFIG || {};
  const url = customUrl || localStorage.getItem("cybershield_sb_url") || cfg.supabaseUrl || DEFAULT_SUPABASE_URL;
  const key = customKey || localStorage.getItem("cybershield_sb_key") || cfg.supabaseAnonKey || "";

  if ($("sbUrl")) $("sbUrl").value = url;
  if ($("sbKey")) $("sbKey").value = key;

  if (!window.supabase || !url || !key) {
    updateSupabaseStatus(false, "Masukkan Supabase URL & Anon Key untuk mengaktifkan koneksi database online.");
    return false;
  }

  try {
    supabaseClient = window.supabase.createClient(url, key);
    
    // Test query ke tabel firewall_rules
    const { data: rulesData, error: rulesErr } = await supabaseClient
      .from("firewall_rules")
      .select("id, rule_name, ip_address, port, protocol, action, is_active")
      .order("id", { ascending: true });

    if (rulesErr) {
      console.warn("Supabase query error:", rulesErr);
      updateSupabaseStatus(false, `Koneksi gagal: ${rulesErr.message}. Pastikan skrip supabase_schema.sql sudah dijalankan di SQL Editor Supabase.`);
      return false;
    }

    updateSupabaseStatus(true);
    localStorage.setItem("cybershield_sb_url", url);
    localStorage.setItem("cybershield_sb_key", key);

    // Muat data aturan dari Supabase jika ada
    if (rulesData && rulesData.length > 0) {
      state.rules = rulesData.map((r) => ({
        id: r.id,
        name: r.rule_name,
        ip: r.ip_address,
        port: isNaN(+r.port) ? r.port : +r.port,
        proto: r.protocol,
        action: r.action,
        active: r.is_active,
      }));
      state.nextRuleId = Math.max(...state.rules.map((r) => r.id), 0) + 1;
      renderRules();
    }

    // Muat blacklist dari Supabase
    const { data: blData } = await supabaseClient
      .from("blacklist_ips")
      .select("ip_address, reason, hits, blocked_at")
      .order("id", { ascending: false });

    if (blData && blData.length > 0) {
      state.blacklist = blData.map((b) => ({
        ip: b.ip_address,
        reason: b.reason,
        hits: b.hits || 0,
        added: b.blocked_at ? new Date(b.blocked_at).toLocaleDateString("id-ID", { day: "2-digit", month: "short", year: "numeric" }) : "Online",
      }));
      renderBlacklist();
    }

    // Muat log audit awal dari Supabase
    const { data: logData } = await supabaseClient
      .from("security_logs")
      .select("*")
      .order("id", { ascending: false })
      .limit(80);

    if (logData && logData.length > 0) {
      state.logs = logData.map((l) => ({
        time: l.event_time ? pad2(new Date(l.event_time).getHours()) + ":" + pad2(new Date(l.event_time).getMinutes()) + ":" + pad2(new Date(l.event_time).getSeconds()) : nowTime(),
        src: l.source_ip,
        port: isNaN(+l.dest_port) ? l.dest_port : +l.dest_port,
        proto: "TCP",
        jenis: l.activity_type || "Traffic",
        desc: l.description || "",
        action: l.action || "Izinkan",
        reason: l.reason || "",
      }));
      $("badgeLogs").textContent = state.logs.length;
      if (currentView === "logs") renderLogs();
    }

    // Setup Realtime Subscription
    setupRealtime();

    toast("Supabase Terhubung", "Sinkronisasi database online aktif secara real-time.", "green");
    return true;
  } catch (err) {
    console.error("Init Supabase Error:", err);
    updateSupabaseStatus(false, "Terjadi kesalahan saat menginisialisasi klien Supabase.");
    return false;
  }
}

function setupRealtime() {
  if (!supabaseClient || !isSupabaseOnline) return;
  try {
    if (supabaseRealtimeChannel) {
      supabaseClient.removeChannel(supabaseRealtimeChannel);
    }
    supabaseRealtimeChannel = supabaseClient
      .channel("cybershield-realtime-channel")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "firewall_rules" },
        async () => {
          const { data } = await supabaseClient.from("firewall_rules").select("*").order("id", { ascending: true });
          if (data) {
            state.rules = data.map((r) => ({
              id: r.id,
              name: r.rule_name,
              ip: r.ip_address,
              port: isNaN(+r.port) ? r.port : +r.port,
              proto: r.protocol,
              action: r.action,
              active: r.is_active,
            }));
            renderRules();
          }
        }
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "blacklist_ips" },
        async () => {
          const { data } = await supabaseClient.from("blacklist_ips").select("*").order("id", { ascending: false });
          if (data) {
            state.blacklist = data.map((b) => ({
              ip: b.ip_address,
              reason: b.reason,
              hits: b.hits || 0,
              added: "Realtime Sync",
            }));
            renderBlacklist();
          }
        }
      )
      .subscribe();
  } catch (e) {
    console.warn("Realtime listener error:", e);
  }
}

// Supabase Form Submissions
$("sbForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = $("sbUrl").value.trim();
  const key = $("sbKey").value.trim();

  if (!url || !key) {
    toast("Input Belum Lengkap", "Masukkan URL dan Anon Key Supabase Anda.", "amber");
    return;
  }

  toast("Menghubungkan...", "Menguji koneksi ke Supabase...", "cyan");
  const ok = await initSupabase(url, key);
  if (ok) {
    toggleModal("supabaseModal", false);
  }
});

$("btnDisconnectSb").addEventListener("click", () => {
  localStorage.removeItem("cybershield_sb_key");
  if ($("sbKey")) $("sbKey").value = "";
  if (supabaseRealtimeChannel && supabaseClient) supabaseClient.removeChannel(supabaseRealtimeChannel);
  supabaseClient = null;
  updateSupabaseStatus(false, "Koneksi Supabase diputuskan. Menggunakan memori lokal.");
  toast("Mode Lokal", "Database Supabase diputuskan.", "amber");
});

// Copy SQL Schema Button
$("btnCopySql").addEventListener("click", async () => {
  const sql = `-- Supabase Schema untuk CyberShield
CREATE TABLE IF NOT EXISTS public.firewall_rules (id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, rule_name VARCHAR(100) NOT NULL, ip_address VARCHAR(45) NOT NULL, port VARCHAR(20) NOT NULL, protocol VARCHAR(20) NOT NULL DEFAULT 'TCP', action VARCHAR(20) NOT NULL DEFAULT 'Izinkan', is_active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()));
CREATE TABLE IF NOT EXISTS public.security_logs (id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, event_time TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()), source_ip VARCHAR(45) NOT NULL, dest_port VARCHAR(20) NOT NULL, activity_type VARCHAR(100) NOT NULL, action VARCHAR(20) NOT NULL, description TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS public.blacklist_ips (id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, ip_address VARCHAR(45) NOT NULL UNIQUE, reason VARCHAR(255) NOT NULL, hits INT NOT NULL DEFAULT 0, blocked_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()));
ALTER TABLE public.firewall_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blacklist_ips ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public access firewall_rules" ON public.firewall_rules FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Public access security_logs" ON public.security_logs FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
CREATE POLICY "Public access blacklist_ips" ON public.blacklist_ips FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
ALTER PUBLICATION supabase_realtime ADD TABLE public.firewall_rules, public.security_logs, public.blacklist_ips;`;

  try {
    await navigator.clipboard.writeText(sql);
    toast("SQL Disalin", "Skrip schema Supabase berhasil disalin ke clipboard.", "green");
  } catch (e) {
    toast("Gagal Salin", "Buka berkas supabase_schema.sql secara manual.", "amber");
  }
});

// ========================================================
// SEED DATA AWAL LOKAL (FALLBACK)
// ========================================================
(function seedInitialData() {
  const initialLogs = [
    { min: 1, src: "185.220.101.7", port: 22, proto: "TCP", jenis: "Serangan", desc: "Percobaan login SSH berulang dari IP blacklist", action: "Blokir", reason: "Blacklist IP (Port Scan)" },
    { min: 3, src: "45.135.210.19", port: 80, proto: "TCP", jenis: "Serangan", desc: "Banjir paket HTTP melebihi ambang batas", action: "Blokir", reason: "Blacklist IP (Serangan DDoS)" },
    { min: 5, src: "103.75.196.44", port: 445, proto: "TCP", jenis: "Traffic Mencurigakan", desc: "Pemindaian port SMB terdeteksi", action: "Blokir", reason: "Blacklist IP (Brute Force SSH)" },
    { min: 7, src: "192.168.1.10", port: 443, proto: "TCP", jenis: "Traffic Normal", desc: "Koneksi HTTPS normal dari jaringan internal", action: "Izinkan", reason: "Aturan Firewall: Izinkan HTTPS Publik" },
    { min: 10, src: "203.0.113.88", port: 23, proto: "TCP", jenis: "Traffic Mencurigakan", desc: "Percobaan login telnet eksternal", action: "Blokir", reason: "Aturan Firewall: Blokir Telnet" },
    { min: 14, src: "10.10.1.25", port: 53, proto: "UDP", jenis: "Traffic Normal", desc: "Kueri DNS resolver internal", action: "Izinkan", reason: "Kebijakan Default: Traffic Terverifikasi" },
  ];

  initialLogs.forEach((s) => {
    const d = new Date(Date.now() - s.min * 60000);
    const t = pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
    state.logs.push({
      time: t,
      src: s.src,
      port: s.port,
      proto: s.proto,
      jenis: s.jenis,
      desc: s.desc,
      action: s.action,
      reason: s.reason,
    });
    if (s.action === "Blokir") {
      state.alerts.push({
        time: t,
        src: s.src,
        port: s.port,
        desc: s.desc,
        reason: s.reason,
      });
    }
  });

  $("badgeLogs").textContent = state.logs.length;
})();

// ========================================================
// LOOP UTAMA JARINGAN (1 DETIK SEKALI)
// ========================================================
function walkValue(current, target, maxStep) {
  const diff = target - current;
  const delta = Math.max(-maxStep, Math.min(maxStep, diff));
  const jitter = (Math.random() - 0.5) * maxStep * 0.5;
  return current + delta + jitter;
}

setInterval(() => {
  // 1. Update Jam WIB
  $("clock").textContent = nowTime();

  // 2. Pemrosesan Paket Real-time
  if (state.running) {
    const packetCount = ri(2, 4);
    for (let i = 0; i < packetCount; i++) {
      processPacket(generateNormalPacket());
    }

    state.seriesA.push(Math.min(state.tickAllowed, 60));
    state.seriesB.push(Math.min(state.tickBlocked, 60));
    if (state.seriesA.length > 40) {
      state.seriesA.shift();
      state.seriesB.shift();
    }

    state.tickAllowed = 0;
    state.tickBlocked = 0;
  }

  // 3. Update Variasi Metrik Sistem (CPU, RAM, Bandwidth)
  const isUnderAttack = Object.keys(state.activeAttacks).length > 0;
  if (!isUnderAttack && state.running) {
    state.cpuTarget = 18 + Math.random() * 8;
    state.memTarget = 42 + Math.random() * 5;
    state.bwTarget = 1.2 + Math.random() * 1.5;
  }

  state.cpu = Math.max(5, Math.min(99, walkValue(state.cpu, state.cpuTarget, 6)));
  state.mem = Math.max(20, Math.min(98, walkValue(state.mem, state.memTarget, 3)));
  state.bw = Math.max(0.2, Math.min(45, walkValue(state.bw, state.bwTarget, 3.0)));

  renderHealthGauges();

  if (currentView === "dashboard") {
    drawTrafficChart();
  }
}, 1000);

// ========================================================
// INISIALISASI AWAL APLIKASI
// ========================================================
renderStats();
renderPorts();
renderAlerts();
renderRules();
renderBlacklist();
renderHealthGauges();
renderSimulationState();

$("clock").textContent = nowTime();
requestAnimationFrame(drawTrafficChart);

// Inisialisasi Supabase (Mengambil data tersimpan jika ada)
setTimeout(() => {
  initSupabase();
  toast("CyberShield Siap", "Sistem firewall logis dan inspeksi paket jaringan aktif.", "green");
}, 400);
