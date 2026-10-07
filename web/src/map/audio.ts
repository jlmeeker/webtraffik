import type { LonLat } from '../lib/types';
import { geoDistKm, MAX_GEO_DIST_KM } from '../lib/utils/geo';
import { getPref, setPref } from '../lib/utils/prefs';

const AUDIO_MIN_DURATION = 0.06;
const AUDIO_MAX_DURATION = 0.5;
const AUDIO_BASE_FREQ = 220;
const AUDIO_TOP_FREQ = 1320;
const AUDIO_GAIN = 0.07;
const MAX_CONCURRENT_TONES = 12;
const PREF_KEY = 'audioEnabled';

/** Pure mapping from great-circle distance → tone parameters (unit-tested). */
export function toneFor(src: LonLat, dst: LonLat): { duration: number; freq: number } {
  const t = Math.min(geoDistKm(src, dst) / MAX_GEO_DIST_KM, 1);
  return {
    duration: AUDIO_MIN_DURATION + t * (AUDIO_MAX_DURATION - AUDIO_MIN_DURATION),
    freq: AUDIO_TOP_FREQ - t * (AUDIO_TOP_FREQ - AUDIO_BASE_FREQ),
  };
}

/** Web Audio sine blips per event; pitch/duration follow arc length. */
export class AudioEngine {
  private ctx: AudioContext | null = null;
  private active = 0;
  enabled = getPref(PREF_KEY) === 'true';

  private ensureCtx(): AudioContext | null {
    try {
      if (!this.ctx) this.ctx = new AudioContext();
      if (this.ctx.state === 'suspended') void this.ctx.resume();
      return this.ctx;
    } catch {
      return null;
    }
  }

  setEnabled(on: boolean): void {
    this.enabled = on;
    setPref(PREF_KEY, String(on));
    if (on) this.ensureCtx();
  }

  /** Browsers need a user gesture before audio can start. */
  armUnlock(): void {
    if (!this.enabled) return;
    const unlock = () => {
      this.ensureCtx();
      document.removeEventListener('pointerdown', unlock);
      document.removeEventListener('keydown', unlock);
    };
    document.addEventListener('pointerdown', unlock);
    document.addEventListener('keydown', unlock);
  }

  play(src: LonLat, dst: LonLat): void {
    if (!this.enabled || this.active >= MAX_CONCURRENT_TONES) return;
    const ctx = this.ensureCtx();
    if (!ctx) return;
    const { duration, freq } = toneFor(src, dst);
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, now);
    osc.frequency.exponentialRampToValueAtTime(freq * 0.85, now + duration);
    gain.gain.setValueAtTime(0, now);
    gain.gain.linearRampToValueAtTime(AUDIO_GAIN, now + 0.008);
    gain.gain.setValueAtTime(AUDIO_GAIN, now + duration * 0.5);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);
    osc.connect(gain);
    gain.connect(ctx.destination);
    this.active++;
    osc.start(now);
    osc.stop(now + duration);
    osc.onended = () => {
      this.active--;
      osc.disconnect();
      gain.disconnect();
    };
  }
}
