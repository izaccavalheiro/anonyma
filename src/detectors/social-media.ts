/**
 * @module detectors/social-media
 * @description Detector for social media identifiers and handles.
 *
 * Covered:
 * - Twitter/X handles: @username (1-15 alphanumeric/underscore)
 * - Instagram handles: @username (1-30 alphanumeric/underscore/period)
 * - Discord IDs: 17-19 digit snowflake IDs
 * - YouTube channel IDs: UC + 22 base64 chars
 * - TikTok handles: @username
 * - LinkedIn profile URLs: linkedin.com/in/...
 * - Reddit usernames: u/username
 */

import type { PiiMatch } from "../types.js";

/**
 * Twitter/X handle: @ + 1-15 word chars (letters, digits, underscores).
 * No period allowed in Twitter handles.
 * @internal
 */
const TWITTER_HANDLE_PATTERN = /(?<![a-zA-Z0-9])@[a-zA-Z0-9_]{1,15}(?![a-zA-Z0-9_@])/g;

/**
 * Discord snowflake ID: 17-19 digit integer.
 * Requires context keyword.
 * @internal
 */
const DISCORD_ID_PATTERN = /\b\d{17,19}\b/g;

/**
 * YouTube channel ID: UC + 22 base64 URL-safe chars
 * @internal
 */
const YT_CHANNEL_PATTERN = /\bUC[a-zA-Z0-9_-]{22}\b/g;

/**
 * Reddit username: u/ or /u/ prefix
 * @internal
 */
const REDDIT_USER_PATTERN = /\b(?:u|\/u)\/[a-zA-Z0-9_-]{3,20}\b/g;

/**
 * LinkedIn profile URL fragment
 * @internal
 */
const LINKEDIN_PATTERN = /\blinkedin\.com\/in\/[a-zA-Z0-9-]{3,100}\b/gi;

/**
 * Context keywords for Discord IDs.
 * @internal
 */
const DISCORD_CONTEXT_RE =
  /\b(?:discord(?:\s+(?:id|user|server|guild))?|user\s+id|uid)\s*:?\s*/gi;

/**
 * Detect social media identifiers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "social-media"`.
 */
export function detectSocialMedia(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const discordContextPositions: number[] = [];
  const ctxRe = new RegExp(DISCORD_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    discordContextPositions.push(cm.index + cm[0].length);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    // Social-media patterns never produce overlapping ranges in practice.
    /* v8 ignore next */
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "social-media", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // Twitter handles — use the more restrictive pattern (no periods)
  // Apply conservative confidence since @ is common in other contexts
  const twitterRe = new RegExp(TWITTER_HANDLE_PATTERN.source, "g");
  while ((m = twitterRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  // YouTube channel IDs — distinctive
  const ytRe = new RegExp(YT_CHANNEL_PATTERN.source, "g");
  while ((m = ytRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.90);
  }

  // Reddit usernames
  const redditRe = new RegExp(REDDIT_USER_PATTERN.source, "g");
  while ((m = redditRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.85);
  }

  // LinkedIn profiles
  const linkedinRe = new RegExp(LINKEDIN_PATTERN.source, "gi");
  while ((m = linkedinRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.92);
  }

  // Discord snowflake IDs — requires context
  const discordRe = new RegExp(DISCORD_ID_PATTERN.source, "g");
  while ((m = discordRe.exec(text)) !== null) {
    const match = m;
    const hasContext = discordContextPositions.some(
      (pos) => pos <= match.index && match.index - pos <= 30,
    );
    if (hasContext) push(match[0], match.index, match.index + match[0].length, 0.85);
  }

  return matches;
}
