'use strict';
/**
 * Bot vs human classification from the User-Agent header.
 *
 * Deliberately mirrors the same pattern lists nginx itself already uses to
 * block or allow traffic (good-bots.conf, ia-bots.conf, bad-bots.conf) rather
 * than inventing a separate classification: what the dashboard calls a
 * "bot" should match what nginx already treats as one, or the two disagree
 * about the same traffic for no good reason.
 */

const GOOD_BOTS = [
  /googlebot/i, /bingbot/i, /adidxbot/i,
  /duckduckbot/i, /qwantify/i, /baiduspider/i, /yandexbot/i, /yeti/i,
  /facebookexternalhit/i, /twitterbot/i, /pinterestbot/i,
];

const AI_BOTS = [
  /Applebot-Extended/i, /GPTBot/i, /CCBot/i, /Cohere-ai/i, /ChatGPT-User/i,
  /OAI-SearchBot/i, /ClaudeBot/i, /Claude-web/i, /Google-Extended/i,
  /GoogleOther/i, /ImagesiftBot/i, /Meta-ExternalAgent/i, /PerplexityBot/i,
  /YouBot/i, /FacebookBot/i,
];

const BAD_BOTS = [
  /AhrefsBot/i, /Amazonbot/i, /Bytespider/i, /DataForSeoBot/i, /DotBot/i,
  /MJ12bot/i, /PetalBot/i, /Rogerbot/i, /SemrushBot/i, /Seomoz/i, /Sogou/i,
  /VelenPublicWebCrawler/i, /YanBot/i, /Shodan/i, /Censys/i, /Nmap/i,
  /ZmEu/i, /Masscan/i,
];

// Anything self-identifying as automated but not on one of the three named
// lists above — a generic net-negative signal, distinct from "definitely
// malicious" or "definitely a known crawler".
const GENERIC_BOT_HINT = /bot|crawler|spider|scrapy|python-requests|curl|wget|go-http-client|java\/|libwww|httpclient|okhttp|axios\/|node-fetch/i;

/**
 * Classify a User-Agent string.
 * Returns { isBot, category } where category is 'good' | 'ai' | 'bad' |
 * 'unknown' (automated but unrecognized) | 'human' | null (no UA at all —
 * distinct from "human", since a missing header is itself unusual).
 */
function classifyAgent(ua) {
  if (!ua) return { isBot: null, category: null };
  if (GOOD_BOTS.some(re => re.test(ua))) return { isBot: true, category: 'good' };
  if (AI_BOTS.some(re => re.test(ua)))   return { isBot: true, category: 'ai' };
  if (BAD_BOTS.some(re => re.test(ua)))  return { isBot: true, category: 'bad' };
  if (GENERIC_BOT_HINT.test(ua))         return { isBot: true, category: 'unknown' };
  return { isBot: false, category: 'human' };
}

module.exports = { classifyAgent, GOOD_BOTS, AI_BOTS, BAD_BOTS, GENERIC_BOT_HINT };
