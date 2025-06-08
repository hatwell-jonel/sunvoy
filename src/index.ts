import fetch from 'node-fetch';
import fetchCookie from 'fetch-cookie';
import { CookieJar } from 'tough-cookie';
import { JSDOM } from 'jsdom';
import crypto from 'crypto';
import fs from 'fs';

type UserData = {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
};

const BASE_URL = 'https://challenge.sunvoy.com';
const API_URL = 'https://api.challenge.sunvoy.com';

const CREDENTIAL = {
  username: 'demo@example.org',
  password: 'test',
}

const fetchWithCookies = fetchCookie(fetch, new CookieJar());

/**
 * Fetches the login page and extracts the nonce token required for login.
 * @returns {Promise<string>} The nonce token string.
 * @throws Throws if nonce is not found in the login page HTML.
 */
async function getNonce(): Promise<string> {
  const res = await fetchWithCookies(`${BASE_URL}/login`, { headers: { Accept: 'text/html' } });
  const match = (await res.text()).match(/name="nonce" value="([^"]+)"/);
  if (!match) throw new Error('Nonce not found');
  return match[1];
};


/**
 * Fetches a URL and parses the JSON response.
 * Throws an error if the response is not OK.
 * @param {string} url The endpoint URL to fetch.
 * @param {any} [options] Optional fetch options.
 * @returns {Promise<any>} Parsed JSON response.
 */
async function fetchJson  (url: string, options?: any) {
  const res = await fetchWithCookies(url, options);
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} failed: ${res.status} - ${text}`);
  return JSON.parse(text);
};

/**
 * Parses the given HTML and extracts all hidden input elements with id and value.
 * @param {string} html The HTML string to parse.
 * @returns {Record<string, string>} Key-value pairs of input id and value.
 */
function extractHiddenInputs(html: string): Record<string, string> {
  return [...new JSDOM(html).window.document.querySelectorAll('input[type="hidden"]')]
    .reduce((acc, el) => {
      const input = el as HTMLInputElement;
      if (input.id && input.value) acc[input.id] = input.value;
      return acc;
    }, {} as Record<string, string>);
}

/**
 * Creates a signed request payload by adding a timestamp and generating
 * an HMAC-SHA1 checkcode with a secret key (mys3cr3t).
 * @param {Record<string, string>} data The data to include in the payload.
 * @returns {{ payload: string; checkcode: string; fullPayload: string; timestamp: number }} Signed payload details.
 */
function createSignedRequest(data: Record<string, string>) {
  const timestamp = Math.floor(Date.now() / 1000);
  const payloadObj = { ...data, timestamp: timestamp.toString() } as Record<string, string>;

  const sortedKeys = Object.keys(payloadObj).sort();
  const queryString = sortedKeys
    .map((key) => `${key}=${encodeURIComponent(payloadObj[key])}`)
    .join('&');

  const hmac = crypto.createHmac('sha1', 'mys3cr3t');
  hmac.update(queryString);
  const checkcode = hmac.digest('hex').toUpperCase();

  const fullPayload = `${queryString}&checkcode=${checkcode}`;

  return { payload: queryString, checkcode, fullPayload, timestamp };
}

/**
 * Performs login by retrieving nonce, sending credentials with nonce,
 * and checking for a successful redirect.
 * @throws Throws error if login response status is not a redirect (302).
 */
async function login() {
  const nonce = await getNonce();
  const formBody = new URLSearchParams({ nonce, username: CREDENTIAL.username, password: CREDENTIAL.password });
  const res = await fetchWithCookies(`${BASE_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: BASE_URL,
      Referer: `${BASE_URL}/login`,
    },
    body: formBody.toString(),
    redirect: 'manual',
  });
  if (res.status !== 302) throw new Error(`Login failed: ${res.status}`);
};

/**
 * Checks if the current session is valid by requesting a protected page
 * and verifying the response is not a redirect to login.
 * @returns {Promise<boolean>} True if session is valid, false otherwise.
 */
async function isSessionValid(): Promise<boolean>{
  const res = await fetchWithCookies(`${BASE_URL}/settings/tokens`, {
    headers: { Accept: 'text/html', Referer: BASE_URL }, redirect: 'manual',
  });
  return res.status === 200 && !(res.headers.get('location')?.includes('/login'));
};


/**
 * Main function to manage session, fetch user data, and write to users.json.
 * Logs in if needed and combines user list with current user info.
 */
async function main() {
  try {
    const hasValidSession = await isSessionValid();

    if (!hasValidSession) {
      try {
        await login();
        console.log('🔑 Logged in again.');
      } catch (error) {
        console.error('❌ Login failed:', error);
        return;
      }
    } else {
      console.log('✅ Existing session is still valid.');
    }

    const users = await fetchJson(`${BASE_URL}/api/users`, {
      method: 'POST',
      headers: { Accept: '*/*', Origin: BASE_URL, Referer: `${BASE_URL}/list` },
    });

    const tokensHtml = await fetchWithCookies(`${BASE_URL}/settings/tokens`, {
      headers: { Accept: 'text/html', Referer: BASE_URL },
    }).then(r => r.text());

    const signedPayload = createSignedRequest(extractHiddenInputs(tokensHtml)).fullPayload;

    const currentUser = await fetchJson(`${API_URL}/api/settings`, {
      method: 'POST',
      headers: {
        Accept: '*/*', Origin: BASE_URL,
        Referer: `${BASE_URL}/settings/tokens`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: signedPayload,
    });

    const result = [...users, currentUser]
    .map( ({ id, firstName, lastName, email }: UserData) =>
      ({ id, firstName, lastName, email }));

    fs.writeFileSync('users.json', JSON.stringify(result, null, 2));
    console.log('✅ users.json generated');
  } catch (err) {
    console.error('Error:', err);
  }
}

main();
