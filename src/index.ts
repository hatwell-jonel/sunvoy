import fetch from 'node-fetch';
import fetchCookie from 'fetch-cookie';
import { CookieJar } from 'tough-cookie';
import crypto from 'crypto';
import { JSDOM } from 'jsdom';
import fs from "fs";

const BASE_URL = 'https://challenge.sunvoy.com';
const API_URL = 'https://api.challenge.sunvoy.com';

const USERNAME = 'demo@example.org';
const PASSWORD = 'test';

const cookieJar = new CookieJar();
const fetchWithCookies = fetchCookie(fetch, cookieJar);


/**
 * Fetches the login page and extracts the nonce token required for login.
 * @returns {Promise<string>} The nonce token string.
 * @throws Will throw an error if the nonce token is not found in the login page HTML.
 */
async function getNonce(): Promise<string> {
  const res = await fetchWithCookies(`${BASE_URL}/login`, {
    method: 'GET',
    headers: { Accept: 'text/html' },
  });
  const html = await res.text();
  const match = html.match(/name="nonce" value="([^"]+)"/);
  if (!match) throw new Error('Nonce token not found in login page');
  return match[1];
}

/**
 * Extracts all hidden input fields from an HTML string, keyed by their input element ID.
 * @param {string} html - The HTML string to parse.
 * @returns {Record<string, string>} An object mapping input IDs to their values.
 */
function extractHiddenInputs(html: string): Record<string, string> {
  const dom = new JSDOM(html);
  const doc = dom.window.document;
  const inputs = doc.querySelectorAll('input[type="hidden"]');
  const result: Record<string, string> = {};
  inputs.forEach((input) => {
    const inputEl = input as HTMLInputElement;
    if (inputEl.id && inputEl.value) {
      result[inputEl.id] = inputEl.value;
    }
  });
  return result;
}

/**
 * Creates a signed request payload with timestamp and HMAC SHA1 checkcode.
 * The checkcode is generated using the shared secret 'mys3cr3t' and the sorted query string.
 * @param {Record<string, string>} data - The data object to include in the payload.
 * @returns {{ payload: string; checkcode: string; fullPayload: string; timestamp: number }} 
 * An object containing the query string payload, checkcode, full signed payload, and timestamp.
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
 * Performs login using nonce, username, and password.
 * Throws an error if login is not successful (status code is not 302 redirect).
 * @param {string} nonce - The nonce token extracted from login page.
 * @param {string} username - The username credential.
 * @param {string} password - The password credential.
 */
async function login(nonce: string, username: string, password: string) {
  const formBody = new URLSearchParams({ nonce, username, password });
  const res = await fetchWithCookies(`${BASE_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: BASE_URL,
      Referer: `${BASE_URL}/login`,
    },
    body: formBody.toString(),
    redirect: 'manual', // expect redirect after login
  });
  if (res.status !== 302) {
    throw new Error(`Login failed with status ${res.status}`);
  }
}

/**
 * Fetches the list of users from the internal users API.
 * @returns {Promise<any[]>} The array of user objects.
 * @throws Will throw an error if the request fails.
 */
async function fetchUsers(): Promise<any> {
  const res = await fetchWithCookies(`${BASE_URL}/api/users`, {
    method: 'POST',
    headers: {
      'Accept': '*/*',
      'Origin': `${BASE_URL}`,
      'Referer': `${BASE_URL}/list`,
    },
    // No body needed, content-length=0
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`Failed to fetch users: ${res.status} - ${text}`);
  return JSON.parse(text);
}


/**
 * Fetches the tokens settings page HTML.
 * @returns {Promise<string>} The HTML content of the tokens settings page.
 * @throws Will throw an error if the request fails.
 */
async function fetchTokensPage(): Promise<string> {
  const res = await fetchWithCookies(`${BASE_URL}/settings/tokens`, {
    method: 'GET',
    headers: {
      Accept: 'text/html',
      Referer: BASE_URL,
    },
  });
  if (!res.ok) throw new Error(`Failed to fetch tokens page: ${res.status}`);
  return await res.text();
}

/**
 * Fetches the currently authenticated user's info from the API using a signed payload.
 * @param {string} signedPayload - The full signed payload string (including checkcode).
 * @returns {Promise<any>} The current user object.
 * @throws Will throw an error if the request fails.
 */
async function fetchCurrentUser(signedPayload: string) {
  const res = await fetchWithCookies(`${API_URL}/api/settings`, {
    method: 'POST',
    headers: {
      Accept: '*/*',
      Origin: BASE_URL,
      Referer: `${BASE_URL}/settings/tokens`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: signedPayload,
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`Failed to fetch current user: ${res.status} - ${text}`);

  return JSON.parse(text);
}


/**
 * Checks if the current session is still valid by attempting to access a page requiring authentication.
 * @returns {Promise<boolean>} True if session is valid; false otherwise.
 */
async function isSessionValid(): Promise<boolean> {
  const res = await fetchWithCookies(`${BASE_URL}/settings/tokens`, {
    method: 'GET',
    headers: {
      Accept: 'text/html',
      Referer: BASE_URL,
    },
    redirect: 'manual',
  });

  const location = res.headers.get('location');
  return res.status === 200 && !location?.includes('/login');
}



/**
 * Main entry point of the script.
 * - Checks session validity.
 * - Logs in if needed.
 * - Fetches users and current user info.
 * - Writes combined user info to users.json.
 */
async function main() {
  try {

    const hasValidSession = await isSessionValid();

    if (!hasValidSession) {
      try {
        const nonce = await getNonce();
        await login(nonce, USERNAME, PASSWORD);
        console.log('🔑 Logged in again.');
      } catch (error) {
        console.error('❌ Login failed:', error);
        return; // Or rethrow if you want to bubble up
      }
    } else {
      console.log('✅ Existing session is still valid.');
    }

    const users = await fetchUsers();
    const tokensPageHtml = await fetchTokensPage();
    const hiddenInputs = extractHiddenInputs(tokensPageHtml);
    const signedRequest = createSignedRequest(hiddenInputs);
    const currentUser = await fetchCurrentUser(signedRequest.fullPayload);

     const result = [
      ...users.map((u: any) => ({
        id: u.id,
        firstName: u.firstName,
        lastName: u.lastName,
        email: u.email,
      })),
      {
        id: currentUser.id,
        firstName: currentUser.firstName,
        lastName: currentUser.lastName,
        email: currentUser.email,
      },
    ];

    fs.writeFileSync('users.json', JSON.stringify(result, null, 2));
    console.log('✅ users.json generated');
  } catch (err) {
    console.error('Error:', err);
  }
}

main();
