import * as jwt from 'jsrsasign';

export const TOKEN = 'token';

export interface jwtPayload {
  username: string;
  iat: number;
  exp: number;
}

export function getAuthToken(): string | null {
  const token = getCookie(TOKEN);
  if (token === null) {
    return null;
  }

  return token;
}

export function getAuthClaims(token: string): jwtPayload | null {
  try {
    const secret = process.env.REACT_APP_HUBBLE_SECRET_KEY ?? '';
    if (jwt.KJUR.jws.JWS.verifyJWT(token, secret, { alg: ['HS512'] })) {
      const payload = jwt.KJUR.jws.JWS.readSafeJSONString(
        jwt.b64utoutf8(token.split('.')[1]),
      );

      return payload as jwtPayload;
    }

    return null;
  } catch (e) {
    return null;
  }
}

export function getCookie(name: string): string | null {
  const nameLenPlus = name.length + 1;
  return (
    document.cookie
      .split(';')
      .map(c => c.trim())
      .filter(cookie => {
        return cookie.substring(0, nameLenPlus) === `${name}=`;
      })
      .map(cookie => {
        return decodeURIComponent(cookie.substring(nameLenPlus));
      })[0] || null
  );
}

export function deleteAuthCookie() {
  document.cookie = TOKEN + '=; Path=/;';
}
