import { environment } from '../../environments/environment';
import { JwtTokenConstants, JwtTokenHelper } from './JwtHelper';

export interface LoginResult {
  [x: string]: any;
  code?: string;
  error?: string;
  timerId?: number;
}

export interface IOAuthService {
  openLoginPopup(options: OAuthPopupOptions): IOAuthPopup;

  fetchConsentUrlForConnection: (connectionId: string) => Promise<string>;
  confirmConsentCodeForConnection: (connectionId: string, code: string) => Promise<any>;
}

export interface IOAuthServiceOptions {
  apiVersion: string;
  baseUrl: string;
  httpClient: any;
  subscriptionId: string;
  resourceGroup: string;
  location: string;
}

export interface IOAuthPopup {
  [x: string]: any;
  loginPromise: Promise<any>;
}

interface ConfirmConsentCodeRequest {
  code: string;
  objectId: string;
  tenantId: string;
}

interface ConsentLinkRequest {
  parameters: ConsentLinkObject[];
}

interface ConsentLinkObject {
  objectId?: string;
  parameterName?: string;
  redirectUrl: string;
  tenantId?: string;
}

export interface ConsentLink {
  link: string;
  displayName?: string;
  status?: string;
}

export interface OAuthPopupOptions {
  consentUrl: string;
  redirectUrl: string;
}

const popupId = 'msla-logicapps-oauthpopup';

const getRedirectUri = async (): Promise<string> => {
  return `https://localhost:4200/oauthredirect.html?pid=${popupId}`;
};

export class OAuthPopup implements IOAuthPopup {
  public loginPromise: Promise<LoginResult>;

  private _popupId: string;
  private _popupWindow: Window | undefined;
  private _timer: any;
  private _msg?: string;
  constructor(options: OAuthPopupOptions) {
    const { consentUrl } = options;
    this._popupId = popupId;
    this.loginPromise = this.login(consentUrl);
  }

  private login = async (consentUrl: string): Promise<LoginResult> => {
    const redirect_uri = await getRedirectUri();
    const authUrl = new URL(consentUrl);
    authUrl.searchParams.set('redirect_uri', redirect_uri);

    const oAuthWindow = window.open(authUrl.href, this._popupId, 'scrollbars=1, resizable=1, width=600, height=600, popup=1');
    if (!oAuthWindow) throw new Error('The browser has blocked the popup window.');
    // eslint-disable-next-line no-restricted-globals
    oAuthWindow?.moveBy(screen.width / 2 - 600 / 2, screen.height / 2 - 600 / 2);
    this._popupWindow = oAuthWindow;

    if (!this._popupWindow) {
      throw new Error('The browser has blocked the popup window.');
    }

    let timeoutCounter = 0;
    const listener = (event: MessageEvent) => {
      const origin = event.origin;
      const redirectOrigin = new URL(redirect_uri).origin;
      if (origin !== redirectOrigin) return;
      this._msg = decodeURIComponent(event.data);
      window.removeEventListener('message', listener);
      this._popupWindow?.close();
    };
    window.addEventListener('message', listener);
    return new Promise<LoginResult>((resolve, reject) => {
      this._timer = window.setInterval(() => {
        timeoutCounter++;
        this.handlePopup(resolve, reject, timeoutCounter);
      }, 1000);
    });
  };

  private handlePopup(resolve: any, reject: any, timeoutCounter: number) {
    if (this._popupWindow?.closed) {
      const storageValue = this._msg ? decodeURIComponent(this._msg) : undefined;

      if (storageValue) {
        resolve({ code: JSON.parse(storageValue).code });
      } else {
        reject({
          name: 'Error',
          message: 'The browser is closed',
        });
      }
      clearInterval(this._timer);
    } else if (timeoutCounter >= 300) {
      reject({
        name: 'Error',
        message: 'Timeout',
      });
      clearInterval(this._timer);
    }
  }
}

export class StandaloneOAuthService implements IOAuthService {
  constructor(private readonly options: IOAuthServiceOptions) {}

  public openLoginPopup(options: OAuthPopupOptions): IOAuthPopup {
    return new OAuthPopup(options);
  }

  private getConnectionRequestPath(connectionName: string): string {
    const { subscriptionId, resourceGroup } = this.options;
    return `/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Web/connections/${connectionName}`;
  }

  public async confirmConsentCodeForConnection(connectionName: string, code: string) {
    const { baseUrl, httpClient, apiVersion } = this.options;
    const hostName = baseUrl.split('/subscriptions')[0];
    const uri = `${hostName}${this.getConnectionRequestPath(connectionName)}/confirmConsentCode`;

    const authToken = environment.armToken;
    if (!authToken) throw new Error('No ARM token found');
    const helper = JwtTokenHelper.createInstance();
    const tokenObject = helper.extractJwtTokenPayload(authToken);
    const requestBody: ConfirmConsentCodeRequest = {
      code,
      objectId: tokenObject[JwtTokenConstants.objectId],
      tenantId: tokenObject[JwtTokenConstants.tenantId],
    };

    return httpClient.post({
      content: requestBody,
      uri,
      queryParameters: {
        'api-version': apiVersion,
      },
    });
  }

  public async fetchConsentUrlForConnection(connectionName: string) {
    const { baseUrl, httpClient, apiVersion } = this.options;
    const hostName = baseUrl.split('/subscriptions')[0];
    const uri = `${hostName}${this.getConnectionRequestPath(connectionName)}/listConsentLinks`;

    const authToken = environment.armToken;
    if (!authToken) throw new Error('No ARM token found');
    const helper = JwtTokenHelper.createInstance();
    const tokenObject = helper.extractJwtTokenPayload(authToken);
    const requestBody: ConsentLinkRequest = {
      parameters: [
        {
          parameterName: 'token',
          redirectUrl: await getRedirectUri(),
          objectId: tokenObject[JwtTokenConstants.objectId],
          tenantId: tokenObject[JwtTokenConstants.tenantId],
        },
      ],
    };

    try {
      const response = await httpClient.post({
        content: requestBody,
        uri,
        queryParameters: {
          'api-version': apiVersion,
        },
      });

      if (response?.value[0]?.link) return response.value[0].link;
      else throw new Error('Error fetching consent URL');
    } catch (error) {
      console.error(error);
      throw new Error(error as any);
    }
  }
}
