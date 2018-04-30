/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { StringTools, Password } from "zoapp-core";
import createModel from "./model";
import Route from "./model/route";
import { GRANT_TYPE_PASSWORD, GRANT_TYPE_REFRESH_TOKEN } from "./constants";

export class ZOAuthServer {
  /* static ErrorsMessages = {
    CANT_REGISTER: "Can't register this application name",
    WRONG_EMAIL: "Wrong email sent",
    WRONG_NAME: "Wrong name sent",
    CANT_SAVE_APP: "Can't save application",
  }; */
  constructor(config = {}, database = null) {
    this.config = { ...config };
    this.model = createModel(this.config.database, database);
    this.permissionRoutes = [];
  }

  /* eslint-disable class-methods-use-this */
  createResultResponse(message) {
    return {
      result: message,
    };
  }

  async start() {
    await this.model.open();
  }

  async stop() {
    await this.model.close();
  }

  async reset() {
    await this.model.reset();
  }

  getRoute(routeName) {
    return this.permissionRoutes[routeName];
  }

  addRoute(routeName, scope = "default", method = "GET", auth = true) {
    // Check if route is already present and add new scopes / methods
    let route = this.getRoute(routeName);
    if (!route) {
      route = new Route(routeName, auth);
      this.permissionRoutes[routeName] = route;
    }
    route.addScope(scope);
    route.addMethod(method);
    return route;
  }

  findRoute(routeName, method = "GET") {
    let route = this.getRoute(routeName);
    // logger.info("route=" + route ? JSON.stringify(route) : "no route");
    if (!(route && route.isMethodValid(method))) {
      route = null;
    }
    return route;
  }

  async grantAccess(
    routeName,
    method = "GET",
    accessToken = null,
    appCredentials = null,
  ) {
    const route = this.findRoute(routeName, method);
    let response = {};
    let access = null;
    if (route && accessToken) {
      access = await this.model.validateAccessToken(accessToken);
      if (access) {
        const authenticateUser = await this.model.getUser(access.user_id);
        if (authenticateUser) {
          // logger.info("access=", access);
          // logger.info("route=", route);
          if (route.isScopeValid(access.scope)) {
            /* eslint-disable camelcase */
            const {
              access_token,
              client_id,
              expires_in,
              refresh_token,
              scope,
              user_id,
            } = access;
            response.result = {
              access_token,
              client_id,
              expires_in,
              refresh_token,
              scope,
              user_id,
            };
            /* eslint-enable camelcase */
          } else {
            response = this.createResultResponse({
              error: "Not allowed",
            });
          }
        } else {
          response = this.createResultResponse({
            error: "Not valid user account",
          });
        }
      } else {
        response = this.createResultResponse({
          error: "Not valid access token",
        });
      }
    } else if (route && route.isOpen()) {
      response = this.createResultResponse({
        access: "open",
      });
    } else if (
      route &&
      route.isScopeValid("application") &&
      (await this.validateApplicationCredentials(appCredentials))
    ) {
      response = this.createResultResponse({
        client_id: appCredentials.id,
        scope: "application",
      });
    } else {
      response = this.createResultResponse({
        error: "No permission route",
      });
    }
    return response;
  }

  static validatePassword(params) {
    const { password } = params;
    const strength = Password.strength(password);
    let response = {};
    if (strength > 0) {
      const hash = Password.generateSaltHash(password);
      response.result = { hash, strength };
    } else {
      response = this.createResultResponse({ error: "Empty password" });
    }
    return response;
  }

  async validateApplicationCredentials(credentials) {
    const app = await this.getApplication(credentials.id);
    if (app && app.secret === credentials.secret) {
      return true;
    }
    return false;
  }

  static validateApplicationName(name) {
    // TODO regex name validation
    let ret = true;
    if (StringTools.stringIsEmpty(name) || name.length < 3) {
      ret = false;
    }
    return ret;
  }

  /**
   * Register a Client Application
   */
  async registerApplication(params) {
    const {
      name,
      url,
      email,
      redirect_uri: redirectUri,
      grant_type: grantType,
      policies,
      domains,
    } = params;
    // logger.info("registerApplication");
    let response = {};
    let app = null;
    const wrongEmail = !StringTools.isEmail(email);
    if (ZOAuthServer.validateApplicationName(name) && !wrongEmail) {
      app = await this.model.getApplicationByName(name);
      if (!app) {
        app = {
          name,
          url,
          email,
          policies,
          redirect_uri: redirectUri,
          grant_type: grantType,
          domains,
        };
      } else {
        // logger.info("app exist !");
        app = null;
        response = this.createResultResponse({
          error: "Can't register this application name",
        });
      }
    } else if (wrongEmail) {
      response = this.createResultResponse({
        error: "Wrong email sent",
      });
    } else {
      response = this.createResultResponse({
        error: "Wrong name sent",
      });
    }

    if (app) {
      app = await this.model.setApplication(app);
      // logger.info("app=", app);
      if (app) {
        response = this.createResultResponse({
          client_id: app.id,
          client_secret: app.secret,
        });
      } else {
        response = this.createResultResponse({
          error: "Can't save application",
        });
      }
    }
    // TODO authorizedIps CORS params
    return response;
  }

  static validateCredentialsValue(
    username,
    email,
    password,
    policies = { userNeedEmail: true },
  ) {
    // TODO regex username validation
    let ret = true;
    if (StringTools.stringIsEmpty(username) || username.length < 1) {
      ret = false;
    }
    if (StringTools.stringIsEmpty(password) || password.length < 4) {
      ret = false;
    }
    if (policies.userNeedEmail && !StringTools.isEmail(email)) {
      ret = false;
    }
    return ret;
  }

  /**
   * Register a ResourceOwner User
   */
  async anonymousAccess(params) {
    const { client_id: clientId, anonymous_secret: anonymousSecret } = params;
    let app = null;
    let response = null;
    let username = null;
    let userId = null;
    if (clientId) {
      app = await this.model.getApplication(clientId);
      const policies = (app && app.policies) || {};
      if (policies.authorizeAnonymous) {
        let p = { client_id: clientId, anonymous_secret: anonymousSecret };
        response = await this.registerUser(p);
        if (response.result.id) {
          ({ username, id: userId } = response.result);
          p = {
            client_id: clientId,
            username,
            password: anonymousSecret,
            scope: "anonymous",
            redirect_uri: "localhost",
          };
          response = await this.authorizeAccess(p);
          if (response.result.redirect_uri) {
            p = {
              client_id: clientId,
              username,
              password: anonymousSecret,
              grant_type: "password",
            };
            response = await this.requestAccessToken(p);
            if (response.result.access_token) {
              response.result.username = username;
              response.result.user_id = userId;
            }
          }
        }
      }
    }
    if (!response) {
      response = this.createResultResponse({ error: "No client found" });
    }
    return response;
  }

  /**
   * Register a ResourceOwner User
   */
  async registerUser(params) {
    const {
      client_id: clientId,
      username,
      email,
      password,
      ...extras
    } = params;
    let app = null;
    if (clientId) {
      app = await this.model.getApplication(clientId);
    }
    let response = {};

    if (!app) {
      return this.createResultResponse({ error: "No client found" });
    }
    let user = null;
    const policies = app.policies || { userNeedEmail: true }; // TODO remove this default policies
    if (
      StringTools.stringIsEmpty(username) ||
      (policies.userNeedEmail && StringTools.stringIsEmpty(email)) ||
      StringTools.stringIsEmpty(password)
    ) {
      if (
        policies.authorizeAnonymous &&
        extras.anonymous_secret === policies.anonymous_secret
      ) {
        const token = this.model.generateAnonymousToken();
        const anonymous = `anonymous-${token}`;
        user = {
          username: anonymous,
          valid_email: false,
          password: policies.anonymous_secret,
          anonymous: true,
          anonymous_token: token,
          anonymous_secret: extras.anonymous_secret,
        };
      } else {
        response = this.createResultResponse({
          error: "Wrong parameters sent",
        });
      }
    } else if (
      ZOAuthServer.validateCredentialsValue(username, email, password, policies)
    ) {
      user = await this.model.getUser(null, username, email);
      if (!user) {
        user = {
          username,
          password,
        };
        if (email) {
          user.email = email;
          user.valid_email = false;
        }
      } else {
        user = null;
        response = this.createResultResponse({
          error: `User exist: ${username}`,
        });
      }
    } else {
      response = this.createResultResponse({
        error: "Wrong parameters sent",
      });
    }
    if (user) {
      user = await this.model.setUser(user);
      if (user) {
        response = this.createResultResponse({
          id: user.id,
          username: user.username,
        });
        if (user.email) {
          response.result.email = user.email;
        }
      } else {
        response = this.createResultResponse({ error: "Can't save user" });
      }
    }
    return response;
  }

  /**
   * Authorize a resourceOwner ($userId) to access Resources using an application ($clientId)
   */
  async authorizeAccess(params) {
    const {
      username,
      password,
      client_id: clientId,
      user_id: userId,
      scope,
      redirect_uri: redirectUri,
      /* ...extras */
    } = params;
    const authentication = {};
    let response = {};
    let app = null;
    let user = null;
    let storedAuth = null;
    // logger.info("params", params);
    if (clientId) {
      app = await this.model.getApplication(clientId);
    }
    // logger.info("authorizeAccess", userId, username, password);
    if (!StringTools.stringIsEmpty(userId)) {
      user = await this.model.getUser(userId);
    } else {
      // authenticate user
      user = await this.model.validateCredentials(username, password);
    }
    if (user && app) {
      authentication.user_id = user.id;
      authentication.client_id = clientId;
      authentication.scope = scope;
      authentication.redirect_uri = this.model.validateRedirectUri(redirectUri);
      // TODO save extra params
      storedAuth = await this.model.setAuthentication(authentication);
      if (storedAuth) {
        response = this.createResultResponse({
          redirect_uri: authentication.redirect_uri,
        });
      } else {
        response = this.createResultResponse({
          error: "Can't authenticate",
        });
      }
    } else if (!app) {
      response = this.createResultResponse({
        error: "No valid client_id",
      });
    } else if (user == null && userId) {
      response = this.createResultResponse({
        error: "No valid user_id",
      });
    } else if (user == null && username && password) {
      response = this.createResultResponse({
        error: "Wrong credentials",
      });
    } else {
      response = this.createResultResponse({
        error: "Not valid",
      });
    }
    return response;
  }

  /**
   * Request an access token
   * Inspired by Offical Doc of OAuth2, resume here :
   * https://docs.google.com/document/d/1yEzRcvOlHXoMmBmV49G4HxAPEmkWuW7CFGo2cuDYdfo/edit?usp=sharing
   */
  async requestAccessToken(params) {
    const {
      grant_type: grantType,
      refresh_token: refreshToken,
      client_id: clientId,
      username,
      password,
      /* redirect_uri: redirectUri, */
      /* ...extras */
    } = params;
    let response = {};
    if (clientId) {
      if (grantType === GRANT_TYPE_PASSWORD) {
        response = await this.requestGrantTypePassword(
          clientId,
          username,
          password,
        );
      } else if (grantType === GRANT_TYPE_REFRESH_TOKEN) {
        response = await this.requestGrantTypeRefreshToken(
          clientId,
          refreshToken,
        );
      } else {
        response = this.createResultResponse({
          error: `Unknown grant type: ${grantType}`,
        });
      }
    } else {
      response = this.createResultResponse({
        error: "Require client_id",
      });
    }
    return response;
  }

  /**
   * requestGrantTypePassword() used in requestAccessToken() for GrantType Password
   *
   * The Password grant type is used to obtain additional access tokens
   * in order to prolong the client’s authorization of a user’s resources.
   *
   * Password Grant require : client_id, client_secret, "redirect_uri", username, password
   */
  async requestGrantTypePassword(clientId, username, password) {
    let response = {};
    let authentication = null;
    let user = null;
    // validate user
    user = await this.model.validateCredentials(username, password);
    if (user) {
      // validate authentication
      authentication = await this.model.getAuthentication(clientId, user.id);
      if (!authentication) {
        response = this.createResultResponse({ error: "Not authentified" });
      }
      // TODO extras, redirectUri
    } else {
      response = this.createResultResponse({ error: "Can't authenticate" });
    }
    if (user && authentication) {
      // generate accessToken
      const { scope } = authentication;
      const session = await this.model.getAccessToken(
        GRANT_TYPE_PASSWORD,
        null,
        clientId,
        user.id,
        scope,
      );
      response.result = {
        access_token: session.access_token,
        expires_in: session.expires_in,
        refresh_token: session.refresh_token,
        scope: session.scope,
      };
    }
    return response;
  }

  /* eslint-disable no-unused-vars */
  /**
   * requestGrantTypeRefreshToken() used in requestAccessToken() for GrantType Refresh Token
   *
   * The Refresh Token grant type is used to obtain a new access token
   * without setting a password.
   *
   * Refresh Token Grant require : client_id, client_secret, refresh_token
   */
  async requestGrantTypeRefreshToken(clientId, refreshToken) {
    let response = {};
    // no need to validate user we have refreshToken
    if (refreshToken) {
      // generate accessToken, scope is stock in refresh
      const session = await this.model.getAccessToken(
        GRANT_TYPE_REFRESH_TOKEN,
        refreshToken,
        clientId,
      );
      if (session.error === undefined) {
        response = this.createResultResponse({
          access_token: session.access_token,
          expires_in: session.expires_in,
          refresh_token: session.refresh_token,
          scope: session.scope,
        });
      } else {
        response = this.createResultResponse({
          error: session.error,
        });
      }
      // TODO extras, redirectUri
    } else {
      response = this.createResultResponse({
        error: "Use GRANT_TYPE_REFRESH_TOKEN without refresh_token",
      });
    }
    return response;
  }

  /* eslint-disable no-unused-vars */
  /* eslint-disable class-methods-use-this */
  /**
   * Register a Scope
   */
  registerScope(params) {
    // TODO
  }

  /**
   * Register a grant type
   */
  registerGrantType(params) {
    // TODO
  }

  async getUser(id) {
    const user = await this.model.getUser(id);
    if (user) {
      delete user.password;
    }
    return user;
  }

  async getAuthsWithScope(scope, clientId) {
    return this.model.queryAuthentications(
      `scope=${scope} AND client_id=${clientId}`,
    );
  }

  async getApplication(id) {
    const app = await this.model.getApplication(id);
    return app;
  }

  async getApplicationByName(name) {
    const app = await this.model.getApplication(`name=${name}`);
    return app;
  }
}

export default (config, database) => new ZOAuthServer(config, database);
