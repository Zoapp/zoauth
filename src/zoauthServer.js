/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { StringTools, Password } from "zoapp-core";
import createModel from "./model";
import Route from "./model/route";

export class ZOAuthServer {
  /* static ErrorsMessages = {
    CANT_REGISTER: "Can't register this application name",
    WRONG_EMAIL: "Wrong email sent",
    WRONG_NAME: "Wrong name sent",
    CANT_SAVE_APP: "Can't save application",
  }; */

  constructor(config = {}, database = null, middleware = null) {
    this.config = { ...config };
    this.model = createModel(this.config.database, database);
    this.permissionRoutes = [];
    this.middleware = middleware;
  }

  static errorMessages() {}

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
    const response = {};
    const route = this.findRoute(routeName, method);
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
              scope,
              user_id,
            } = access;
            response.result = {
              access_token,
              client_id,
              expires_in,
              scope,
              user_id,
            };
            /* eslint-enable camelcase */
          } else {
            response.result = { error: "Not allowed", status: 403 };
          }
        } else {
          response.result = { error: "Not valid user account", status: 401 };
        }
      } else {
        response.result = { error: "Not valid access token", status: 401 };
      }
    } else if (route && route.isOpen()) {
      response.result = { access: "open" };
    } else if (
      route &&
      route.isScopeValid("application") &&
      (await this.validateApplicationCredentials(appCredentials))
    ) {
      response.result = {
        client_id: appCredentials.id,
        scope: "application",
      };
    } else {
      response.result = { error: "No permission route" };
    }
    return response;
  }

  async changePassword(params) {
    const { client_id: clientId, email, password } = params;
    let response = null;
    if (clientId) {
      const app = await this.model.getApplication(clientId);
      const user = await this.model.getUser(null, null, email);
      if (user && ZOAuthServer.validatePassword({ password })) {
        const policies = (app && app.policies) || {};
        if (
          policies.resetPassword &&
          this.middleware &&
          this.middleware.sendChangedPassword
        ) {
          user.password = password;
          // TODO backup previous password
          await this.model.setUser(user);
          if (this.middleware.sendChangedPassword(email)) {
            response.result = { ok: "Password changed" };
          }
        }
      }
    }
    if (!response) {
      response = { error: "Not valid action" };
    }
    return response;
  }

  async resetPassword(params) {
    const { client_id: clientId, email } = params;
    let response = null;
    if (clientId) {
      const app = await this.model.getApplication(clientId);
      const user = await this.model.getUser(null, null, email);
      if (user) {
        const policies = (app && app.policies) || {};
        if (
          policies.resetPassword &&
          this.middleware &&
          this.middleware.sendResetPassword
        ) {
          if (this.middleware.sendResetPassword(email)) {
            response.result = { ok: "Email send" };
          }
        }
      }
    }
    if (!response) {
      response = { error: "Not valid action" };
    }
    return response;
  }

  static validatePassword(params) {
    const { password } = params;
    const response = {};
    const strength = Password.strength(password);
    if (strength > 0) {
      const hash = Password.generateSaltHash(password);
      response.result = { hash, strength };
    } else {
      response.result = { error: "Empty password" };
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
    const response = {};
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
        response.result = { error: "Can't register this application name" };
      }
    } else if (wrongEmail) {
      response.result = { error: "Wrong email sent" };
    } else {
      response.result = { error: "Wrong name sent" };
    }

    if (app) {
      app = await this.model.setApplication(app);
      // logger.info("app=", app);
      if (app) {
        response.result = { client_id: app.id, client_secret: app.secret };
      } else {
        response.result = { error: "Can't save application" };
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
      response = { error: "No client found" };
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
    const response = {};

    if (!app) {
      return { error: "No client found" };
    }
    let user = null;
    const policies = app.policies || { userNeedEmail: true }; // TODO remove this default policies
    const validationPolicy = policies.validation || "none";
    const validation = !!(validationPolicy === "none");

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
        response.result = { error: "Wrong parameters sent" };
      }
    } else if (
      ZOAuthServer.validateCredentialsValue(username, email, password, policies)
    ) {
      if (!extras.accept) {
        response.result = { error: "Please accept policies's terms" };
        return response;
      }
      user = await this.model.getUser(null, username, email);
      if (!user) {
        user = {
          username,
          password,
        };
        if (email) {
          user.email = email;
          user.valid_email = validation;
          if (this.middleware && this.middleware.sendUserCreated) {
            this.middleware.sendUserCreated(email, username, validationPolicy);
          }
        }
      } else {
        user = null;
        response.result = { error: `Not valid user: ${username}` };
      }
    } else {
      response.result = { error: "Wrong parameters sent" };
    }
    if (user) {
      user = await this.model.setUser(user);
      if (user) {
        response.result = {
          id: user.id,
          username: user.username,
          validation: validationPolicy,
        };
        if (user.email) {
          response.result.email = user.email;
        }
      } else {
        response.result = { error: "Can't save user" };
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
    const response = {};
    const authentication = {};
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
        response.result = { redirect_uri: authentication.redirect_uri };
      } else {
        response.result = { error: "Can't authenticate" };
      }
    } else if (!app) {
      response.result = { error: "No valid client_id" };
    } else if (user == null && userId) {
      response.result = { error: "No valid user_id" };
    } else if (user == null && username && password) {
      response.result = { error: "Wrong credentials" };
    } else {
      response.result = { error: "Not valid" };
    }
    return response;
  }

  /**
   * Request an access token
   */
  async requestAccessToken(params) {
    const {
      username,
      password,
      grant_type: grantType,
      /* redirect_uri: redirectUri, */
      client_id: clientId,
      /* ...extras */
    } = params;
    const response = {};
    let authentication = null;
    let user = null;
    // Only grantType = password for now
    if (grantType === "password") {
      // validate user
      user = await this.model.validateCredentials(username, password);
      if (user) {
        // validate authentication
        authentication = await this.model.getAuthentication(clientId, user.id);
        if (!authentication) {
          response.result = { error: "Not authentified", status: 400 };
        }
        // TODO extras, redirectUri
      } else {
        response.result = { error: "Can't authenticate", status: 400 };
      }
    } else {
      response.result = { error: `Unknown grant type: ${grantType}` };
    }

    if (user && authentication) {
      // generate accessToken
      const { scope } = authentication;
      const accessToken = await this.model.getAccessToken(
        clientId,
        user.id,
        scope,
      );
      response.result = {
        access_token: accessToken.access_token,
        expires_in: accessToken.expires_in,
        scope: accessToken.scope,
      };
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

  async getUsers(anonymous = false) {
    return this.model.retrieveUsers(anonymous);
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
