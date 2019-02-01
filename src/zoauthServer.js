/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { StringTools, Password } from "zoapp-core";
import createModel from "./model";
import Route from "./model/route";
import ValidationError from "./errors/ValidationError";

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
   * Create pre anonymous user
   */
  createPreAnonymous(policies, anonymousSecret) {
    if (
      !policies.authorizeAnonymous ||
      anonymousSecret !== policies.anonymous_secret
    ) {
      throw new Error("Wrong parameters sent.");
    }

    const token = this.model.generateAnonymousToken();
    const anonymous = `anonymous-${token}`;
    return {
      username: anonymous,
      valid_email: false,
      password: policies.anonymous_secret,
      anonymous: true,
      anonymous_token: token,
      anonymous_secret: anonymousSecret,
      account_state: "enable",
    };
  }

  /**
   * Create pre user
   */
  async createPreUser(
    accept,
    username,
    email,
    password,
    validationPolicy,
    scope = null,
  ) {
    const policy = scope === "admin" ? "none" : validationPolicy;
    const validation = policy === "none";
    if (!accept) {
      throw new Error("Please accept policies's terms.");
    }

    let user = await this.model.getUser(null, username, email);
    if (user) {
      // User already exist
      throw new Error(`Not valid user: ${username}.`);
    }

    user = {
      username,
      password,
      account_state: validation ? "enable" : "pending_validation",
    };
    if (email) {
      user.email = email;
      user.valid_email = validation;
    }
    return user;
  }

  /**
   * Register a ResourceOwner User
   */
  async registerUser(params, accessToken) {
    const {
      client_id: clientId,
      username,
      email,
      password,
      ...extras
    } = params;
    try {
      const app = await this.model.getApplication(clientId);
      if (!app) {
        throw new Error("No client found.");
      }

      // get scope from authenticated user for unauthorized not admin user
      let scope;
      if (accessToken) {
        ({ scope } = await this.model.validateAccessToken(accessToken));
        if (scope !== "admin") {
          throw new Error("Unauthorized.");
        }
      }

      let user = null;
      const policies = app.policies || { userNeedEmail: true }; // TODO remove this default policies
      const validationPolicy =
        scope === "admin" || !policies.validation
          ? "none"
          : policies.validation;

      if (
        StringTools.stringIsEmpty(username) ||
        (policies.userNeedEmail && StringTools.stringIsEmpty(email)) ||
        StringTools.stringIsEmpty(password)
      ) {
        // Anonymous
        user = this.createPreAnonymous(policies, extras.anonymous_secret);
      } else if (
        ZOAuthServer.validateCredentialsValue(
          username,
          email,
          password,
          policies,
        )
      ) {
        // User
        user = await this.createPreUser(
          extras.accept,
          username,
          email,
          password,
          validationPolicy,
          scope,
        );
      } else {
        throw new Error("Wrong parameters sent.");
      }

      user = await this.model.setUser(user);
      if (!user) {
        // Fail on user store
        throw new Error("Can't save user.");
      }
      const result = {
        id: user.id,
        username: user.username,
        validation: validationPolicy,
      };
      if (user.email) {
        result.email = user.email;
        if (this.middleware && this.middleware.sendUserCreated) {
          let activationMailToken;
          if (validationPolicy === "mail") {
            // Generate token to create mail activation link
            activationMailToken = await this.model.getAccessToken(
              clientId,
              user.id,
              "owner",
              86400,
            );
          }
          await this.middleware.sendUserCreated(
            email,
            username,
            validationPolicy,
            activationMailToken,
          );
        }
      }

      return { result };
    } catch (error) {
      return { result: { error: error.message } };
    }
  }

  /**
   * Validate if account is enable
   */
  static isAccountEnable(user, app, prefix = "Can't authenticate.") {
    let error;
    if (user.account_state === "pending_validation") {
      const policies = app.policies || {};
      const validationPolicy = policies.validation || "none";
      switch (validationPolicy) {
        case "none":
          break;
        case "admin":
          error = `${prefix} Please call your administrator to activate your account.`;
          break;
        case "mail":
          error = `${prefix} Please see your mail to activate your account.`;
          break;
        default:
          error = `${prefix} Unknow validation policy.`;
          break;
      }
    } else if (user.account_state === "disable") {
      error = `${prefix} Your account is disable. Please call your administrator to investigate.`;
    }
    if (error) {
      throw new ValidationError(error);
    }
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
    try {
      const app = await this.model.getApplication(clientId);
      if (!app) {
        throw new Error("No client found.");
      }

      let user = null;
      if (!StringTools.stringIsEmpty(userId)) {
        user = await this.model.getUser(userId);
      } else {
        // authenticate user
        user = await this.model.validateCredentials(username, password);
      }

      if (!user) {
        if (userId) {
          throw new Error("No valid user_id.");
        }

        if (username && password) {
          throw new Error("Wrong credentials.");
        }

        throw new Error("Not valid.");
      }

      ZOAuthServer.isAccountEnable(user, app, "Can't authorize.");

      // Account enable
      const authentication = {};
      authentication.user_id = user.id;
      authentication.client_id = clientId;
      authentication.scope = scope;
      authentication.redirect_uri = this.model.validateRedirectUri(redirectUri);
      // TODO save extra params
      let storedAuth = null;
      storedAuth = await this.model.setAuthentication(authentication);
      if (!storedAuth) {
        throw new Error("Can't authorize.");
      }
      return { result: { redirect_uri: authentication.redirect_uri } };
    } catch (error) {
      if (error instanceof ValidationError) {
        return { result: { error: error.toJson() } };
      }
      return { result: { error: error.message } };
    }
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
    try {
      const app = await this.model.getApplication(clientId);
      if (!app) {
        throw new Error("No client found.");
      }

      // Only grantType = password for now
      if (grantType !== "password") {
        throw new Error(`Unknown grant type: ${grantType}.`);
      }

      // validate user
      const user = await this.model.validateCredentials(username, password);
      if (!user) {
        throw new Error("Can't authenticate.");
      }

      // Validate account state
      ZOAuthServer.isAccountEnable(user, app);

      // validate authentication
      const authentication = await this.model.getAuthentication(
        clientId,
        user.id,
      );
      if (!authentication) {
        throw new Error("Not authentified.");
      }

      // TODO extras, redirectUri
      // generate accessToken
      const { scope } = authentication;
      const accessToken = await this.model.getAccessToken(
        clientId,
        user.id,
        scope,
      );
      return {
        result: {
          access_token: accessToken.access_token,
          expires_in: accessToken.expires_in,
          scope: accessToken.scope,
        },
      };
    } catch (error) {
      if (error instanceof ValidationError) {
        return { result: { error: error.toJson() } };
      }
      return { result: { error: error.message } };
    }
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

  async validateUserFromAdmin(
    { userId, newState, client_id: clientId, redirect_uri: redirectUri },
    accessToken,
  ) {
    try {
      const access = await this.model.validateAccessToken(accessToken);
      if (access.scope !== "admin") {
        throw new Error("Unauthorized.");
      }

      let user = await this.model.getUser(userId);
      if (!user) {
        throw new Error("No valid user found.");
      }

      if (newState !== "enable" && newState !== "disable") {
        throw new Error(`Invalide state type ${newState}.`);
      }

      user = {
        id: user.id,
        account_state: newState,
      };
      user = await this.model.setUser(user);
      if (!user) {
        throw new Error("User store faillure.");
      }

      if (newState === "enable") {
        // Create authentacation row
        const response = await this.authorizeAccess({
          username: user.username,
          password: user.password,
          client_id: clientId,
          user_id: user.id,
          scope: "owner",
          redirect_uri: redirectUri,
        });
        if (response.result.error) {
          throw new Error(response.result.error);
        }
        await this.middleware.sendAccountEnable(user.email, user.username);
      } else {
        // Delete authentacation row
        const authentacation = await this.model.getAuthentication(
          clientId,
          user.id,
        );
        if (authentacation) {
          await this.model.deleteAuthentication(authentacation.id);
        }
      }

      return user;
    } catch (error) {
      return { result: { error: error.message } };
    }
  }

  async validateUserFromMail({
    username,
    email,
    client_id: clientId,
    validation_token: validationToken,
  }) {
    let app;
    try {
      app = await this.model.getApplication(clientId);
      if (!app) {
        throw new Error("No client found.");
      }

      const access = await this.model.validateAccessToken(validationToken);
      // Token is out of date
      if (!access) {
        throw new Error("Invalid token.");
      }

      // Get user from credentials
      let user = await this.model.getUser(null, username, email);
      if (!user) {
        throw new Error("Invalid credentials.");
      }

      // Token is the right one for user credentials
      if (access.user_id !== user.id) {
        throw new Error("Invalid token");
      }

      user = {
        id: user.id,
        account_state: "enable",
      };
      user = await this.model.setUser(user);
      if (!user) {
        throw new Error("User store faillure.");
      }

      // Create authentacation row
      const response = await this.authorizeAccess({
        username: user.username,
        password: user.password,
        client_id: clientId,
        user_id: user.id,
        scope: "owner",
      });
      if (response.result.error) {
        throw new Error(response.result.error);
      }
      return {
        result: {
          redirectUri: app.redirect_uri,
          info:
            "Validation account successful. Please sign in to enjoy your chatbot builder.",
        },
      };
    } catch (error) {
      const result = { error: error.message };
      if (app) {
        result.redirectUri = app.redirect_uri;
      }
      return { result };
    }
  }
}

export default (config, database) => new ZOAuthServer(config, database);
