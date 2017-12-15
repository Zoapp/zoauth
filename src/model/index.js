/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import StringTools from "zoapp-core/helpers/stringTools";

import dbCreate from "zoapp-core/database";
import descriptor from "./descriptor";

export class ZOAuthModel {
  constructor(config = {}, database = null) {
    this.database = database;
    if (database == null) {
      // console.log("config=", JSON.stringify(config));
      // console.log("descriptor=", JSON.stringify(descriptor));
      this.database = dbCreate({ descriptor, ...config });
    }
    this.config = config;
    this.tokenExpiration = this.config.tokenExpiration || 3600;
  }

  async open() {
    await this.database.load();
  }

  async close() {
    await this.database.close();
  }

  async reset() {
    await this.database.reset();
  }

  getFilename() {
    return this.database.getName();
  }

  generateAnonymousToken() {
    return this.database.generateToken(6);
  }

  generateAccessToken() {
    return this.database.generateToken(48);
  }

  generateId() {
    return this.database.generateToken(32);
  }

  generateClientId() {
    return this.database.generateToken(64);
  }

  getApplications() {
    const apps = this.database.getTable("applications");
    return apps;
  }

  getUsers() {
    return this.database.getTable("users");
  }

  getAuthentications() {
    return this.database.getTable("authentications");
  }

  getSessions() {
    return this.database.getTable("sessions");
  }

  async setApplication(application, applications = this.getApplications()) {
    const app = { ...application };
    let localApp = {};
    let clientId = app.id;
    if (!clientId) {
      // generate client_id
      let cid = this.generateClientId();
      // In case the client_id already exist
      localApp = await this.getApplication(cid);
      /* eslint-disable no-await-in-loop*/
      while (localApp) {
        cid = this.generateClientId();
        localApp = await this.getApplication(cid);
      }
      /* eslint-enable no-await-in-loop*/
      localApp = {};
      app.id = cid;
      app.creation_date = Date.now();
    } else {
      clientId = app.id;
      localApp = await this.getApplication(clientId);
      // TODO compare localapp/application values
    }
    if (!app.secret && !localApp.secret) {
      // generate client_secret
      app.secret = this.generateClientId();
    }
    await applications.setItem(clientId, app);
    this.database.flush();
    return app;
  }

  async getApplication(
    appId,
    appSecret = null,
    applications = this.getApplications(),
  ) {
    let application = null;
    if (appId) {
      application = await applications.getItem(appId);
      if (!(
        application &&
        (StringTools.stringIsEmpty(appSecret) || application.secret === appSecret))
      ) {
        application = null;
      }
    }

    return application;
  }

  async getApplicationByName(appName, applications = this.getApplications()) {
    let app = null;
    await applications.nextItem((a) => {
      if (a && a.name === appName) {
        app = a;
        return true;
      }
      return false;
    });
    return app;
  }

  async setUser(user, users = this.getUsers()) {
    const u = { ...user };
    const { username, email } = user;
    // const password = user.password;

    let cachedUser = await this.getUser(username, email, users);
    let userId = null;
    if (!user.id) {
      // generate user_id
      u.id = this.generateId();
      u.creation_date = Date.now();
      // check if username/email are valid and not already used
      if (cachedUser) {
        throw new Error("username / email are already used");
      }
      cachedUser = u;
    } else if (cachedUser) {
      userId = user.id;
    } else {
      throw new Error("unknown user");
    }
    Object.keys(u).forEach((key) => {
      const value = u[key];
      if (key === "password") {
        // TODO check password complexity
        // TODO hash password
        cachedUser.password = StringTools.hashPassword(value);
      } else {
        cachedUser[key] = value;
      }
    });
    // console.log("cachedUser=" + cachedUser.id);
    await users.setItem(userId, cachedUser);
    this.database.flush();

    // Remove password to return user
    delete cachedUser.password;

    return cachedUser;
  }

  async getUser(id, username, email, users = this.getUsers()) {
    let user = null;
    if (id) {
      user = await users.getItem(id);
    } else if (username != null || email != null) {
      await users.nextItem((u) => {
        let match = false;
        let e = u.email;
        if (email && StringTools.strcasecmp(e, email) === 0) {
          match = true;
        } else {
          e = u.username;
          if (username && StringTools.strcasecmp(e, username) === 0) {
            match = true;
          }
        }
        if (match) {
          user = u;
          return true;
        }
        return false;
      });
    }

    if (user && user.id) {
      return user;
    }
    return null;
  }

  async getUserByNameOrEmail(login, users = this.getUsers()) {
    let user = null;
    if (!StringTools.stringIsEmpty(login)) {
      await users.nextItem((u) => {
        // console.log("getUserByNameOrEmail nexItem", u.email);
        const e = u.email;
        const n = u.username;
        if (
          StringTools.strcasecmp(n, login) === 0 ||
          StringTools.strcasecmp(e, login) === 0
        ) {
          // console.log("getUserByNameOrEmail found", u.email);
          user = u;
          return true;
        }
        return false;
      });
    }
    return user;
  }

  async validateCredentials(login, password) {
    let user = null;
    if (!StringTools.stringIsEmpty(password)) {
      user = await this.getUserByNameOrEmail(login);
      // console.log("validateCredentials found", user);
      if (user) {
        // const pw = StringTools.hashPassword(password);
        // console.log("validateCredentials found", user.password, pw);
        if (
          password !== user.password &&
          StringTools.hashPassword(password) !== user.password
        ) {
          // console.log("validateCredentials not ok");
          user = null;
        }
      }
    }
    return user;
  }

  async setAuthentication(
    authentication,
    authentications = this.getAuthentications(),
  ) {
    let auth = null;
    // console.log("set Authen", authentication);
    if (authentication && authentication.client_id && authentication.user_id) {
      const clientId = authentication.client_id;
      const userId = authentication.user_id;
      const localAuth = await this.getAuthentication(
        clientId,
        userId,
        authentications,
      );
      let id = null;
      auth = { ...authentication };
      if (localAuth) {
        // TODO mix with previous stored authentication
        id = localAuth.id;
        if (!auth.scope) {
          auth.scope = localAuth.scope;
        }
      } else {
        auth.id = `${clientId}-${userId}`;
        auth.scope = this.validateScope(authentication.scope);
      }
      // console.log("setAuthentification", auth);
      await authentications.setItem(id, auth);
      this.database.flush();
    }
    return auth;
  }

  async getAuthentication(
    clientId,
    userId,
    authentications = this.getAuthentications(),
  ) {
    if (clientId && userId) {
      const id = `${clientId}-${userId}`;
      const auth = await authentications.getItem(id);
      return auth;
    }
    return null;
  }

  async queryAuthentications(query, authentications = this.getAuthentications()) {
    return authentications.getItem(query);
  }

  async getAccessToken(
    clientId,
    userId,
    scope,
    expiration = this.tokenExpiration,
    sessions = this.getSessions(),
  ) {
    let accessToken = null;
    if (clientId && userId) {
      const time = Date.now();
      let id = `${clientId}-${userId}`;
      accessToken = await sessions.getItem(id);
      if (!accessToken) {
        accessToken = {
          access_token: this.generateAccessToken(),
          expires_in: expiration,
          scope,
          client_id: clientId,
          user_id: userId,
          id,
          created: time,
        };
        id = null;
      } else {
        accessToken.last = time;
        // TODO handle token expiration
        if (scope) {
          accessToken.scope = scope;
        }
      }
      await sessions.setItem(id, accessToken);
      // this.database.flush();
    }
    return accessToken;
  }

  async validateAccessToken(accessToken, sessions = this.getSessions()) {
    let access = null;
    if (accessToken) {
      await sessions.nextItem((a) => {
        if (a.access_token === accessToken) {
          access = a;
          return true;
        }
        return false;
      });
    }
    return access;
  }

  /* eslint-disable no-unused-vars */
  /* eslint-disable class-methods-use-this */
  validateScope(scope) {
    // TODO test if scope is existing
    let s = scope;
    if (StringTools.stringIsEmpty(scope)) {
      s = "default";
    }
    return s;
  }

  setScope(scope) {
    // TODO
    return null;
  }

  getScope(scopeName) {
    // TODO
    return null;
  }

  validateRedirectUri(redirectUri) {
    let ru = redirectUri;
    if (StringTools.stringIsEmpty(ru)) {
      ru = "localhost";
    }
    return ru;
  }
}

export default (config, database) => new ZOAuthModel(config, database);
