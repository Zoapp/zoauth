/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { StringTools, dbCreate } from "zoapp-core";
import descriptor from "./descriptor";

const GRANT_TYPE_PASSWORD = "password";
const GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

export class ZOAuthModel {
  constructor(config = {}, database = null) {
    this.database = database;
    if (database == null) {
      // logger.info("config=", JSON.stringify(config));
      // logger.info("descriptor=", JSON.stringify(descriptor));
      this.database = dbCreate({ descriptor, ...config });
    }
    this.config = config;
    this.tokenExpiration = this.config.tokenExpiration || 3600;
    this.refreshTokenExpiration = this.config.refreshTokenExpiration || 86400;
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

  generateRefreshToken() {
    return this.database.generateToken(32);
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
      /* eslint-disable no-await-in-loop */
      while (localApp) {
        cid = this.generateClientId();
        localApp = await this.getApplication(cid);
      }
      /* eslint-enable no-await-in-loop */
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
      if (
        !(
          application &&
          (StringTools.stringIsEmpty(appSecret) ||
            application.secret === appSecret)
        )
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
      if (key === "password" && value) {
        // TODO check password complexity
        // TODO hash password
        cachedUser.password = StringTools.hashPassword(value);
      } else if (value) {
        cachedUser[key] = value;
      }
    });
    // logger.info("cachedUser=" + cachedUser.id);
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
        // logger.info("getUserByNameOrEmail nexItem", u.email);
        const e = u.email;
        const n = u.username;
        if (
          StringTools.strcasecmp(n, login) === 0 ||
          StringTools.strcasecmp(e, login) === 0
        ) {
          // logger.info("getUserByNameOrEmail found", u.email);
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
      // logger.info("validateCredentials found", user);
      if (user) {
        // const pw = StringTools.hashPassword(password);
        // logger.info("validateCredentials found", user.password, pw);
        if (
          password !== user.password &&
          StringTools.hashPassword(password) !== user.password
        ) {
          // logger.info("validateCredentials not ok");
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
    // logger.info("set Authen", authentication);
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
        ({ id } = localAuth);
        if (!auth.scope) {
          auth.scope = localAuth.scope;
        }
      } else {
        auth.id = `${clientId}-${userId}`;
        auth.scope = this.validateScope(authentication.scope);
      }
      // logger.info("setAuthentification", auth);
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

  async queryAuthentications(
    query,
    authentications = this.getAuthentications(),
  ) {
    return authentications.getItem(query);
  }

  async getAccessToken(
    clientId,
    userId,
    scope,
    grantType = GRANT_TYPE_PASSWORD, // by defaut, other grant type are not supported for moment
    expiration = this.tokenExpiration,
    sessions = this.getSessions(),
  ) {
    let actualSession = null;
    let refreshToken = null;
    const time = Date.now();
    if (grantType === GRANT_TYPE_PASSWORD) {
      // GRANT_TYPE_PASSWORD we can get session by his ID
      if (clientId && userId) {
        let id = `${clientId}-${userId}`;
        actualSession = await sessions.getItem(id);
        if (!actualSession) {
          refreshToken = await this.getRefreshToken();
          actualSession = {
            access_token: this.generateAccessToken(),
            expires_in: expiration,
            scope,
            client_id: clientId,
            user_id: userId,
            id,
            access_created: time,
            created: time,
            refresh_token: refreshToken.refresh_token,
            refresh_expires_in: refreshToken.refresh_expires_in,
            refresh_created: refreshToken.refresh_created,
          };
          id = null;
        } else {
          actualSession.last = time;
          // TODO handle token expiration
          if (scope) {
            actualSession.scope = scope;
          }
        }
        await sessions.setItem(id, actualSession);
        // this.database.flush();
      } else {
        // Error Response
      }
    } else if (grantType === GRANT_TYPE_REFRESH_TOKEN) {
      // We can get session with the refresh_token
      let updatedSession = {};
      actualSession = await sessions.getItem(refreshToken);
      if (actualSession) {
        refreshToken = await this.getRefreshToken();
        updatedSession = {
          access_token: this.generateAccessToken(),
          expires_in: expiration,
          access_created: time,
          refresh_token: refreshToken.refresh_token,
          refresh_expires_in: refreshToken.refresh_expires_in,
          refresh_created: refreshToken.refresh_created,
        };
        await sessions.setItem(actualSession.id, updatedSession);
        // this.database.flush();
      } else {
        // Error Response
      }
    } else {
      actualSession = { error: "Request Failed" };
    }
    return actualSession;
  }

  async getRefreshToken(expiration = this.refreshTokenExpiration) {
    const time = Date.now();
    const refreshToken = {
      refresh_token: this.generateRefreshToken(),
      refresh_expires_in: expiration,
      refresh_created: time,
    };
    return refreshToken;
  }

  async validateAccessToken(accessToken, sessions = this.getSessions()) {
    let access = null;
    if (accessToken) {
      await sessions.nextItem((a) => {
        if (a.access_token === accessToken) {
          const expirationDate = a.access_created + a.expires_in * 1000;
          if (expirationDate > new Date().getTime()) {
            access = a;
            return true;
          }
        }
        return false;
      });
    }
    return access;
  }

  async validateRefreshToken(refreshToken, sessions = this.getSessions()) {
    let refresh = null;
    if (refreshToken) {
      await sessions.nextItem((a) => {
        if (a.refresh_token === refreshToken) {
          const expirationDate = a.created + a.refresh_expires_in * 1000;
          if (expirationDate > new Date().getTime()) {
            refresh = a;
            return true;
          }
        }
        return false;
      });
    }
    return refresh;
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
