/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { Router } from "express"; // Import the Router From Express
import RouteContext from "./routeContext";

/**
 * @module Auth_Router
 */


/**
 * "send" : It's a function used to send a Response.
 *
 * @memberof module:Auth_Router
 *
 * @param {*} res The Response Object.
 * @param {*} payload The Payload Parameter.
 * @param {*} status The status of Response
 * @param {*} cors Required for the Cross-Origin.
 */
const send = (res, payload, status = 200, cors = "*") => {
  // Construct the body.
  const json = JSON.stringify(payload, (key, value) => {
    if (!value) {
      return undefined;
    }
    return value;
  }, 0);

  // Build Header.
  res.charset = "utf-8";
  res.set("Content-Type", "application/json");
  res.set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, access_token, client_id, client_secret");
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Origin", cors || "*");
  res.status(status);
  res.send(json);
};

/**
 * Use "getAccessTokenFromRequest" to get the accesstoken include in the Request.
 *
 * @memberof module:Auth_Router
 *
 * @param {*} req The Resquest Object.
 *
 * @returns {*} Return the accessToken.
 */
const getAccessTokenFromRequest = (req) => {
  let accessToken = req.get("access_token");
  if (!accessToken) {
    accessToken = req.query.access_token;
  }
  // TODO validate accessToken
  return accessToken;
};

/**
 * Use "getAppCredentialsFromRequest" on the Request to get all Credentials
 *
 * @memberof module:Auth_Router
 *
 * @param {*} req The Resquest Object.
 *
 * @returns {object} The Client ID
 * @returns {object} The Client Secret
 */
const getAppCredentialsFromRequest = (req) => {
  let id = req.get("client_id");
  if (!id) {
    id = req.query.client_id;
  }
  let secret = req.get("client_secret");
  if (!secret) {
    secret = req.query.client_secret;
  }
  // TODO validate id, secret
  return { id, secret };
};

/**
 * @class
 * @memberof module:Auth_Router
 * @alias ZOAuthRoute
 * @classdesc "ZOAuthRoute" is used to create route.
 */
class ZOAuthRoute {
  /**
   * The constructor Init four parameters.
   * @constructor
   * @param {*} root The root init
   * @param {*} path The route Path
   * @param {*} authCallback CallBack
   * @param {*} description The route description
   */
  constructor(root, path, authCallback, description) {
    this.root = root;
    this.rootPath = path;
    this.authCallback = authCallback;
    this.description = description;
  }

  /**
   * The function "add()" is used to add a route.
   *
   * @memberof ZOAuthRoute
   *
   * @param {*} method
   * @param {*} path
   * @param {*} scopes
   * @param {*} callback
   * @param {*} authCallback
   */
  add(method, path, scopes, callback, authCallback = null) {
    const { root } = this;
    const authCb = authCallback || this.authCallback;
    const p = this.rootPath ? this.rootPath + path : path;
    root.authServer.addRoute(p, scopes, method);
    // TODO API call limits
    root.methods[method].call(
      p,
      (req, res, next) => {
        root.authMiddleware(req, res, next, authCb);
      },
      async (req, res) => {
        let payload = null;
        let status = 200;
        try {
          payload = await callback(res.locals.context);
          // TODO call logging
        } catch (error) {
          // TODO error logging
          payload = { error: error.message, stack: error.stack, code: error.code };
          status = 500;
        }
        send(res, payload, status, res.locals.access.cors);
      },
    );
  }
}

/**
 * @class
 * @memberof module:Auth_Router
 * @alias ZOAuthRouter
 * @classdesc "ZOAuthRouter" give some functions to work on route.
 */
export default class ZOAuthRouter {
  /**
   * Get the authServer and init him.
   * @param {*} authServer
   */
  constructor(authServer) {
    this.authServer = authServer;
    this.router = Router();
    this.methods = {
      POST: { call: this.router.post.bind(this.router) },
      GET: { call: this.router.get.bind(this.router) },
      DELETE: { call: this.router.delete.bind(this.router) },
      PUT: { call: this.router.put.bind(this.router) },
      ANY: { call: this.router.all.bind(this.router) },
    };
  }

  /**
   * The function "authMiddleware" is used to manage auth security.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} req The Request Object
   * @param {*} res The Response Object
   * @param {*} next The next route.
   * @param {*} callback The callback of route.
   */
  authMiddleware(req, res, next, callback = null) {
    const token = getAccessTokenFromRequest(req);
    const appCredentials = getAppCredentialsFromRequest(req);
    const { method } = req;
    const routeName = req.route.path;
    this.authServer.grantAccess(routeName, method, token, appCredentials).then((access) => {
      let n = false;
      let context = null;
      let { result } = access;
      if (!result.error) {
        context = new RouteContext(req, res);
        n = true;
        if (callback) {
          result = callback(context);
          if (result.error) {
            n = false;
          } else {
            context.access = access.result;
          }
        }
      }

      const status = n ? 200 : 401;
      if (n) {
        res.locals.access = access.result;
        res.locals.context = context;
        next();
      } else {
        send(res, result, status, access.cors);
        next("route");
      }
    });
  }

  /**
   * Used to created a route.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} path The path.
   * @param {*} authCallback The callback use for auth.
   * @param {*} description Description of the route.
   */
  createRoute(path = null, authCallback = null, description = null) {
    return new ZOAuthRoute(this, path, authCallback, description);
  }

  /**
   * Used to add a new route.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} method The method use in this route (Ex: POST)
   * @param {*} path The Path
   * @param {*} scopes The Scope
   * @param {*} callback The callback of route.
   * @param {*} authCallback The authCallback of route.
   */
  addRoute(method, path, scopes, callback, authCallback) {
    const route = this.createRoute();
    route.add(method, path, scopes, callback, authCallback);
    return route;
  }

  /**
   * Used to add a new route with method GET.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} path The Path
   * @param {*} scopes The Scope
   * @param {*} callback The callback of route.
   * @param {*} authCallback The authCallback of route.
   */
  get(path, scopes, callback, authCallback = null) {
    return this.addRoute("GET", path, scopes, callback, authCallback);
  }

  /**
   * Used to add a new route with method POST.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} path The Path
   * @param {*} scopes The Scope
   * @param {*} callback The callback of route.
   * @param {*} authCallback The authCallback of route.
   */
  post(path, scopes, callback, authCallback = null) {
    return this.addRoute("POST", path, scopes, callback, authCallback);
  }

  /**
   * Used to add a new route with method DELETE.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} path The Path
   * @param {*} scopes The Scope
   * @param {*} callback The callback of route.
   * @param {*} authCallback The authCallback of route.
   */
  delete(path, scopes, callback, authCallback = null) {
    return this.addRoute("DELETE", path, scopes, callback, authCallback);
  }

  /**
   * Used to add a new route with method PUT.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} path The Path
   * @param {*} scopes The Scope
   * @param {*} callback The callback of route.
   * @param {*} authCallback The authCallback of route.
   */
  put(path, scopes, callback, authCallback = null) {
    return this.addRoute("PUT", path, scopes, callback, authCallback);
  }

  /**
   * Used to add a new route with method ANY.
   *
   * @memberof ZOAuthRouter
   *
   * @param {*} path The Path
   * @param {*} scopes The Scope
   * @param {*} callback The callback of route.
   * @param {*} authCallback The authCallback of route.
   */
  any(path, scopes, callback, authCallback = null) {
    return this.addRoute("ANY", path, scopes, callback, authCallback);
  }

  /**
   * Use "expressRouter" to get the Router.
   *
   * @memberof ZOAuthRouter
   */
  expressRouter() {
    return this.router;
  }
}
