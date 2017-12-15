/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { Router } from "express";
import RouteContext from "./routeContext";

/* const setHeaders = (res, status, cors) => {
  this.res.charset = "utf-8";
  res.set("Content-Type", "application/json");
  res.set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type,
  access_token, client_id, client_secret");
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Origin", cors || "*");
  res.status(status);
}; */

const send = (res, payload, status = 200, cors = "*") => {
  const json = JSON.stringify(payload, (key, value) => {
    if (!value) {
      return undefined;
    }
    return value;
  }, 0);

  res.charset = "utf-8";
  res.set("Content-Type", "application/json");
  res.set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, access_token, client_id, client_secret");
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Origin", cors || "*");
  res.status(status);

  /* this.res.charset = "utf-8";
  this.res.set("Content-Type", "application/json");
  this.res.setHeader("Access-Control-Allow-Origin", "*"); // TODO
  this.res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
  this.res.setHeader("Access-Control-Allow-Headers", "X-Requested-With,content-type,access_token,
  client_id,client_secret"); */
  res.send(json);
};

const getAccessTokenFromRequest = (req) => {
  let accessToken = req.get("access_token");
  if (!accessToken) {
    accessToken = req.query.access_token;
  }
  return accessToken;
};

class ZOAuthRoute {
  constructor(root, path, authCallback, description) {
    this.root = root;
    this.rootPath = path;
    this.authCallback = authCallback;
    this.description = description;
  }

  add(method, path, scopes, callback, authCallback = null) {
    const root = this.root;
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
          payload = { error: error.message };
          status = 500;
        }
        send(res, payload, status, res.locals.access.cors);
      },
    );
  }
}

export default class ZOAuthRouter {

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

  authMiddleware(req, res, next, callback = null) {
    const token = getAccessTokenFromRequest(req);
    const method = req.method;
    const routeName = req.route.path;
    this.authServer.grantAccess(routeName, method, token).then((access) => {
      let n = false;
      let context = null;
      let result = access.result;
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
      // setHeaders(res, status, access.cors);
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

  createRoute(path = null, authCallback = null, description = null) {
    return new ZOAuthRoute(this, path, authCallback, description);
  }

  addRoute(method, path, scopes, callback, authCallback) {
    const route = this.createRoute();
    route.add(method, path, scopes, callback, authCallback);
    return route;
  }

  get(path, scopes, callback, authCallback = null) {
    return this.addRoute("GET", path, scopes, callback, authCallback);
  }

  post(path, scopes, callback, authCallback = null) {
    return this.addRoute("POST", path, scopes, callback, authCallback);
  }

  delete(path, scopes, callback, authCallback = null) {
    return this.addRoute("DELETE", path, scopes, callback, authCallback);
  }

  put(path, scopes, callback, authCallback = null) {
    return this.addRoute("PUT", path, scopes, callback, authCallback);
  }

  any(path, scopes, callback, authCallback = null) {
    return this.addRoute("ANY", path, scopes, callback, authCallback);
  }

  expressRouter() {
    return this.router;
  }
}
