/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import http from "http";
import bodyParser from "body-parser";
import express, { Router } from "express";
import zoauthServer from "../zoauthServer";

// Express inits
const setHeaders = (res, status, cors) => {
  res.set("Content-Type", "application/json");
  res.set("Access-Control-Allow-Headers", "Content-Type, access_token");
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Origin", cors || "*");
  res.status(status);
};

const sendResponse = async (data, res, ip) => {
  const d = { ...data };
  const status = d.error ? d.status || 401 : 200;
  if (d.status) delete d.status;
  setHeaders(res, status, ip);
  res.json(d);
};

const handleAuthFunc = async (req, res, callback) => {
  const params = req.body;
  const data = await callback(params);
  const result = data.result || data;
  // TODO ip for CORS
  // logger.info("response=", data);
  sendResponse(result, res);
};

export default (authServer = null, app = null, config = {}) => {
  let needStart = false;
  let a = app;
  if (!a) {
    a = express();
    a.server = http.createServer(a);
    a.use(bodyParser.json());
    a.use(bodyParser.urlencoded({ extended: false }));
    needStart = true;
  }
  a.authServer = authServer || zoauthServer(config);

  const router = Router();
  router.get("/", async (req, res) => {
    sendResponse({ auth: "Ok" }, res);
  });
  router.post("/application", async (req, res) => {
    handleAuthFunc(req, res, (params) =>
      a.authServer.registerApplication(params),
    );
  });
  router.post("/anonymous", async (req, res) => {
    handleAuthFunc(req, res, (params) => a.authServer.anonymousAccess(params));
  });
  router.post("/user", async (req, res) => {
    handleAuthFunc(req, res, (params) =>
      a.authServer.registerUser(params, req.query.access_token),
    );
  });
  router.post("/authorize", async (req, res) => {
    handleAuthFunc(req, res, (params) => a.authServer.authorizeAccess(params));
  });
  router.post("/access_token", async (req, res) => {
    handleAuthFunc(req, res, (params) =>
      a.authServer.requestAccessToken(params),
    );
  });
  router.post("/scope", async (req, res) => {
    handleAuthFunc(req, res, (params) => a.authServer.registerScope(params));
  });
  router.post("/validate", async (req, res) => {
    handleAuthFunc(req, res, (params) =>
      a.authServer.validateUserFromAdmin(params, req.query.access_token),
    );
  });
  router.get("/validate", async (req, res) => {
    const { result } = await a.authServer.validateUserFromMail(req.query);
    if (result.redirectUri) {
      let redirect = `${result.redirectUri}?`;

      if (result.error) {
        redirect += `error=${result.error}`;
      } else {
        redirect += `info=${result.info}`;
      }
      res.redirect(redirect);
    } else {
      sendResponse(result, res);
    }
  });
  router.post("/lost_password", async (req, res) => {
    handleAuthFunc(req, res, (params) => a.authServer.resetPassword(params));
  });
  router.put("/reset_password", async (req, res) => {
    handleAuthFunc(req, res, (params) =>
      a.authServer.changePassword(params, req.query.access_token),
    );
  });
  router.post("/logout", async (req, res) => {
    handleAuthFunc(req, res, (params) =>
      a.authServer.logout(params, req.query.access_token),
    );
  });
  router.use(async (req, res) => {
    sendResponse({ error: "unknown request" }, res);
  });
  const defaultEndpoint = "auth";
  const api = config.api || { endpoint: defaultEndpoint };
  const endpoint = api.endpoint || defaultEndpoint;
  a.use(endpoint, router);

  if (needStart) {
    a.server.listen(process.env.PORT || api.port || 8081);
  }

  return a;
};
