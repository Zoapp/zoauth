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
  const status = data.error ? 401 : 200;
  setHeaders(res, status, ip);
  res.json(data);
};

const handleAuthFunc = async (req, res, callback) => {
  const params = req.body;
  // logger.info(JSON.stringify(req.body));
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
    handleAuthFunc(req, res, (params) => a.authServer.registerUser(params));
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
  /* eslint-disable no-unused-vars */
  /* router.use((err, req, res, next) => {
    res.status(500).json({ error: "internal server error" });
  }); */
  router.use(async (req, res, next) => {
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
