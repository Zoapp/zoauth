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
/**
 * Use "setHeader" to initialise the header.
 *
 * @param {*} res The Response.
 * @param {*} status The Statut who have the header.
 * @param {*} cors Required for the Cross-Origin.
 */
const setHeaders = (res, status, cors) => {
  res.set("Content-Type", "application/json");
  res.set("Access-Control-Allow-Headers", "Content-Type, access_token");
  res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.set("Access-Control-Allow-Origin", cors || "*");
  res.status(status); // -> Sets the HTTP status for the response.
};

/**
 * Use "sendResponse" to set a Response with a Header to the Client.
 * <br>The fonction set the statut of Header (401 or 200) by testing the data attribute.
 *
 * @param {*} data Contain all the data of response.
 * @param {*} res The Response.
 * @param {*} ip IP Address for Cross-Origin.
 */
const sendResponse = async (data, res, ip) => {
  const status = data.error ? 401 : 200; // -> Set status according to data.
  setHeaders(res, status, ip);
  res.json(data); // -> Takes a Response stream and reads it to completion.
};

/**
 * "handleAuthFunc" is use in the process of Routing.
 *
 * @param {*} req The Request.
 * @param {*} res The Response.
 * @param {*} callback The Callback.
 */
const handleAuthFunc = async (req, res, callback) => {
  const params = req.body; // -> Get the body of Request.
  // logger.info(JSON.stringify(req.body));
  const data = await callback(params); // -> Await causes execution to pause waiting a Promise.
  const result = data.result || data; // -> Fill the const with "data" result or brut "data".
  // TODO ip for CORS
  // logger.info("response=", data);
  sendResponse(result, res);
};

export default (authServer = null, app = null, config = {}) => {
  let needStart = false;
  let a = app;
  if (!a) { // -> App don't exist : need to be created and started
    a = express(); // -> Create an Express application.
    a.server = http.createServer(a); // -> Create a Server
    a.use(bodyParser.json());
    a.use(bodyParser.urlencoded({ extended: false }));
    // \-> Middleware function in Express. Parses incoming requests with urlencoded payloads.
    needStart = true;
  }
  a.authServer = authServer || zoauthServer(config);

  const router = Router(); // Get a router instance
  router.get("/", async (req, res) => {
    sendResponse({ auth: "Ok" }, res);
  });
  router.post("/application", async (req, res) => {
    handleAuthFunc(req, res, params => a.authServer.registerApplication(params));
  });
  router.post("/anonymous", async (req, res) => {
    handleAuthFunc(req, res, params => a.authServer.anonymousAccess(params));
  });
  router.post("/user", async (req, res) => {
    handleAuthFunc(req, res, params => a.authServer.registerUser(params));
  });
  router.post("/authorize", async (req, res) => {
    handleAuthFunc(req, res, params => a.authServer.authorizeAccess(params));
  });
  router.post("/access_token", async (req, res) => {
    handleAuthFunc(req, res, params => a.authServer.requestAccessToken(params));
  });
  router.post("/scope", async (req, res) => {
    handleAuthFunc(req, res, params => a.authServer.registerScope(params));
  });
  /* eslint-disable no-unused-vars */
  /* router.use((err, req, res, next) => {
    res.status(500).json({ error: "internal server error" });
  }); */
  router.use(async (req, res, next) => {
    sendResponse({ error: "unknown request" }, res);
  });
  const defaultEndpoint = "auth"; // -> Set the defaut end point
  const api = config.api || { endpoint: defaultEndpoint };
  const endpoint = api.endpoint || defaultEndpoint;
  a.use(endpoint, router);

  if (needStart) { // -> Start listening is server need to be start
    a.server.listen(process.env.PORT || api.port || 8081);
  }

  return a; // -> Return the App
};
