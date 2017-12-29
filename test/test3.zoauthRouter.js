/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { assert, expect } from "chai";
import { setupLogger } from "zoapp-core";
import zoauthServer from "../src/zoauthServer";
import ZOAuthRouter from "../src/zoauthRouter";


setupLogger("test");

const mysqlConfig = {
  database: {
    datatype: "mysql",
    host: "localhost",
    name: "auth_test",
    user: "root",
  },
  endpoint: "/auth",
};

const describeParams = (name, params, func) => {
  params.forEach((p) => {
    describe(`${name} using ${p.title}`, () =>
      func(p.config),
    );
  });
};

describeParams("AuthRouter", [{ title: "MemDb", config: {} }, { title: "MySQL Db", config: mysqlConfig }], (config) => {
  describe("create auth Routers", () => {
    let accessToken = null;
    let clientId = null;
    let authRouter = null;
    let authServer = null;

    beforeEach(async () => {
      authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let params = {
        name: "Zoapp", grant_type: "password", redirect_uri: "localhost", email: "toto@test.com",
      };
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
      clientId = result.client_id;
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
      params = {
        client_id: clientId, username: "toto", password: "12345", redirect_uri: "localhost", scope: "default",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["redirect_uri"]);
      assert.equal(result.redirect_uri, "localhost", "Redirect_uri is localhost");
      params = {
        client_id: clientId, username: "toto", password: "12345", redirect_uri: "localhost", grant_type: "password",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["access_token", "expires_in", "scope"]);
      accessToken = result.access_token;
      expect(accessToken).to.have.lengthOf(48);
      authRouter = new ZOAuthRouter(authServer);
    });

    afterEach(async () => {
      await authServer.stop();
    });

    /* eslint-disable no-unused-vars */

    it("should route works", () => {
      authRouter.get("/", "default", (req, res) => {});
      const route = authServer.findRoute("/", "GET");
      assert(route !== null, "Route '/' is available");
    });

    it("should not route", () => {
      authRouter.get("/", "admin", (req, res) => {});
      let route = authServer.findRoute("/toto", "GET");
      assert(route == null, "Route '/toto' is not available");
      route = authServer.findRoute("/", "POST");
      assert(route == null, "Route '/' with default scope is not authorized");
    });
  });

  describe("grantAccess", () => {
    let accessToken = null;
    let accessScope = null;
    let clientId = null;
    let authRouter = null;
    let authServer = null;

    beforeEach(async () => {
      authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let params = {
        name: "Zoapp", grant_type: "password", redirect_uri: "localhost", email: "toto@test.com",
      };
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
      clientId = result.client_id;
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
      params = {
        client_id: clientId, username: "toto", password: "12345", redirect_uri: "localhost",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["redirect_uri"]);
      assert.equal(result.redirect_uri, "localhost", "Redirect_uri is localhost");
      params = {
        client_id: clientId, username: "toto", password: "12345", redirect_uri: "localhost", grant_type: "password",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["access_token", "expires_in", "scope"]);
      accessScope = result.scope;
      accessToken = result.access_token;
      expect(accessToken).to.have.lengthOf(48);
      authRouter = new ZOAuthRouter(authServer);
    });

    afterEach(async () => {
      await authServer.stop();
    });

    /* eslint-disable no-unused-vars */

    it("should grantAccess works", async () => {
      authRouter.get("/", "default", (req, res) => {});
      const response = await authServer.grantAccess("/", "GET", accessToken);
      const { result } = response;
      expect(result).to.have.all.keys(["access_token", "expires_in", "scope", "client_id", "user_id"]);
    });

    it("should not grantAccess", async () => {
      authRouter.get("/", "default", (req, res) => {});
      let response = await authServer.grantAccess("/", "GET");
      let { result } = response;
      assert.equal(result.error, "No permission route", "Route '/' need accessToken");
      response = await authServer.grantAccess("/", "GET", "xxxx");
      ({ result } = response);
      assert.equal(result.error, "Not valid access token", "Route '/' need valid accessToken");
      response = await authServer.grantAccess("/", "POST");
      ({ result } = response);
      assert.equal(result.error, "No permission route", "Route '/' with post method is not available");
      response = await authServer.grantAccess("/", "POST", "xxxx");
      ({ result } = response);
      assert.equal(result.error, "No permission route", "Route '/' with post method is not available");
      authRouter.get("/admin", "admin", (req, res) => {});
      response = await authServer.grantAccess("/admin", "GET", accessToken);
      ({ result } = response);
      assert.equal(result.error, "Not allowed", "Route '/' is not allowed for default scope");
    });
  });
});
