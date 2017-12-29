/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { assert, expect } from "chai";
import { setupLogger } from "zoapp-core";
import zoauthServer from "../src/zoauthServer";

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

describeParams("AuthServer", [{ title: "MemDb", config: {} }, { title: "MySQL Db", config: mysqlConfig }], (config) => {
  describe("registerApplication", () => {
    it("should register Application", async () => {
      const params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      const response = await authServer.registerApplication(params);
      const { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
    });
    it("should not register Application", async () => {
      let params = {};
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      assert.equal(result.error, "Wrong email sent", "Empty parameters sent");
      params = { email: "toto@test.com" };
      response = await authServer.registerApplication(params);
      ({ result } = response);
      assert.equal(result.error, "Wrong name sent", "No name send");
      params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      await authServer.registerApplication(params);
      response = await authServer.registerApplication(params);
      ({ result } = response);
      assert.equal(
        result.error,
        "Can't register this application name",
        "Application already exist",
      );
      // TODO more tests for grant_type & redirect_uri
    });
  });
  describe("registerUser", () => {
    it("should register User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      const clientId = result.client_id;
      expect(clientId).to.have.lengthOf(64);
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
    });
    it("should not register User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      const clientId = result.client_id;
      expect(clientId).to.have.lengthOf(64);
      params = { client_id: clientId };
      response = await authServer.registerUser(params);
      ({ result } = response);
      assert.equal(
        result.error,
        "Wrong parameters sent",
        "Empty parameters sent",
      );
      params = { client_id: clientId, email: "tutu@test.com" };
      response = await authServer.registerUser(params);
      ({ result } = response);
      assert.equal(result.error, "Wrong parameters sent", "No name send");
      params = { client_id: clientId, email: "tutu@test.com", username: "tutu" };
      response = await authServer.registerUser(params);
      ({ result } = response);
      assert.equal(result.error, "Wrong parameters sent", "No password send");
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      await authServer.registerUser(params);
      response = await authServer.registerUser(params);
      ({ result } = response);
      assert.equal(result.error, "User exist: toto", "User already exist");
    });
  });
  describe("registerAnonymousUser", () => {
    it("should register anonymous User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
        policies: { authorizeAnonymous: true, anonymous_secret: "koko" },
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      const clientId = result.client_id;
      expect(clientId).to.have.lengthOf(64);
      params = {
        client_id: clientId, anonymous_secret: "koko",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "username"]);
      expect(result.id).to.have.lengthOf(32);
    });
    it("should not register User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
        policies: { authorizeAnonymous: true, anonymous_secret: "koko" },
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      const clientId = result.client_id;
      expect(clientId).to.have.lengthOf(64);
      params = { client_id: clientId };
      response = await authServer.registerUser(params);
      ({ result } = response);
      assert.equal(
        result.error,
        "Wrong parameters sent",
        "Empty parameters sent",
      );
      params = { client_id: clientId, anonymous_secret: "kiki" };
      response = await authServer.registerUser(params);
      ({ result } = response);
      assert.equal(result.error, "Wrong parameters sent", "No name send");
    });
  });
  describe("createAnonymousUserWithAccessToken", () => {
    it("should register anonymous User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
        policies: { authorizeAnonymous: true, anonymous_secret: "koko" },
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      const clientId = result.client_id;
      expect(clientId).to.have.lengthOf(64);
      params = {
        client_id: clientId, anonymous_secret: "koko",
      };
      response = await authServer.anonymousAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["user_id", "username", "access_token", "expires_in", "scope"]);
      expect(result.user_id).to.have.lengthOf(32);
    });
    it("should not register User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
        policies: { authorizeAnonymous: true, anonymous_secret: "koko" },
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      const clientId = result.client_id;
      expect(clientId).to.have.lengthOf(64);
      params = { client_id: clientId };
      response = await authServer.anonymousAccess(params);
      ({ result } = response);
      assert.equal(
        result.error,
        "Wrong parameters sent",
        "Empty parameters sent",
      );
      params = { client_id: clientId, anonymous_secret: "kiki" };
      response = await authServer.anonymousAccess(params);
      ({ result } = response);
      assert.equal(result.error, "Wrong parameters sent", "No name send");
    });
  });
  describe("authorize", () => {
    it("should authorize user", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
      const clientId = result.client_id;
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
      params = {
        client_id: clientId,
        username: "toto",
        password: "12345",
        redirect_uri: "localhost",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["redirect_uri"]);
      assert.equal(
        result.redirect_uri,
        "localhost",
        "Redirect_uri is localhost",
      );
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["redirect_uri"]);
      assert.equal(
        result.redirect_uri,
        "localhost",
        "Duplicate authorize returns the same",
      );
    });
    it("should not authorize User", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
      const clientId = result.client_id;
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
      params = {
        client_id: clientId,
        password: "12345",
        redirect_uri: "localhost",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      assert.equal(result.error, "Not valid", "No credentials");
      params = {
        client_id: clientId,
        username: "toto",
        password: "wrong",
        redirect_uri: "localhost",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      assert.equal(result.error, "Wrong credentials", "Wrong password");
    });
  });
  describe("requestAccessToken", () => {
    it("should get accessToken", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
      const clientId = result.client_id;
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
      params = {
        client_id: clientId,
        username: "toto",
        password: "12345",
        redirect_uri: "localhost",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["redirect_uri"]);
      assert.equal(
        result.redirect_uri,
        "localhost",
        "Redirect_uri is localhost",
      );
      params = {
        client_id: clientId,
        username: "toto",
        password: "12345",
        redirect_uri: "localhost",
        grant_type: "password",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["access_token", "expires_in", "scope"]);
      expect(result.access_token).to.have.lengthOf(48);
    });
    it("should not get accessToken", async () => {
      let params = {
        name: "Zoapp",
        grant_type: "password",
        redirect_uri: "localhost",
        email: "toto@test.com",
      };
      const authServer = zoauthServer(config);
      await authServer.reset();
      await authServer.start();
      let response = await authServer.registerApplication(params);
      let { result } = response;
      expect(result).to.have.all.keys(["client_id", "client_secret"]);
      expect(result.client_id).to.have.lengthOf(64);
      const clientId = result.client_id;
      params = {
        client_id: clientId, username: "toto", password: "12345", email: "toto@test.com",
      };
      response = await authServer.registerUser(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["id", "email", "username"]);
      expect(result.id).to.have.lengthOf(32);
      params = {
        client_id: clientId,
        username: "toto",
        password: "12345",
        redirect_uri: "localhost",
      };
      response = await authServer.authorizeAccess(params);
      ({ result } = response);
      expect(result).to.have.all.keys(["redirect_uri"]);
      assert.equal(
        result.redirect_uri,
        "localhost",
        "Redirect_uri is localhost",
      );
      params = {
        client_id: clientId,
        username: "toto",
        password: "12345",
        redirect_uri: "localhost",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      assert.equal(
        result.error,
        "Unknown grant type: undefined",
        "No grant_type",
      );
      params = {
        client_id: clientId,
        password: "12345",
        redirect_uri: "localhost",
        grant_type: "password",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      assert.equal(result.error, "Can't authenticate", "No credentials");
      params = {
        client_id: clientId,
        username: "toto",
        password: "wrong",
        redirect_uri: "localhost",
        grant_type: "password",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      assert.equal(result.error, "Can't authenticate", "Wrong password");
      params = {
        username: "toto",
        password: "12345",
        redirect_uri: "localhost",
        grant_type: "password",
      };
      response = await authServer.requestAccessToken(params);
      ({ result } = response);
      assert.equal(result.error, "Not authentified", "Wrong client_id");
    });
  });
});
