/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import zoauthServer from "zoauth/zoauthServer";
import ZOAuthRouter, { send } from "zoauth/zoauthRouter";

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
    describe(`${name} using ${p.title}`, () => func(p.config));
  });
};

describeParams(
  "AuthRouter",
  [
    { title: "MemDatabase", config: {} },
    { title: "MySQLDatabase", config: mysqlConfig },
  ],
  (config) => {
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
          name: "Zoapp",
          grant_type: "password",
          redirect_uri: "localhost",
          email: "toto@test.com",
        };

        let response = await authServer.registerApplication(params);
        let { result } = response;
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);

        clientId = result.client_id;
        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual(["id", "username", "email"]);
        expect(result.id).toHaveLength(32);

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          redirect_uri: "localhost",
          scope: "default",
        };
        response = await authServer.authorizeAccess(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual(["redirect_uri"]);
        expect(result.redirect_uri).toEqual("localhost");

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          redirect_uri: "localhost",
          grant_type: "password",
        };
        response = await authServer.requestAccessToken(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "access_token",
          "expires_in",
          "scope",
        ]);
        accessToken = result.access_token;
        expect(accessToken).toHaveLength(48);

        authRouter = new ZOAuthRouter(authServer);
      });

      afterEach(async () => {
        await authServer.stop();
      });

      it("should route works", () => {
        authRouter.get("/", "default", () => {});

        const route = authServer.findRoute("/", "GET");
        expect(route !== null).toEqual(true);
      });

      it("should not route", () => {
        authRouter.get("/", "admin", () => {});

        let route = authServer.findRoute("/toto", "GET");
        expect(route == null).toEqual(true);

        route = authServer.findRoute("/", "POST");
        expect(route == null).toEqual(true);
      });
    });

    describe("grantAccess", () => {
      let accessToken = null;
      let clientId = null;
      let authRouter = null;
      let authServer = null;

      beforeEach(async () => {
        authServer = zoauthServer(config);
        await authServer.reset();
        await authServer.start();

        let params = {
          name: "Zoapp",
          grant_type: "password",
          redirect_uri: "localhost",
          email: "toto@test.com",
        };

        let response = await authServer.registerApplication(params);
        let { result } = response;
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);

        clientId = result.client_id;
        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual(["id", "username", "email"]);
        expect(result.id).toHaveLength(32);

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          redirect_uri: "localhost",
        };
        response = await authServer.authorizeAccess(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual(["redirect_uri"]);
        expect(result.redirect_uri).toEqual("localhost");

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          redirect_uri: "localhost",
          grant_type: "password",
        };
        response = await authServer.requestAccessToken(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "access_token",
          "expires_in",
          "scope",
        ]);
        accessToken = result.access_token;
        expect(accessToken).toHaveLength(48);

        authRouter = new ZOAuthRouter(authServer);
      });

      afterEach(async () => {
        await authServer.stop();
      });

      it("should grantAccess works", async () => {
        authRouter.get("/", "default", () => {});

        const response = await authServer.grantAccess("/", "GET", accessToken);
        const { result } = response;
        expect(Object.keys(result)).toEqual([
          "access_token",
          "client_id",
          "expires_in",
          "scope",
          "user_id",
        ]);
      });

      it("should not grantAccess", async () => {
        authRouter.get("/", "default", () => {});

        let response = await authServer.grantAccess("/", "GET");
        let { result } = response;
        expect(result.error).toEqual("No permission route");

        response = await authServer.grantAccess("/", "GET", "xxxx");
        ({ result } = response);
        expect(result.error).toEqual("Not valid access token");

        response = await authServer.grantAccess("/", "POST");
        ({ result } = response);
        expect(result.error).toEqual("No permission route");

        response = await authServer.grantAccess("/", "POST", "xxxx");
        ({ result } = response);
        expect(result.error).toEqual("No permission route");

        authRouter.get("/admin", "admin", () => {});
        response = await authServer.grantAccess("/admin", "GET", accessToken);
        ({ result } = response);
        expect(result.error).toEqual("Not allowed");
      });
    });
  },
);

describe("zoauthRouter", () => {
  const resMock = {
    send: jest.fn(),
    set: jest.fn(),
    status: jest.fn(),
  };

  describe("send()", () => {
    it("removes null values in response payload", () => {
      const payload = { count: null };

      send(resMock, payload);
      expect(resMock.send).toHaveBeenCalledWith("{}");
    });

    it("removes undefined values in response payload", () => {
      const payload = { count: undefined };

      send(resMock, payload);
      expect(resMock.send).toHaveBeenCalledWith("{}");
    });

    it("does not remove 0 values in response payload", () => {
      const payload = { count: 0 };

      send(resMock, payload);
      expect(resMock.send).toHaveBeenCalledWith(JSON.stringify(payload));
    });
  });
});
