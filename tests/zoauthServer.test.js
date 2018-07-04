/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import zoauthServer from "zoauth/zoauthServer";

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
  "AuthServer",
  [
    { title: "MemDatabase", config: {} },
    { title: "MySQLDatabase", config: mysqlConfig },
  ],
  (config) => {
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);
      });

      it("should not register Application", async () => {
        let params = {};
        const authServer = zoauthServer(config);
        await authServer.reset();
        await authServer.start();

        let response = await authServer.registerApplication(params);
        let { result } = response;
        expect(result.error).toEqual("Wrong email sent");
        params = { email: "toto@test.com" };

        response = await authServer.registerApplication(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong name sent");

        params = {
          name: "Zoapp",
          grant_type: "password",
          redirect_uri: "localhost",
          email: "toto@test.com",
        };
        await authServer.registerApplication(params);
        response = await authServer.registerApplication(params);
        ({ result } = response);
        expect(result.error).toEqual("Can't register this application name");
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        const clientId = result.client_id;
        expect(clientId).toHaveLength(64);

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "id",
          "username",
          "validation",
          "email",
        ]);
        expect(result.id).toHaveLength(32);
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        const clientId = result.client_id;
        expect(clientId).toHaveLength(64);

        params = { client_id: clientId };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");

        params = { client_id: clientId, email: "tutu@test.com" };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");

        params = {
          client_id: clientId,
          email: "tutu@test.com",
          username: "tutu",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        await authServer.registerUser(params);
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(result.error).toEqual("Not valid user: toto");
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        const clientId = result.client_id;
        expect(clientId).toHaveLength(64);

        params = {
          client_id: clientId,
          anonymous_secret: "koko",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual(["id", "username", "validation"]);
        expect(result.id).toHaveLength(32);
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        const clientId = result.client_id;
        expect(clientId).toHaveLength(64);

        params = { client_id: clientId };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");

        params = { client_id: clientId, anonymous_secret: "kiki" };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        const clientId = result.client_id;
        expect(clientId).toHaveLength(64);

        params = {
          client_id: clientId,
          anonymous_secret: "koko",
        };
        response = await authServer.anonymousAccess(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "access_token",
          "expires_in",
          "scope",
          "username",
          "user_id",
        ]);
        expect(result.user_id).toHaveLength(32);
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        const clientId = result.client_id;
        expect(clientId).toHaveLength(64);

        params = { client_id: clientId };
        response = await authServer.anonymousAccess(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");

        params = { client_id: clientId, anonymous_secret: "kiki" };
        response = await authServer.anonymousAccess(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong parameters sent");
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);
        const clientId = result.client_id;

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "id",
          "username",
          "validation",
          "email",
        ]);
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
        response = await authServer.authorizeAccess(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual(["redirect_uri"]);
        expect(result.redirect_uri).toEqual("localhost");
      });

      it("should authorize user in existing application", async () => {
        let params = {
          name: "Zoapp",
          grant_type: "password",
          redirect_uri: "localhost",
          email: "toto@test.com",
        };
        const authServer = zoauthServer(config);
        await authServer.reset();
        await authServer.start();

        if (config.database) {
          // insert an app in bdd
          await authServer.model.database.query(
            " INSERT INTO `applications` (`id`,`idx`,`name`,`email`,`redirect_uri`,`grant_type`,`creation_date`,`secret`) VALUES ( unhex(replace(uuid(),'-','')), 'authclientid', 'foo', 'opla@example.org', 'http://127.0.0.1:8080', 'password', '2018-05-25 00:04:46.968', 'authsecret') ",
          );
          const clientId = "authclientid";

          params = {
            client_id: clientId,
            username: "toto",
            password: "12345",
            email: "toto@test.com",
          };
          let response = await authServer.registerUser(params);
          let { result } = response;
          expect(Object.keys(result)).toEqual(["id", "username", "email"]);
          expect(result.id).toHaveLength(32);

          response = await authServer.authorizeAccess(params);
          ({ result } = response);
          expect(Object.keys(result)).toEqual(["redirect_uri"]);
          expect(result.redirect_uri).toEqual("localhost");
          response = await authServer.authorizeAccess(params);
          ({ result } = response);
          expect(Object.keys(result)).toEqual(["redirect_uri"]);
          expect(result.redirect_uri).toEqual("localhost");
        }
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);
        const clientId = result.client_id;

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "id",
          "username",
          "validation",
          "email",
        ]);
        expect(result.id).toHaveLength(32);

        params = {
          client_id: clientId,
          password: "12345",
          redirect_uri: "localhost",
        };
        response = await authServer.authorizeAccess(params);
        ({ result } = response);
        expect(result.error).toEqual("Not valid");

        params = {
          client_id: clientId,
          username: "toto",
          password: "wrong",
          redirect_uri: "localhost",
        };
        response = await authServer.authorizeAccess(params);
        ({ result } = response);
        expect(result.error).toEqual("Wrong credentials");
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);
        const clientId = result.client_id;

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "id",
          "username",
          "validation",
          "email",
        ]);
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
        expect(result.access_token).toHaveLength(48);
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
        expect(Object.keys(result)).toEqual(["client_id", "client_secret"]);
        expect(result.client_id).toHaveLength(64);
        const clientId = result.client_id;

        params = {
          client_id: clientId,
          username: "toto",
          password: "12345",
          email: "toto@test.com",
        };
        response = await authServer.registerUser(params);
        ({ result } = response);
        expect(Object.keys(result)).toEqual([
          "id",
          "username",
          "validation",
          "email",
        ]);
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
        };
        response = await authServer.requestAccessToken(params);
        ({ result } = response);
        expect(result.error).toEqual("Unknown grant type: undefined");

        params = {
          client_id: clientId,
          password: "12345",
          redirect_uri: "localhost",
          grant_type: "password",
        };
        response = await authServer.requestAccessToken(params);
        ({ result } = response);
        expect(result.error).toEqual("Can't authenticate");

        params = {
          client_id: clientId,
          username: "toto",
          password: "wrong",
          redirect_uri: "localhost",
          grant_type: "password",
        };
        response = await authServer.requestAccessToken(params);
        ({ result } = response);
        expect(result.error).toEqual("Can't authenticate");

        params = {
          username: "toto",
          password: "12345",
          redirect_uri: "localhost",
          grant_type: "password",
        };
        response = await authServer.requestAccessToken(params);
        ({ result } = response);
        expect(result.error).toEqual("Not authentified");
      });
    });
  },
);
