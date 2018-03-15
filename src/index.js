/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { setupLogger } from "zoapp-core";
import authApi from "./api";
import { ZOAuthServer } from "./zoauthServer";
import ZOAuthRouter from "./zoauthRouter";

// Minimal bootstrap launch
// authApi({});

setupLogger();

export default (config = {}, app = null) => {
  const authServer = new ZOAuthServer(config);
  authApi(authServer, app, config);
  return authServer;
};

export const AuthRouter = (authServer) => new ZOAuthRouter(authServer);
