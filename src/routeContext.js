/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
export default class RouteContext {
  constructor(req, res) {
    this.req = req;
    this.res = res;
  }

  getParams() {
    return this.req.params;
  }

  getQuery() {
    return this.req.query;
  }

  getBody() {
    return this.req.body;
  }

  getScope() {
    const access = this.res.locals.access;
    let scope = null;
    if (access) {
      scope = access.scope;
    }
    return scope;
  }

  getClientId() {
    const access = this.res.locals.access;
    let clientId = null;
    if (access) {
      clientId = access.client_id;
    }
    return clientId;
  }

}

