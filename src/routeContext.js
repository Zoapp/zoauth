/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * @class
 * @memberof module:ZOAUTH
 * @alias RouteContext
 * @classdesc "RouteContext" give some functions to work on Request and Response.
 */
export default class RouteContext {
  /**
   * The constructor Init the Request and Response.
   * @constructor
   * @param {*} req The Request Object.
   * @param {*} res The Response Object.
   */
  constructor(req, res) {
    this.req = req; // Init Request.
    this.res = res; // Init Response.
  }

  /**
   * getParams() : Get the parameters of the Request object.
   *
   * @memberof RouteContext
   * @returns {req.params} Return the parameters of Request.
   */
  getParams() {
    return this.req.params;
  }

  /**
   * getQuery() : Get the query use in the Request object.
   *
   * @memberof RouteContext
   * @returns {req.query} Return the query use of Request.
   */
  getQuery() {
    return this.req.query;
  }

  /**
   * getBody() : Get the body of the Request object.
   *
   * @memberof RouteContext
   * @returns {req.body} Return the body of Request.
   */
  getBody() {
    return this.req.body;
  }

  /**
   * getScope() : Get the scope of the Response object.
   *
   * @memberof RouteContext
   * @returns {object} Return the scope or null if there are not locals.
   */
  getScope() {
    const { access } = this.res.locals;
    let scope = null;
    if (access) {
      ({ scope } = access);
    }
    return scope;
  }

  /**
   * getClientId() : Get the client_id on the locals from Response Object and return him.
   *
   * @memberof RouteContext
   * @returns {object} Return the client_id or null if there are not locals.
   */
  getClientId() {
    const { access } = this.res.locals;
    let clientId = null;
    if (access) {
      clientId = access.client_id;
    }
    return clientId;
  }
}
