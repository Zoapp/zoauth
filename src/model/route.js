/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import StringTools from "zoapp-core/helpers/stringTools";

export default class Route {
  constructor(name, auth) {
    this.name = name;
    this.auth = auth;
    this.scopes = [];
    this.methods = [];
    this.open = true;
  }

  static isContained(array, value) {
    let ret = false;
    array.some((v) => {
      if (value === v) {
        ret = true;
      }
      return ret;
    });
    return ret;
  }

  static putStringValue(array, value) {
    if (!Route.isContained(array, value)) {
      array.push(value);
    }
  }

  static addValue(array, value) {
    let ret = false;
    if (value) {
      if (Array.isArray(value) && value.length > 0) {
        value.forEach((v) => {
          Route.putStringValue(array, v);
        });
        ret = true;
      } else if (!StringTools.stringIsEmpty(value)) {
        Route.putStringValue(array, value.toLowerCase());
        ret = true;
      }
    }
    return ret;
  }

  addScope(scope) {
    const ret = Route.addValue(this.scopes, scope);

    let o = false;
    if (this.scopes.length > 0) {
      this.scopes.some((s) => {
        if (s === "open") {
          o = true;
        }
        return o;
      });
    } else {
      o = true;
    }
    this.open = o;
    return ret;
  }

  addMethod(method) {
    return Route.addValue(this.methods, method);
  }

  isOpen() {
    return this.open;
  }

  isScopeValid(scope) {
    let ret = false;
    if (!StringTools.stringIsEmpty(scope)) {
      const sc = scope.toLowerCase();
      this.scopes.some((s) => {
        if (s === "open" || s === "*" || s === sc) {
          ret = true;
        }
        return ret;
      });
    }
    return ret;
  }

  isMethodValid(method) {
    let ret = false;
    if (!StringTools.stringIsEmpty(method)) {
      const meth = method.toLowerCase();
      this.methods.some((m) => {
        if (m === "any" || m === meth) {
          ret = true;
        }
        return ret;
      });
    }
    return ret;
  }
}
