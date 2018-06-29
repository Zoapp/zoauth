/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
const descriptor = {
  title: "Auth",
  description: "JSON schema for ZOAuth description collections",
  $schema: "http://json-schema.org/draft-04/schema#",
  type: "object",
  definitions: {
    Id: {
      type: "string",
    },
    DateTime: {
      type: "string",
    },
    Link: {
      type: "string",
    },
  },
  properties: {
    applications: {
      title: "Applications",
      properties: {
        id: {
          type: "#Id",
        },
        secret: {
          type: "string",
        },
        name: {
          type: "string",
        },
        url: {
          type: "string",
        },
        redirect_uri: {
          type: "string",
        },
        grant_type: {
          type: "string",
        },
        email: {
          type: "string",
        },
        domains: {
          type: "string",
        },
        policies: {
          type: "object",
        },
        creation_date: {
          type: "#DateTime",
        },
      },
    },
    users: {
      title: "Users",
      properties: {
        id: {
          type: "#Id",
        },
        username: {
          type: "string",
        },
        email: {
          type: "string",
        },
        valid_email: {
          type: "boolean",
        },
        password: {
          type: "string",
          size: "128",
        },
        salt: {
          type: "string",
          size: "128",
        },
        creation_date: {
          type: "#DateTime",
        },
        anonymous: {
          type: "boolean",
        },
        anonymous_token: {
          type: "string",
        },
        anonymous_secret: {
          type: "string",
        },
      },
    },
    authentications: {
      title: "Authentications",
      properties: {
        id: {
          type: "#Id",
        },
        client_id: {
          type: "#Link",
          link: "applications.id",
        },
        user_id: {
          type: "#Link",
          link: "users.id",
        },
        redirect_uri: {
          type: "string",
        },
        scope: {
          type: "string",
        },
      },
    },
    sessions: {
      title: "Sessions",
      properties: {
        id: {
          type: "#Id",
        },
        access_token: {
          type: "string",
        },
        expires_in: {
          type: "integer",
        },
        scope: {
          type: "array",
          arraytype: "string",
        },
        client_id: {
          type: "#Link",
          link: "applications.id",
        },
        user_id: {
          type: "#Link",
          link: "users.id",
        },
        created: {
          type: "#DateTime",
        },
        last: {
          type: "#DateTime",
        },
        ua: {
          type: "string",
        },
        lg: {
          type: "string",
        },
        ip: {
          type: "string",
        },
        ref: {
          type: "string",
        },
        ga: {
          type: "string",
        },
        cfduid: {
          type: "string",
        },
      },
    },
  },
};
export default descriptor;
