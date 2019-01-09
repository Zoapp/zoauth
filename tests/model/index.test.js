/**
 * Copyright (c) 2015-present, CWB SAS
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { ZOAuthModel } from "../../src/model";

describe("zoauth - model", () => {
  const zoAuthModel = new ZOAuthModel({}, null);
  zoAuthModel.generateId = () => "abcd";

  const getItemSpy = (preexistingUser) =>
    jest.fn((arg) => {
      if (arg === preexistingUser.id) return Promise.resolve(preexistingUser);
      return Promise.resolve(null);
    });

  const setItemSpy = (updatedUser) =>
    jest.fn().mockResolvedValue(Promise.resolve(updatedUser));

  const UsersModelMock = (existingUser, updatedUser) => ({
    getItem: getItemSpy(existingUser),
    setItem: setItemSpy(updatedUser),
    nextItem: getItemSpy(existingUser),
  });

  describe("setUser", () => {
    it("should set a user by id", async () => {
      const id = "abcd";

      const updatedUser = {
        id,
        username: "final",
        email: "final@example.fr",
      };

      const preexistingUser = {
        id,
        username: "initial",
        email: "initial@example.fr",
      };
      const res = await zoAuthModel.setUser(
        updatedUser,
        UsersModelMock(preexistingUser, updatedUser),
      );
      expect(res).toMatchObject(updatedUser);
      expect(res.salt).toBeUndefined();
      expect(res.password).toBeUndefined(); // Password shouldn't be returned
    });
    it("should set a user passwd by username/email", async () => {
      const updatedUser = {
        username: "final",
        email: "final@example.fr",
        password: "passwordUpdate",
      };

      const preexistingUser = {
        username: "final",
        email: "final@example.fr",
      };

      const res = await zoAuthModel.setUser(
        updatedUser,
        UsersModelMock(preexistingUser, updatedUser),
      );
      expect(res).toMatchObject(preexistingUser); // Check for pre-existing user, since username/email will not change
      expect(res.salt).toBeDefined();
      expect(res.password).toBeUndefined(); // Password shouldn't be returned
    });
    it("should throw an error if user id doesn't exist", async () => {
      const updatedUser = {
        id: "abcd",
        username: "final",
        email: "final@example.fr",
      };

      const preexistingUser = {
        id: "dcba",
        username: "initial",
        email: "initial@example.fr",
      };

      try {
        await zoAuthModel.setUser(
          updatedUser,
          UsersModelMock(preexistingUser, updatedUser),
        );
      } catch (err) {
        expect(err.message).toEqual("unknown user");
      }
    });
    it("should update password (salt regeneration)", async () => {
      const id = "abcd";

      const updatedUser = {
        id,
        username: "final",
        email: "final@example.fr",
        password: "1",
      };

      const preexistingUser = {
        id,
        username: "initial",
        email: "initial@example.fr",
      };

      const res = await zoAuthModel.setUser(
        updatedUser,
        UsersModelMock(preexistingUser, updatedUser),
      );
      expect(res.salt).toBeDefined();
      expect(res.password).toBeUndefined(); // Password shouldn't be returned
    });
  });
});
