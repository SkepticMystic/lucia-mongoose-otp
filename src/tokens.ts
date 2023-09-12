import type { User } from "lucia";
import type { Model } from "mongoose";
import { err, ok } from "./result";

/** Every Token has the following properties  */
export interface TokenBase {
  /** The pin that the user will use to verify the Token  */
  pin: string;
  /** The kind of Token this is  */
  kind: string;

  /** The identifier of the Lucia user that this Token is for  */
  identifier: `${string}:${string}`;

  /** Arbitrary data that can be stored with the Token  */
  data?: Record<string, unknown>;

  /** Milliseconds since createdAt when the Token expires  */
  expiresInMs?: number;
  createdAt: Date;
}

export class Tokens<Token extends TokenBase> {
  private models: { Token: Model<Token>; User: Model<User> };

  constructor(models: { Token: Model<Token>; User: Model<User> }) {
    this.models = models;
  }

  /**
   * Check if a Token is expired.
   *
   * If it doesn't have an expiry date, it's never expired
   */
  isExpired = (
    { createdAt, expiresInMs }: Pick<Token, "expiresInMs" | "createdAt">,
  ) => {
    if (expiresInMs === undefined) return false;

    const expiresAt = createdAt.getTime() + expiresInMs;
    return expiresAt < Date.now();
  };

  /** A more type-safe option than Tokens.create */
  create = (input: Omit<Token, "pin" | "createdAt">) =>
    this.models.Token.create(input);

  /** Return an existing Token if it exists and is not expired, otherwise create a new one */
  getOrCreate = async (input: Omit<Token, "pin" | "createdAt">) => {
    const { identifier, kind } = input;

    // Check if there is an existing Token for that user of that kind
    const existing = await this.models.Token
      .findOne({ identifier, kind })
      .exec();

    if (existing) {
      if (this.isExpired(existing)) {
        const [newToken, _removeOld] = await Promise.all([
          this.create(input),
          existing.deleteOne(),
        ]);

        return newToken;
      } else {
        return existing;
      }
    } else {
      return this.create(input);
    }
  };

  /**
   * Given a pin, and the kind of Token, returns the Token if it exists and is not expired.
   *
   * If the Token is expired, it will be deleted.
   */
  validateToken = async <T extends Token = Token>(
    { pin, kind }: Pick<T, "pin" | "kind">,
  ) => {
    const token = await this.models.Token
      .findOne({ pin, kind })
      .exec();

    if (!token) {
      return err({ code: "token_not_found" as const });
    }

    if (this.isExpired(token)) {
      await token.deleteOne();
      return err({ code: "token_expired" as const });
    }

    return ok(token);
  };

  /** Given a Token,
   *   parse the identifier,
   *   find the user,
   *   make sure the identifier value matches,
   *   and return the user in Lucia format.
   *
   * If the user is not found,
   *   or the identifier value doesn't match,
   *   it will return an error, but it **won't** delete the Token.
   *
   * Use this to check if a user exists to decide how to handle their Token.
   */
  getTokenUser = async (token: Pick<Token, "identifier">) => {
    // Parse the identifier
    const [idField, ...idRest] = token.identifier.split(":");
    const identifier = { field: idField, value: idRest.join(":") };

    // Find the user
    const rawUser = await this.models.User
      .findOne({ [identifier.field]: identifier.value })
      .lean();

    if (!rawUser) {
      return err({ identifier, code: "user_not_found" as const });
    }

    // Make sure the identifier value matches
    // NOTE: Mongo will just find the first user in the db if either of these are undefined
    //  so we need to check for that
    // @ts-expect-error
    if (rawUser[identifier.field] !== identifier.value) {
      return err({ identifier, code: "identifier_value_mismatch" as const });
    }

    // Convert to the shape auth.getUser would return
    // @ts-expect-error
    const { _id, ...userRest } = rawUser;
    return ok({
      identifier,
      user: { userId: _id, ...userRest },
    });
  };

  /**
   * Given a pin, and the kind of Token, returns the user and the Token if it exists and is not expired.
   *
   * If the Token is expired, or the user is not found, it will be deleted.
   */
  validateUserToken = async (input: Pick<Token, "pin" | "kind">) => {
    const validateToken = await this.validateToken(input);
    if (!validateToken.ok) return validateToken;
    const token = validateToken.data;

    const userCheck = await this.getTokenUser(token);
    if (!userCheck.ok) {
      await token.deleteOne();
      return userCheck;
    }

    return ok({
      user: userCheck.data.user,
      token,
    });
  };
}
