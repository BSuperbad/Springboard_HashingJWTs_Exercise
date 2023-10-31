/** User class for message.ly */
const db = require("../db");
const ExpressError = require('../expressError');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const {
  BCRYPT_WORK_FACTOR,
  SECRET_KEY
} = require("../config");
const {
  authenticateJWT
} = require("../middleware/auth")


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({
    username,
    password,
    first_name,
    last_name,
    phone
  }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const results = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, first_name, last_name, phone, password`,
      [username, hashedPassword, first_name, last_name, phone]
    );
    return results.rows[0];

  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const results = await db.query(
      `SELECT password
      FROM users
      WHERE username =$1`,
      [username]);
    const user = results.rows[0];
    return user && await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    try {
      const results = await db.query(
        `UPDATE users
        SET last_login_at = current_timestamp
        WHERE username = $1
        RETURNING username, last_login_at`,
        [username]
      );
      if (results.rows.length === 0) {
        throw new ExpressError(`${username} not found`, 404);
      }
      return results.rows[0];
    } catch (e) {
      throw new ExpressError(`Failed to update last login time`, 500)
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, 
      first_name, 
      last_name, 
      phone 
      FROM users`);
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username,
      first_name,
      last_name,
      phone, 
      join_at,
      last_login_at
      FROM users 
      WHERE username =$1`,
      [username]
    );
    if (result.rows.length === 0) {
      throw new ExpressError(`${username} not found`, 404)
    }
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT m.id, 
      u.username AS to_user,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at
     FROM messages AS m
     JOIN users AS u ON m.to_username = u.username
     WHERE from_username = $1`,
      [username]
    );
    return results.rows.map((message) => {
      return {
        id: message.id,
        to_user: {
          username: message.to_user,
          first_name: message.first_name,
          last_name: message.last_name,
          phone: message.phone,
        },
        body: message.body,
        sent_at: message.sent_at,
        read_at: message.read_at,
      };
    });
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT m.id,
      u.username AS from_user,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at
      FROM messages AS m
      JOIN users AS u 
      ON m.from_username = u.username
      WHERE to_username = $1`,
      [username]
    );

    return results.rows.map((message) => {
      return {
        id: message.id,
        from_user: {
          username: message.from_user,
          first_name: message.first_name,
          last_name: message.last_name,
          phone: message.phone,
        },
        body: message.body,
        sent_at: message.sent_at,
        read_at: message.read_at,
      };
    });
  }
}


module.exports = User;