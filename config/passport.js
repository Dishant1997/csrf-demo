var LocalStrategy = require('passport-local').Strategy;
var mysql = require('mysql');
var bcrypt = require('bcrypt-nodejs');
var config = require('./config');

var connection = mysql.createConnection({
  host: config.host,
  user: config.user,
  password: config.password,
  database: config.mysqldb
});

connection.connect();

module.exports = function(passport) {
  // used to serialize the user for the session
  passport.serializeUser(function(user, done) {
    done(null, user.idAccount);
  });

  // used to deserialize the user
  passport.deserializeUser(function(id, done) {
    connection.query("SELECT * FROM Account WHERE idAccount = ? ",[id], function(err, rows){
      done(err, rows[0]);
    });
  });

  passport.use(
    'local-signup',
    new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    },
    function(req, email, password, done) {
      connection.query("SELECT * FROM Account WHERE email = ?", [email], function(err, rows) {
        if (err) {
          return done(err);
        }
        if (rows.length) {
          return done(null, false, req.flash('signupMessage', 'That email is already taken'));
        } else {
          var userInfo = {
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, null, null),
            firstName: req.body.firstName,
            lastName: req.body.lastName
          };

          var insertQuery = "INSERT INTO Account (firstName, lastName, email, password) values (?,?,?,?)";

          console.log(userInfo);
          connection.query(insertQuery, [userInfo.firstName, userInfo.lastName, userInfo.email, userInfo.password], function(err, rows) {
            userInfo.idAccount = rows.insertId;

            return done(null, userInfo);
          });
        }
      });
    })
  );

  passport.use(
    'local-login',
    new LocalStrategy({
      usernameField : 'email',
      passwordField : 'password',
      passReqToCallback : true
    },
    function(req, email, password, done) {
      connection.query("SELECT * FROM Account WHERE email = ?", [email], function(err, rows){
        if (err)
          return done(err);
        if (!rows.length) {
          return done(null, false, req.flash('loginMessage', 'No user found.'));
        }

        // if the user is found but the password is wrong
        if (!bcrypt.compareSync(password, rows[0].password)) {
          return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
        }

        // all is well, return successful user
        console.log(rows[0]);
        return done(null, rows[0]);
      });
    })
  );

}
