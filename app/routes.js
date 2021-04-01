var mysql = require('mysql');
var csrf = require('../csrfDefenseLibrary/index');
var bodyParser = require('body-parser');
var path = require('path');
var config = require('../config/config');

var connection = mysql.createConnection({
  host: config.host,
  user: config.user,
  password: config.password,
  database: config.mysqldb
});

connection.connect();

var csrfProtection = csrf({ cookie: true });
// console.log("CSRF PROTECTION", csrfProtection)
var parseForm = bodyParser.urlencoded({ extended: false });

module.exports = function (app, passport) {

  app.get('/', (req, res) => {
    res.sendFile(path.join(`${__dirname}/../public/app/views/index.html`));
  });

  app.post('/signup', passport.authenticate('local-signup'), (req, res) => {
    delete req.user.password;
    console.log(req.user);
    res.json(req.user);
  });

  app.post('/login', passport.authenticate('local-login'), (req, res) => {
    delete req.user.password;
    console.log(req.user);
    if (req.body.remember) {
      req.session.cookie.maxAge = 1000 * 60 * 3;
    } else {
      req.session.cookie.expires = false;
    }
    res.json(req.user);
  });

  app.get('/user', (req, res) => {
    if (req.user) {
      delete req.user.password;
      console.log(req.user);
      res.json(req.user);
    } else {
      res.send('user is not logged in');
    }

  });

  app.post('/send', (req, res) => {
    // create connection and transfer money
    var from = req.query.from;
    var to = req.query.to;
    var amount = Number(req.query.amount).toFixed(2);

    connection.query(`SELECT * from Account WHERE email = '${from}'`, (err, rows) => {
      console.log("ROWS:", rows);
      if (rows == "") {
        res.json(rows);
      } else {

        connection.query(`INSERT INTO Transaction (toAccount, fromAccount, amount) VALUES ('${to}', '${from}', ${amount});`, (err, rows) => {

          connection.query(`UPDATE Account SET money = money - ${amount} WHERE email = '${from}'`, (err, rows) => {

            connection.query(`UPDATE Account SET money = money + ${amount} WHERE email = '${to}';`, (err, rows) => {

            })
          })
        })
      }
    });

    res.send(`$${req.query.amount} sent to ${req.query.to}`);
  })

  app.get('/csrfToken', csrfProtection, isLoggedIn, (req, res) => {
    res.json({
      csrfToken: req.csrfToken()
    });
  });

  app.post('/send-v2', parseForm, csrfProtection, (req, res) => {
    var from = req.query.from;
    var to = req.query.to;
    var amount = Number(req.query.amount).toFixed(2);
    console.log(req.query);
    connection.query(`INSERT INTO Transaction (toAccount, fromAccount, amount) VALUES ('${to}', '${from}', ${amount});`, (err, rows) => {
      if (err) throw err;

      connection.query(`UPDATE Account SET money = money - ${amount} WHERE email = '${from}'`, (err, rows) => {
        if (err) throw err;

        connection.query(`UPDATE Account SET money = money + ${amount} WHERE email = '${to}';`, (err, rows) => {
          if (err) throw err;

        })
      })
    });
    res.send(`$${req.query.amount} sent to ${req.query.to}`);
  });

  app.get('/logout', (req, res) => {
    req.logout();
    res.send('bye');
  });

};

// route middleware to make sure
function isLoggedIn(req, res, next) {

  // if user is authenticated in the session, carry on
  if (req.isAuthenticated())
    return next();

  // if they aren't redirect them to the home page
  res.redirect('/');
}
