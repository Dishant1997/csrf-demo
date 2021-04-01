var express = require('express');
var session = require('express-session');
var app = express();
var mysql = require('mysql');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var morgan = require('morgan');
var passport = require('passport');
var path = require('path');
var config = require('./config/config');

var connection = mysql.createConnection({
  host: config.host,
  user: config.user,
  password: config.password,
  database: config.mysqldb
});

connection.connect();

require('./config/passport')(passport);


app.use(morgan('dev'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// configure app to handle CORS requests
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
  next();
});

// required for passport
app.use(session({
	secret: 'supersecrettosignsessionidcookie',
	resave: true,
	saveUninitialized: true
 } )); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions

app.use(express.static(`${__dirname}/public`));

// API routes
var apiRoutes = require('./app/api')(app);
app.use('/api', apiRoutes);

require('./app/routes')(app, passport);



// catchall route (send users to Angular frontend)
app.get('*', (req, res) => {
  res.sendFile(path.join(`${__dirname}/public/app/views/index.html`));
});

app.listen(config.port);
console.log(`Working on port ${config.port}`);
