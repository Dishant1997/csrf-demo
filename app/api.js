var express = require('express');
var mysql= require('mysql');

module.exports = function(app) {

  var api = express.Router();

  api.route('/test')
    .get((req, res) => {
      res.send('HTTP GET works!');
    })
    .post((req, res) => {
      res.send('HTTP POST works');
    });

  return api;
};
