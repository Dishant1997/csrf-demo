angular.module('accountService', [])

  .factory('Account', function($http) {
    var accountFactory = {};

    accountFactory.signup = function(userData) {
      return $http.post('/signup', userData);
    };

    accountFactory.accountDetails = function() {
      return $http.get('/user');
    };

    accountFactory.isLoggedIn = function() {
      return $http.get('/user')
        .success(function(data) {
          console.log(data);
          if (typeof data === 'object' && Object.keys(data).length > 0) {
            return true;
          } else {
            return false;
          }
        });
    };

    accountFactory.send = function(transactionData) {
      console.log('sending transaction data: ' + transactionData);
      return $http.get('/send', transactionData);
    };

    accountFactory.login = function(userData) {
      return $http.post('/login', userData);
    };

    accountFactory.logout = function() {
      return $http.get('/logout');
    };


    return accountFactory;
  });
