angular.module('accountCtrl', ['accountService'])

  .controller('sessCtrl', function($rootScope, $location, Account) {
    var vm = this;

    Account.isLoggedIn()
      .success(function(data) {
        if(data === 'user is not logged in') {
          vm.loggedIn = false;
        } else {
          vm.loggedIn = true;
        }
      })

    $rootScope.$on('$routeChangeStart', function() {
      Account.isLoggedIn()
        .success(function(data) {
          if(data === 'user is not logged in') {
            vm.loggedIn = false;
          } else {
            vm.loggedIn = true;
          }
        })
    })

    vm.logout = function() {
      Account.logout()
        .success(function(data) {
          console.log(data);
          $location.url('/thanks');
        })
    };

  })

  .controller('createAccountCtrl', function($location, Account) {
    var vm = this;

    vm.createAccount = function() {
      Account.signup(vm.userData)
        .success(function(data) {
          $location.url('/dashboard');
        });
    }

  })

  .controller('loginCtrl', function($location, Account) {
    var vm = this;

    vm.login = function() {
      Account.login(vm.userData)
        .success(function(data) {
          $location.url('/dashboard');
        });
    }
  });
