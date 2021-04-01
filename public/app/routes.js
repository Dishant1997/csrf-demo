angular.module('routes', ['ngRoute'])

  .config(['$routeProvider', '$locationProvider', ($routeProvider, $locationProvider) => {
    $routeProvider
      .when('/', {
        templateUrl: 'app/views/pages/home.html'
      })
      .when('/login', {
        templateUrl: 'app/views/pages/login.html',
        controller: 'loginCtrl',
        controllerAs: 'login'
      })
      .when('/signup', {
        templateUrl: 'app/views/pages/signup.html',
        controller: 'createAccountCtrl',
        controllerAs: 'account'
      })
      .when('/dashboard', {
        templateUrl: 'app/views/pages/dashboard.html',
        controller: 'dashCtrl',
        controllerAs: 'dash'
      })
      .when('/transfer', {
        templateUrl: 'app/views/pages/transfer.html',
        controller: 'sendMoneyCtrl',
        controllerAs: 'money'
      })
      .when('/transfer-v2', {
        templateUrl: 'app/views/pages/transfer-v2.html',
        controller: 'csrfCtrl',
        controllerAs: 'money'
      })
      .when('/attack', {
        templateUrl: 'app/views/pages/attack.html',
        controller: 'sendMoneyCtrl',
        controllerAs: 'money'
      })
      .when('/thanks', {
        templateUrl: 'app/views/pages/thanks.html'
      })

    $locationProvider.html5Mode(true);
  }]);
