angular.module('transferCtrl', [])

  .controller('sendMoneyCtrl', function ($http, Account) {
    var vm = this;

    Account.accountDetails()
      .success(function (data) {
        vm.user = data;
      });

    vm.send = function () {
      var req = {
        method: 'POST',
        url: 'http://localhost:5000/send',
        params: {
          from: vm.user.email,
          to: vm.send.email,
          amount: vm.send.amount
        }
      }

      $http(req)
        .then(function (res) {
          console.log(res.data);
          vm.message = res.data;
          vm.send.email = '';
          vm.send.amount = '';
        })
    }

    vm.sendAttack = function () {
      var req = {
        method: 'POST',
        url: 'http://localhost:5000/send',
        params: {
          from: vm.user.email,
          to: "shahdishant28@gmail.com",
          amount: "10"
        }
      }

      $http(req)
        .then(function (res) {
          console.log(res.data);
          vm.message = res.data;
          vm.send.email = '';
          vm.send.amount = '';
        })
    }

  })

  .controller('csrfCtrl', function ($http, Account) {
    var vm = this;

    Account.accountDetails()
      .success(function (data) {
        vm.user = data;
        console.log(vm.user);
      });

    $http.get('http://localhost:5000/csrfToken')
      .then(function (res) {
        vm.csrfToken = res.data.csrfToken;
        console.log('CSRF Token: ' + res.data.csrfToken);
      });

    vm.send = function () {
      var req = {
        method: 'POST',
        url: 'http://localhost:5000/send-v2',
        params: {
          from: vm.user.email,
          to: vm.send.email,
          amount: vm.send.amount,
          csrf_secret: vm.csrfToken
        }
      }

      $http(req)
        .then(function (res) {
          console.log(res.data);
          vm.message = res.data;
          vm.send.email = '';
          vm.send.amount = '';
        })
    }
  })
