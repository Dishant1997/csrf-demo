angular.module('dashboardCtrl', [])

  .controller('dashCtrl', function(Account) {
    var vm = this;

    Account.accountDetails()
      .success(function(data) {
        vm.user = data;
      });
  });
