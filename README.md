This is a simple web application I built for my Secure Web Apps class. There are two branches in this repository - csrf and anti-csrf.

The csrf branch allow vulnerability attacks by sending a HTTP POST request to /send

/send?amount=100&from=asdf@asdf.com&to=email@asdf.com

The anti-csrf branch will not allow the above request to go through because the endpoint will require a CSRF Token, which can only be attainable by a logged in user from a separate endpoint.

In order to use the app, go to the terminal and run

git clone -b csrf https://github.com/jonathandiep/CSRF-Demo.git

and

git clone -b anti-csrf https://github.com/jonathandiep/CSRF-Demo.git

Import the SQL file into mysql database (not included yet)

Start the Node server by running

node index.js
