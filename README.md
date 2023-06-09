
<img alt="logo" src="src\main\resources\cinema-logo.png" width="400px">

<h1 style="color: cornflowerblue; align-self: auto">Cinema-App</h1>

This web application has been developed for educational and demonstration objectives, aiming to simulate a cinema's ticket reservation system. Users can utilize the application to register and log in using their personal credentials. Furthermore, the application offers role-based authorization, distinguishing between administrators and regular users.

# Functionality
- Session-based authentication, encrypted password storing in DB;
- Role-based authorization (admin, user);
- Separated access to endpoints for different roles;
- Admin tools: get customer info, add movies, cinema halls, manage movie sessions;
- Full customer cycle: register, obtain shopping cart, add tickets on movie session, complete order.

# How it works
`REMARK! When starting the application, two default users are already injected into the database, use them:`

| Role  | Username   | Password |
|-------|------------|----------|
| Admin | admin@i.ua | admin123 |
| User  | user@i.ua  | user123  |

- Clone [this](https://github.com/NickolayVoloshchuk/cinema-app.git) repository;
- Replace the appropriate fields in the `src\main\resources\db.properties` file to access your database;
  - Change the `YOUR_USERNAME` and `YOUR_PASSWORD` to your own, if you will use MySql;
  - Or change all properties to your another DB.
- Build the project. Use `mvn clean package`;
- Deploy the generated cinema-app.war image with servlet container such as `Tomcat`;
- Use [my Postman collection](https://www.postman.com/spacecraft-astronomer-48290803/workspace/cinema-app/collection/27159960-e364c4f1-59c9-46b1-a0e5-957bd2f05359?action=share&creator=27159960) for easy communication with program or use endpoints, here is map of endpoints:
  - `POST` `/register` - register new user (`non-auth access`);
  - `GET` `/movie-sessions/available` - get list of sessions (`USER`, `ADMIN`);
  - `GET` `/cinema-halls` - get list of halls (`USER`, `ADMIN`);
  - `GET` `/users/by-email` - retrieve user's info (`ADMIN`);
  - `POST`: `/cinema-halls` ,`/movies`, `/movie-sessions` - create corresponding objects (`ADMIN`);
  - `PUT`, `DELETE` `/movie-sessions` - update and delete movie session (`ADMIN`);
  - `GET` `/orders` `/shopping-carts/by-user` - show history of orders, list of tickets in cart (`USER`);
  - `PUT` `/shopping-carts/movie-sessions` - put a ticket on this movie session to the cart (`USER`);
  - `POST` `/orders/complete` - execute order (`USER`).

All endpoints send and receive JSON data, except for the login page, which is generated by Spring Security. Almost all endpoints are secured by role-based authorization. More details can be found in the `SecurityConfig` class.

If you still have any questions, watch [this video tutorial]()

# Project structure:
- `config` stores Spring configuration;
- `controller` controllers for endpoints;
- `dao` data access layer (repository) that calls CRUD methods in the database;
- `dto` data transfer objects - wrapper for model objects to unify the requests and responses in controllers;
- `exception` custom exception;
- `lib` contains custom email and password validators with its annotations;
- `model` contains models for the database;
- `security` contains custom `UserDetailsService`;
- `service` contains services that call repositories and the Authentication class;
  - `mapper` converts model objects to DTO objects;
- `resources` contains configuration file with JDBC and Hibernate params and other tmp.

# DB structure:
<img alt="db-schema" src="src\main\resources\cinema-db-schema.png" width="800px">

# Stack and versions
- Java `17`
- Maven `3.9.1`
- Spring `5.3.20`
- Spring Security `5.6.10`
- Hibernate `5.6.14.Final`
- Hibernate Validator `6.1.6.Final`
- MySql Connector `8.0.22`
- Javax Servlets `4.0.1`
- Javax Annotations `1.3.2`
- Tomcat `9.0.73`

# My contacts:

[nk.voloshchuk@gmail.com](mailto:nk.voloshchuk@gmail.com)

[Skype](https://join.skype.com/invite/HNejCfYluDKx)

[Telegram](https://t.me/proxyKossack)

# Author

Mykola Voloshchuk
[GitHub](https://github.com/NickolayVoloshchuk)
