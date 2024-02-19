# @scor32k/auth - Simple Auth. Package 🍕

An simple authentication package designed to simplify authentication processes in your projects.

## Usage

### 1. Install Package

```bash
npm install @scor32k/auth
```

### 2. Implement Authentication

Create an authentication middleware file in your project's `config` directory. Follow these steps or you can invent your own:

```bash
cd %PROJECT_BASE%
mkdir config && cd config
vim auth.middleware.js
```

In `auth.middleware.js`, set up authentication with a JWT secret:

```js
const Auth = require("@scor32k/auth");
const auth = new Auth();
auth.setToken("jwt-secret");

// commonjs
module.exports = auth;
```

### 3. Add Authentication Middleware

Apply authentication to all endpoints using the middleware:

```js
const auth = require("path/to/auth.middleware");

app.use((req, res, next) => {
  auth.authenticate(req, res, next);
});
```

### 4. Implement Authorization

Note: Authentication is required before authorization. Ensure the token includes a `role` key, for example of login token precess:

```js
let user = {
  id: 1,
  name: "abhishek",
  role: "ADMIN",
};

let authtoken = jwt.sign(user, "jwt-secret");
```

Specify roles as an array of strings in `auth.allow`:

```js
const auth = require("path/to/auth.middleware");

app.post("/getMoney", auth.allow(["ADMIN"]), (req, res) => {
  try {
    console.log(req.user);
    // Your protected logic here
  } catch (error) {
    console.log("Error: ", error);
  }
});
```

Or you can use numbers too.

Ensure consistency between the format of roles specified in the token and the `auth.allow` method. If roles are in string format, use an array of strings; if roles are in number format, use an array of numbers.

---

### Contribution
Feel free to contribute by submitting issues, feature requests, or even pull requests. Your contributions are highly valued!

Happy coding! 🚀