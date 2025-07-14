const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

const path = require("path");

const app = express();
const db = new sqlite3.Database("./users.db");

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "mySecretKey",
    resave: false,
    saveUninitialized: false,
  })
);

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT
)`);

// Create employees table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT,
  position TEXT,
  department TEXT,
  salary REAL
)`);

// Create products table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  price REAL,
  image TEXT
)`);

// Routes
app.get("/", (req, res) => {
  if (req.session.username) {
    res.send(`Welcome ${req.session.username}! <a href="/logout">Logout</a>`);
  } else {
    res.send('<a href="/login">Login</a> or <a href="/register">Register</a>');
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
    if (err) return res.send("Error registering user.");
    res.redirect("/login");
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.send("User not found.");
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.username = username;
      res.redirect("/");
    } else {
      res.send("Incorrect password.");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Middleware to protect employee routes
function isAuthenticated(req, res, next) {
  if (req.session.username) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Show all employees
app.get("/employees", isAuthenticated, (req, res) => {
  db.all("SELECT * FROM employees", (err, rows) => {
    if (err) return res.send("Error loading employees.");
    res.render("employees", { employees: rows });
  });
});

// Show form to add employee
app.get("/employees/add", isAuthenticated, (req, res) => {
  res.render("addEmployee");
});

// Handle new employee form
app.post("/employees/add", isAuthenticated, (req, res) => {
  const { name, email, position, department, salary } = req.body;
  db.run(
    "INSERT INTO employees (name, email, position, department, salary) VALUES (?, ?, ?, ?, ?)",
    [name, email, position, department, salary],
    (err) => {
      if (err) return res.send("Error adding employee.");
      res.redirect("/employees");
    }
  );
});

// Show form to edit employee
app.get("/employees/edit/:id", isAuthenticated, (req, res) => {
  const id = req.params.id;
  db.get("SELECT * FROM employees WHERE id = ?", [id], (err, row) => {
    if (err || !row) return res.send("Employee not found.");
    res.render("editEmployee", { employee: row });
  });
});

// Handle update
app.post("/employees/edit/:id", isAuthenticated, (req, res) => {
  const id = req.params.id;
  const { name, email, position, department, salary } = req.body;
  db.run(
    "UPDATE employees SET name=?, email=?, position=?, department=?, salary=? WHERE id=?",
    [name, email, position, department, salary, id],
    (err) => {
      if (err) return res.send("Error updating employee.");
      res.redirect("/employees");
    }
  );
});

// Delete employee
app.get("/employees/delete/:id", isAuthenticated, (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM employees WHERE id = ?", [id], (err) => {
    if (err) return res.send("Error deleting employee.");
    res.redirect("/employees");
  });
});

// Show all products
app.get("/products", isAuthenticated, (req, res) => {
  db.all("SELECT * FROM products", (err, rows) => {
    if (err) return res.send("Error loading products.");
    res.render("products", { products: rows });
  });
});


// Show form to add product
app.get("/products/add", isAuthenticated, (req, res) => {
  res.render("addProduct");
});


// ✅ INSERT THIS BELOW:
app.post("/products/add", isAuthenticated, (req, res) => {
  const { name, description, price, image } = req.body;
  db.run(
    "INSERT INTO products (name, description, price, image) VALUES (?, ?, ?, ?)",
    [name, description, price, image],
    (err) => {
      if (err) {
        console.error(err);
        return res.send("Error adding product.");
      }
      res.redirect("/products");
    }
  );
});

app.get("/test", (req, res) => {
  res.send("✅ TEST ROUTE WORKS");
});


app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
