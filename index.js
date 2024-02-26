const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const dotenv = require("dotenv");
const app = express();

dotenv.config();

const port = process.env.PORT;

const conn = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static(__dirname + "/public"));
app.use(
  session({
    secret: "your_secret_key",
    resave: true,
    saveUninitialized: true,
  })
);

app.get("/", (req, res) => {
  res.render("login");
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/register", (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  if (!name || !email || !password || !confirmPassword) {
    return res.render("register", { error: "Please fill in all fields" });
  }

  if (password !== confirmPassword) {
    return res.render("register", {
      error: "Password and Confirm Password do not match",
    });
  }

  conn.query(
    "SELECT * FROM Register WHERE email = ?",
    email,
    function (err, result) {
      if (err) {
        console.log("ERROR:", err);
        res.render("register", {
          error: "An error occurred during registration",
        });
      } else {
        if (result.length === 0) {
          bcrypt.hash(password, 10, function (err, hash) {
            if (err) {
              console.log("ERROR:", err);
              res.render("register", {
                error: "An error occurred during registration",
              });
            } else {
              conn.query(
                "INSERT INTO Register (name, email, password) VALUES (?, ?, ?)",
                [name, email, hash],
                function (err, result) {
                  if (err) {
                    console.log("ERROR:", err);
                    res.render("register", {
                      error: "An error occurred during registration",
                    });
                  } else {
                    console.log("Inserted " + result.affectedRows + " row");
                    res.redirect("/login");
                  }
                }
              );
            }
          });
        } else {
          res.render("register", {
            error: "User with the same email already exists",
          });
        }
      }
    }
  );
});

app.post("/login", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.render("login", { error: "Please fill in all fields" });
  }

  conn.query(
    "SELECT * FROM Register WHERE email = ?",
    email,
    function (err, result) {
      if (err) {
        console.log("ERROR:", err);
        res.render("login", { error: "An error occurred during login" });
      } else {
        if (result.length > 0) {
          const hash = result[0].password;
          bcrypt.compare(password, hash, function (err, isValid) {
            if (isValid) {
              req.session.userEmail = email;
              res.redirect("/profile");
            } else {
              res.render("login", { error: "Invalid login credentials" });
            }
          });
        } else {
          res.render("login", { error: "User not found" });
        }
      }
    }
  );
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.get("/changepassword", (req, res) => {
  res.render("changepassword", { error: null });
});

app.post("/change-password", (req, res) => {
  const email = req.session.userEmail; // Get the user's email from the session
  const currentPassword = req.body.currentPassword;
  const newPassword = req.body.newPassword;
  const confirmNewPassword = req.body.confirmNewPassword;

  if (!currentPassword || !newPassword || !confirmNewPassword) {
    return res.render("changepassword", { error: "Please fill in all fields" });
  }

  if (newPassword !== confirmNewPassword) {
    return res.render("changepassword", {
      error: "New Password and Confirm New Password do not match",
    });
  }

  conn.query(
    "SELECT * FROM Register WHERE email = ?",
    email,
    function (err, result) {
      if (err) {
        console.log("ERROR:", err);
        res.render("changepassword", {
          error: "An error occurred during password change",
        });
      } else {
        if (result.length > 0) {
          const hash = result[0].password;
          bcrypt.compare(currentPassword, hash, function (err, isValid) {
            if (isValid) {
              bcrypt.hash(newPassword, 10, function (err, newHash) {
                if (err) {
                  console.log("ERROR:", err);
                  res.render("changepassword", {
                    error: "An error occurred during password change",
                  });
                } else {
                  conn.query(
                    "UPDATE Register SET password = ? WHERE email = ?",
                    [newHash, email],
                    function (err, updateResult) {
                      if (err) {
                        console.log("ERROR:", err);
                        res.render("changepassword", {
                          error: "An error occurred during password change",
                        });
                      } else {
                        console.log("Password changed successfully.");
                        res.redirect("/login"); // Redirect to the login page
                      }
                    }
                  );
                }
              });
            } else {
              res.render("changepassword", {
                error: "Invalid current password",
              });
            }
          });
        } else {
          res.render("changepassword", { error: "User not found" });
        }
      }
    }
  );
});

app.get("/profile", (req, res) => {
  // Retrieve the user's email from the session
  const userEmail = req.session.userEmail;

  if (userEmail) {
    conn.query(
      "SELECT name FROM Register WHERE email = ?",
      userEmail,
      (err, result) => {
        if (err) {
          console.error("Error querying the database:", err);
          res.render("profile", {
            yourname: "Error retrieving name",
            youremail: userEmail,
          });
        } else {
          if (result.length > 0) {
            const userName = result[0].name;
            res.render("profile", { yourname: userName, youremail: userEmail });
          } else {
            res.render("profile", {
              yourname: "User not found",
              youremail: userEmail,
            });
          }
        }
      }
    );
  } else {
    // User's email is not available in the session; handle the case as needed
    res.render("profile", {
      yourname: "User email not found",
      youremail: "No email available",
    });
  }
});

app.post("/weight", (req, res) => {
  const userEmail = req.session.userEmail;
  const weight = req.body.weight;
  const entryDate = req.body.entryDate;

  if (!userEmail) {
    return res.redirect("/login"); // Redirect to the login page if not logged in
  }

  if (!weight || !entryDate) {
    return res.render("weight", {
      error: "Please fill in both weight and date fields",
    });
  }

  // Save the weight entry to the database, associating it with the logged-in user
  conn.query(
    "INSERT INTO WeightEntries (user_id, weight, entryDate) VALUES ((SELECT id FROM Register WHERE email = ?), ?, ?)",
    [userEmail, weight, entryDate],
    (err, result) => {
      if (err) {
        console.log("ERROR:", err);
        return res.render("weight", {
          error: "An error occurred while saving the weight entry",
        });
      }

      console.log("Weight entry saved successfully.");
      res.redirect("/planner");
    }
  );
});

app.post("/exercises", (req, res) => {
  const exerciseType = req.body.exerciseType;
  const exerciseDate = req.body.exerciseDate;
  const exerciseDuration = req.body.exerciseDuration;
  const exerciseRepetitions = req.body.exerciseRepetitions;
  const userEmail = req.session.userEmail; // Get the user's email from the session

  if (!userEmail) {
    return res.redirect("/login"); // Redirect to the login page if not logged in
  }

  if (
    !exerciseType ||
    !exerciseDate ||
    !exerciseDuration ||
    !exerciseRepetitions
  ) {
    return res.render("exercises", { error: "Please fill in all fields" });
  }

  // Save the exercise to the database, associating it with the logged-in user
  conn.query(
    "INSERT INTO Exercises (exerciseType, exerciseDate, durationMinutes, repetitions, userId) VALUES (?, ?, ?, ?, (SELECT id FROM Register WHERE email = ?))",
    [
      exerciseType,
      exerciseDate,
      exerciseDuration,
      exerciseRepetitions,
      userEmail,
    ],
    (err, result) => {
      if (err) {
        console.log("ERROR:", err);
        return res.render("exercises", {
          error: "An error occurred while saving the exercise",
        });
      }

      console.log("Exercise saved successfully.");
      // Redirect to a success page or back to the exercises page as needed.
      res.redirect("/exercises");
    }
  );
});

app.get("/exercises", (req, res) => {
  // Retrieve exercises from the database, formatting the date
  const query = `
        SELECT
            id,
            exerciseType,
            DATE_FORMAT(exerciseDate, '%d/%m/%Y') AS formattedExerciseDate,
            durationMinutes,
            repetitions
        FROM Exercises
        WHERE userId = (SELECT id FROM Register WHERE email = ?)
    `;

  conn.query(query, req.session.userEmail, (err, results) => {
    if (err) {
      console.error("Error querying the database:", err);
      res.render("exercises", {
        error: "An error occurred while retrieving exercises",
        exercises: [],
      });
    } else {
      // Pass the exercises to the template
      res.render("exercises", { error: null, exercises: results });
    }
  });
});

app.post("/delete-exercise/:id", (req, res) => {
  const exerciseId = req.params.id;
  const userEmail = req.session.userEmail;

  if (!userEmail) {
    return res.redirect("/login"); // Redirect to the login page if not logged in
  }

  // Check if the exercise with the given ID belongs to the logged-in user
  const query = `
        DELETE FROM Exercises
        WHERE id = ? AND userId = (SELECT id FROM Register WHERE email = ?)
    `;

  conn.query(query, [exerciseId, userEmail], (err, result) => {
    if (err) {
      console.error("Error deleting exercise:", err);
      return res.redirect("/exercises"); // Redirect back to the exercises page
    }

    console.log("Exercise deleted successfully.");
    res.redirect("/exercises"); // Redirect back to the exercises page
  });
});

app.post("/update-exercise/:id", (req, res) => {
  const exerciseId = req.params.id;
  const userEmail = req.session.userEmail;

  if (!userEmail) {
    return res.redirect("/login"); // Redirect to the login page if not logged in
  }

  const updatedExerciseType = req.body.exerciseType;
  const updatedExerciseDate = req.body.exerciseDate;
  const updatedExerciseDuration = req.body.exerciseDuration;
  const updatedExerciseRepetitions = req.body.exerciseRepetitions;

  if (
    !updatedExerciseType ||
    !updatedExerciseDate ||
    !updatedExerciseDuration ||
    !updatedExerciseRepetitions
  ) {
    return res.render("exercises", {
      error: "Please fill in all fields for the update",
    });
  }

  // Check if the exercise with the given ID belongs to the logged-in user
  const query = `
        UPDATE Exercises
        SET exerciseType = ?, exerciseDate = ?, durationMinutes = ?, repetitions = ?
        WHERE id = ? AND userId = (SELECT id FROM Register WHERE email = ?)
    `;

  conn.query(
    query,
    [
      updatedExerciseType,
      updatedExerciseDate,
      updatedExerciseDuration,
      updatedExerciseRepetitions,
      exerciseId,
      userEmail,
    ],
    (err, result) => {
      if (err) {
        console.error("Error updating exercise:", err);
        return res.redirect("/exercises"); // Redirect back to the exercises page
      }

      console.log("Exercise updated successfully.");
      res.redirect("/exercises"); // Redirect back to the exercises page
    }
  );
});

app.get("/weight", (req, res) => {
  res.render("weight", { error: null });
});

app.get("/planner", (req, res) => {
  res.render("planner", { error: null });
});

app.get("/workouts", (req, res) => {
  res.render("workouts", { error: null });
});

app.get("/progress", (req, res) => {
  // Retrieve exercises from database
  const exerciseQuery = `
        SELECT
            e.id,
            e.exerciseType,
            DATE_FORMAT(e.exerciseDate, '%m/%d/%Y') AS formattedExerciseDate,
            e.durationMinutes,
            e.repetitions,
            r.name
        FROM Exercises AS e
        JOIN Register AS r ON e.userId = r.id
        WHERE e.userId = (SELECT id FROM Register WHERE email = ?)`;

  conn.query(exerciseQuery, req.session.userEmail, (err, exerciseResults) => {
    if (err) {
      console.error("Error querying the database for exercises:", err);
      res.render("progress", {
        error: "An error occurred while retrieving exercises",
        exercises: [],
        weights: [],
      });
    } else {
      // Retrieve weight entries for the user
      const weightQuery = `
                SELECT
                    user_id,
                    weight,
                    DATE_FORMAT(entryDate, '%m/%d/%Y') AS formattedWeightDate
                FROM WeightEntries
                WHERE user_id = (SELECT id FROM Register WHERE email = ?)`;

      conn.query(weightQuery, req.session.userEmail, (err, weightResults) => {
        if (err) {
          console.error("Error querying the database for weight entries:", err);
          res.render("progress", {
            error: "An error occurred while retrieving weight entries",
            exercises: [],
            weights: [],
          });
        } else {
          // Pass both exercise and weight results to the template
          res.render("progress", {
            error: null,
            exercises: exerciseResults,
            weights: weightResults,
          });
        }
      });
    }
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// CREATE TABLE Register (
//   id INT AUTO_INCREMENT PRIMARY KEY,
//   name VARCHAR(255) NOT NULL DEFAULT 'NONE',
//   email VARCHAR(255) NOT NULL DEFAULT 'NONE',
//   password VARCHAR(255) NOT NULL DEFAULT 'NONE'
// );

// CREATE TABLE WeightEntries (
//   id INT AUTO_INCREMENT PRIMARY KEY,
//   user_id INT,
//   weight DECIMAL(5, 2),
//   entryDate DATE,
//   FOREIGN KEY (user_id) REFERENCES Register(id)
// );

// CREATE TABLE Exercises (
//   id INT AUTO_INCREMENT PRIMARY KEY,
//   exerciseType VARCHAR(255),
//   exerciseDate DATE,
//   durationMinutes INT,
//   repetitions INT,
//   userId INT,
//   FOREIGN KEY (userId) REFERENCES Register(id)
// );
