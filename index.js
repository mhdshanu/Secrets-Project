import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import dotenv from "dotenv";
import GoogleStrategy from "passport-google-oauth2";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;
const { Pool } = pg;
const connectionString = process.env.DATABASE_URL;


app.use(bodyParser.urlencoded({ extended: true }));   
app.use(express.static("public"));

app.use(session ({   /* Configures the Express session middleware with a secret key, which is used to sign the session ID cookie. 
  resave: Determines whether the session should be saved back to the session store, even if it hasn't been modified during the request.
  saveUnitialized: Determines whether a session should be created for an uninitialized (new) session.*/
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true, //Now session is created
  cookie: {maxAge: 1000*60*60*24}, //Equivalent to 1 day. It is optional. By default, until browser is closed, cookies will be prevailed.
}));

app.use(passport.initialize());  
app.use(passport.session());
//Initializes Passport and sets it up to use sessions for authentication.


const db = new Pool({
  connectionString: connectionString,
  ssl: {
    rejectUnauthorized: false, // This line may be necessary for some environments
  },
});

db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", async(req, res)=>{       /* Checks if the user is authenticated using Passport's isAuthenticated() method.
                                          If authenticated, renders the secrets page; otherwise, redirects to the login page. */
  if(req.isAuthenticated()){  
    

     //TODO: Update this to pull in the user secret to render in secrets.ejs

     try{
      const result = await db.query("SELECT secrets FROM authentication WHERE username = $1", [req.user.username])
      const secret = result.rows[0].secrets;
      console.log(secret);
      if(secret){
        res.render("secrets.ejs", {secret: secret});
      }else{
        res.render("secrets.ejs", {secret: "Write your Secret..."});
      }

     }catch(err){
      console.log(err);
     }

  }
  else{
    res.redirect("/login");
  }
})

//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.

app.get("/submit", (req, res)=>{
  if(req.isAuthenticated){
    res.render("submit.ejs");
  }
  else{
    res.render("/login");
  }
})

app.post("/submit", async (req, res)=>{
  const secret = req.body.secret;
  console.log(req.user);
  
  try{
    await db.query("UPDATE authentication SET secrets = $1 WHERE username = $2", [secret, req.user.username]);
    res.redirect("/secrets")
  }catch(err){
    console.log(err);
    res.redirect("/submit");
  }
})


app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}))

app.get("/logout", (req, res)=>{
  req.logout((err)=>{
    if(err){
      console.log(err);
    }
    else{
      res.redirect("/");
    }
  })
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM authentication WHERE username = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO authentication (username, password) VALUES ($1, $2) RETURNING *",[email, hash]
          ); // Now we returned the value and stored it on result
           // (Extra added from last version)
            
          const user = result.rows[0];
          req.login(user, (err)=>{  //insted of res.render("/secrets", add this)
          console.log(err)
          res.redirect("/secrets");
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);


//Registering strategy which is imported above.
passport.use(
  new Strategy(async function verify(username, password, cb) { 
    // Defines a new Passport local strategy for authenticating users.
    // The strategy's verify function is called with the provided username and password.
    // It queries the database to find the user by email and compares the hashed password.
    try {
      const result = await db.query("SELECT * FROM authentication WHERE username = $1", [
        username,  // use the same name for username as in index.ejs
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err); // report error using passport
          } else {
            if (result) {
              return cb(null, user); // instead of just rendering secrets.ejs, user gives details of the actual user which is defined in "/register" route.
            } else {
              return cb(null, false); // null means no error is to be passed
            }
          }
        });
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => {  /* passport.serializeUser: is a function provided by Passport that determines which data of the user 
object should be stored in the session. Once you've determined what data to store, you call the callback cb with null (to indicate that there's 
no error) and the data you want to store. */
  cb(null, user);
});
passport.deserializeUser((user, cb) => {  /* passport.deserializeUser: is a function provided by Passport that retrieves the data stored in the 
  session and converts it into a user object.Once you've retrieved the user object, you call the callback cb with null (to indicate that there's 
  no error) and the user object. */
  cb(null, user);
});

passport.use(
  "google",
  new GoogleStrategy(   //google is the type of strategy we care using. We can name all strtegies like google, local strategy for local ones
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      // Add your logic to handle the Google profile here, such as finding or creating a user in your database.
      try{  //Adding the google data into database
        const result = await db.query("SELECT * FROM authentication WHERE username = $1", [profile.email]);  //google has sent email into profile 
        if(result.rows.length === 0){ // Not added into db yet
          const newUser = await db.query("INSERT INTO authentication(username, password) VALUES($1, $2)", [profile.email, "google"]);
          //Since there is no password sent by google, we can just set ny value into the password column
          cb(null, newUser.rows[0]) //newUser is passed, so it can serialize and deserialize
        }
        else{ // Already in db
          cb(null, result.rows[0])
        }

      }
      catch(err){
        cb(err);
      }
      
    }
  )
);



    
  


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
