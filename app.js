var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var passport = require('passport');
var config = require('./config/database');
var indexRouter = require('./routes/index');
var mongoose = require('mongoose');
var app = express();
var cors = require('cors')
var morgan = require('morgan');
require('dotenv').config();


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use(morgan('combined'));
app.use(cors())
app.use(passport.initialize());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
mongoose.connect(config.database, { 
  useUnifiedTopology: true,
  useNewUrlParser: true
});
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});


app.use('/', indexRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  res.send('Error 404');
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.json(err)
});

module.exports = app;
