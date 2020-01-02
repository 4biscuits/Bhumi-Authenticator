/*
* This route handles the login, signup and forgot password functions
*/
var express = require('express');
var router = express.Router();
var User = require('../models/User');
const bcrypt = require('bcrypt-nodejs');
var passport = require('passport');
require('../config/passport')(passport);
var jwt = require('jsonwebtoken');
var mongoose = require('mongoose');
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var sgTransport = require('nodemailer-sendgrid-transport');
var config = require('../config/database');

/*
* Just a dummy endpoint to test if the server is up
*/
router.get('/', function(req, res, next) {
  res.send("Bhumi Authenticator is up and running!");
})

/*
*  Endpoint that performs user signin
*/
router.post('/signin/', function(req, res, next) {
  User.findOne({
    email:req.body.email
  }, function(err,user){
    if (err) throw err;
    if (!user){
      res.send({success: false, msg: 'Authentication failed. User not found'});
    }else{
      user.comparePassword(req.body.password, function(err, isMatch){
        if (isMatch && !err){
          var token = jwt.sign(user.toObject(), config.secret);
          res.json({success:true, token: token, msg:"Successfully logged in!"});
        }else{
          res.status(401).send({success:false, msg:'Authentication failed. Wrong password'});
        }
      })
    }
  });
});


/*
*  Endpoint that performs user signup
*/
router.post('/signup/',function(req,res,next){
  if (!req.body.email || !req.body.password){
    res.json({success:false, msg:'Please fill up stuff'});
  }else{
    User.findOne({email:req.body.email},function(err,usr){
      if (err){
        res.json({success:false, msg:"Server Hangup!"});
      }
      else if (usr != null){
        res.json({success:false, msg:"User already exists, try logging in!"});
      }else{
        var newUser = new User({
          email: req.body.email,
          password:req.body.password,
          mobile: req.body.phone,
          pin: req.body.pin,
          name: req.body.name,
          city: req.body.city
        });
        newUser.save(function(err,success){
          if(err){
            res.json({success: false, msg:'Database Hangup!'});
          }
          res.json({success:true, msg:'Successfully created new user, login now!'});
        })
      }});
  }
});

/*
* Endpoint that handles forgot password
* It takes the email, searches if the user exists
* If yes, then sends him a mail with the url appended to the secret key
*/
router.get('/forgotPassword/:email', function (req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.params.email }, function(err, user) {
        if (!user) {
          res.json({'success': false, 'msg':'This user is not registered'});
        }
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        User.update({ _id: user._id}, user, {upsert: true} , function (err, usr) {
          if (err) {
            res.send('Failed to set the random keys! '+ err);
            return;
          }
          else done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USER,
          pass: process.env.SENDGRID_PASSWORD
        }
      });
      // Create the mail contents
      var mailOptions = {
        to: req.params.email,
        from: 'support@bhumi.ngo',
        subject: 'Bhumi App Password Reset',
        text: 'Hello, \n\n'+'You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n\n' + 'Thank You'
      };

      // Send the generated mail
      smtpTransport.sendMail(mailOptions, function(err) {
        // Done sending the mail
        if (err) {
          res.json({'success':false, 'msg': 'Server hangup, please try again after sometime', 'err': err});
        } else  {
          res.json({'success': true, 'msg': 'Follow the instructions provided in the mail to reset the password'});
        }
      });
    }
    
  ], function(err) {
    if (err) return next(err);
  });
});

/*
* The endpoint for the user with the input field to reset the password
*/
router.get('/reset/:token', function(req, res) {

  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      res.render('index', {token: req.params.token, err:true, msg: "Invalid token number, please choose the latest mail to reset the password if you requested more than once"});
    }
    res.render('index', {token: req.params.token});
  });
});

/*
* The logic for password validation and update
*/
router.post('/reset/', function (req, res) {
  User.findOne({resetPasswordToken: req.body.token}, function (err, user) {
    if (err) {
      res.render('index', {token: req.body.token, err:true, msg: "Server is busy, please try again"});
    }
    else if (req.body.newpassword !== req.body.retypepassword) {
      res.render('index', {token: req.body.token, err:true, msg: "The passwords don't match!"});
    }
    else if (req.body.newpassword.length < 8) {
      res.render('index', {token: req.body.token, err:true, msg: "Password must be atleast 8 characters long"});
    }
    else {
      // Encrypt the password
      bcrypt.genSalt(10, function(err,salt){
        if (err){
          res.render('index', {token: req.body.token, err:true, msg: "Server is busy, please try again!"});
        }
        bcrypt.hash(req.body.newpassword, salt, null, function(err,hash){
          if (err){
            res.render('index', {token: req.body.token, err:true, msg: "Server is busy, please try again!"});
          }
          user.password = hash;
          user.resetPasswordExpires = null;
          user.resetPasswordToken = null;
          User.updateOne({_id: user._id}, user, {upsert:true},function(err, usr) {
            if (err) {
              res.render('index', {token: req.body.token, err:true, msg: "Server is busy, please try again!"});
            }
            res.render('index', {updated:true, msg: "Password is updated, login on the app!"});
          })
        });
      });
    }})
});

module.exports = router;
