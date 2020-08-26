const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
//User model
const User = require('../models/User');
const { Passport } = require('passport');

//LOGIN PAGE
router.get('/login', (req,res)=> res.render('login'));

//REGISTER PAGE
router.get('/registration', (req,res)=> res.render('registration'));

//REGISTER HANDLE
router.post('/registration', (req, res) =>{
    const {name , email ,password , password2} = req.body;
    let errors =[];

    //Check required fields
    if(!name || !email || !password || !password2){
        errors.push({msg : 'Please fill in all details'});
    }

    //Check passwords match
    if(password!=password2){
        errors.push({msg: 'Passwords do not match'});
    }
    //Check password length
    if(password.length < 6){
        errors.push({msg: 'Password should be atleast 6 characters'});
    }

    if(errors.length > 0){
      res.render('registration',{
          errors,
          name,
          email,
          password,
          password2
      });

    } else {
        //Validation passed
      User.findOne({ email: email})
      .then(user =>{
        if(user) {
           //User exists
            errors.push({msg: 'Email is already registered'});

            res.render('registration',{
             errors,
             name,
             email,
             password,
             password2
            });
  
        } else {

        const newUser= new User({
            name, 
            email,
            password
          });

          //Hash password..no of character
          bcrypt.genSalt(10, (err, salt)=>
          bcrypt.hash(newUser.password, salt, (err, hash)=>{
              if(err) throw err;
// set password to has
              newUser.password= hash;
// save user
              newUser.save()
              .then(user=>{
              req.flash('success_msg', 'You are now registered nd can login');
               res.redirect('/users/login');
           })
           .catch(err => console.log(err));

          }))

          }

  });

 }

});

//Login Handle
router.post('/login', (req, res, next) => {
 passport.authenticate('local',{
     successRedirect: '/dashboard',
     failureRedirect: './users/login',
     failureFlash: true
 })(req, res , next);

});

//logout handle
router.get('/logout', (req, res) =>{
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
})
module.exports = router;