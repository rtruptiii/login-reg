const express =  require('express')
const router = express.Router();
const {ensureAuthenticated} = require('../config/auth');

//WELCOME PAGE

router.get('/', (req, res) => res.render('welcome'));

//DASHBOARD
router.get('/dashboard', ensureAuthenticated, (req, res) => 
  res.render('dashboard',{
    name: req.user.name
  }));

module.exports = router;