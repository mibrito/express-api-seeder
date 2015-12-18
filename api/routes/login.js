var Promise = require('bluebird');
var _ = require('lodash');

// routes helpers
// var R = require('../lib/routes/Responses');
// var build = require('../lib/routes/BuildRequestFunction');
// var AccessControl = require('../lib/routes/AccessControl');
//
// // database
// var db = require('../lib/database/').initDB();
// var User = db.models.User;
// var UserGroup = db.models.UserGroup;
// var Twitter = db.models.Twitter;
// var UserAggregatedScore = db.models.UserAggregatedScore;
// var ThemeGroupPromotion = db.models.ThemeGroupPromotion;
// var Theme = db.models.Theme;

var router = require('express').Router();
router.use(AccessControl.context('anonymous'));

router.post(
    '/signin'
    ,function (req, res, next){
      if( !req.body.username || !req.body.password ){
        res.status(500);
        next(new Error('Missing username or password'));
      }else{
        User.findOne({where: {username: req.body.username}})
          .then(function(user){
            if(user && user.verifyPassword(req.body.password)){
              return user.generateToken()
                .then(function(token){
                  user = user.toJSON();

                  return AddUserToGroup(user)
                    .then(function(){
                      res.status(200).json(_.omit(_.merge(user, token), 'password'));
                    });
                });
            }else{
              res.status(400);
              next(new Error('Incorrect username or password'));
            }
          })
        .catch(function(err){
          res.status(500);
          next(err);
        });
      }
    }
);

module.exports = router;
