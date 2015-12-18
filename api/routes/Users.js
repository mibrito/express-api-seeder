var Promise = require('bluebird');
var _ = require('lodash');

// routes helpers
var R = require('../lib/routes/Responses');
var build = require('../lib/routes/BuildRequestFunction');
var AccessControl = require('../lib/routes/AccessControl');

// database
var db = require('../lib/database/').initDB();
var User = db.models.User;
var Group = db.models.Group;
var UserGroup = db.models.UserGroup;

// router
var router = require('express').Router();

// middlewares
router.use(
	AccessControl.expressJwt.unless({path: ['/users/anon']}),
	AccessControl.groups.unless({path: ['/users/anon']})
);


/**
 * [verifyAsUser description]
 * @param  {[type]} req [description]
 * @param  {[type]} res [description]
 * @return {[type]}     [description]
 */

router.head('/'
	,function verifyAsUser (req, res, next){
		if(!req.params.username){
			res.status(500);
			next(new Error('Missing username'));
		}else{
			return User.scope('inAdminGroup')
			.findOne({ where: { username: req.params.username }, raw: true})
			.then(function(user){
				if(user) {
					res.status(200).send('Exists.');
				} else {
					res.status(401).send('Does not exists.');
				}
			})
			.catch(function(){
				res.status(500);
				next(new Error('Does not exists.'));
			});
		}
	}
);



router.get(
	'/one/:id'
	,function (req, res, next){
		if(!req.params.id){
			res.status(500);
			next(new Error('Missing user id'));
		}else{
			return User.getFullUser(UserGroup, Group, req.params.id)
			.then(function(user){
				if(req.user.id != user.id){
					res.status(200).json(_.omit(user, ['password', 'mapCenter', 'email']));
				}else{
					res.status(200).json(user.toJSON());
				}
			})
			.catch(function(err){
				res.status(500);
				next(err);
			});
		}
	}
);

router.put(
	'/one'
	,function updateOneAsUser (req, res, next) {
		if (!_.size(req.body)) {
			res.status(500);
			next(new Error('Missing body info'));
		} else if (res.user.id != res.body.id) {
			res.status(500);
			next(new Error('Only owner account can change its info'));
		} else {
			return User.findOne({ where:{ id: req.body.id }})
			.then(function(user){
				if(!user){
					res.status(500);
					next(new Error('User does not exists'));
				} else if (req.body.password != user.password) {
					req.body.password = User.bcryptPassword(req.body.password);
				
					_.assign(user, _.omit(req.body, ['id', 'createdAt', 'updatedAt', 'deletedAt', 'mapCenter']));

					return user.save()
					.then(function(rtn){
						res.status(200).json(rtn);
					});
				}
			})
			.catch(function(err){
				if (/^Access/.test(err.message)) {
					res.status(401);
					next(err);
				} else {
					res.status(500);
					next(err);
				}
			});
		}
	}
);

module.exports = router;
