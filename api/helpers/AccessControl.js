var Promise = require('bluebird');
var _ = require('lodash');
var debug = require('debug')('AccessControl');

var unless = require('express-unless');
var jwt = require('jsonwebtoken');
var expressJwt = require('express-jwt');

var R = require('./Responses');
var config = require('../config')();

var db = require('../database/').initDB();
var ModelUser = db.models.User;
var ModelUserGroup = db.models.UserGroup;

var logMe = process.env.NODE_ENV==="dev" ;


var groups = function (req, res, next){
	ModelUser.findOne({where: {id: req.user.id}})
	.then(function(user){
		if(user) return user.getUserGroups();
		else {
			res.status(400);
			next(new Error('User does not exists'));
		}
	})
	.then(function(groups){
		req.user.groups = groups;

		req.user.isAdmin = false;
		_.forEach(groups, function (group) {
			req.user.isAdmin = req.user.isAdmin || group.GroupId == config.get('root');
		});
		next();
	});
};

groups.unless = unless;

exports.groups = groups;

var isAdmin = function isAdmin (req, res, next){
	if(!req.user.isAdmin) return next('route');
	next();
};

exports.isAdmin = isAdmin;

var adminOnly = function isAdmin (req, res, next){
	console.log(req.user);
	if(!req.user || !req.user.isAdmin) return next(new Error('User must be admin to use this route'));
	next();
};

exports.adminOnly = adminOnly;

exports.expressJwt = expressJwt({secret: config.get('jwtSecret')}),

	/**
	 * user: Validates the user's existence for each requests it makes to a signed route.
	 * @param  {Express Request}	req	contain the request params and body
	 * @param  {Express Response}	res	contain the answer object
	 * @return {[type]}     [description]
	 */
exports.user = function user (req, res){
		return ModelUser.findOne({where: {id: req.user.id}})
			.then(function( user ){
				if( !user ){
					debug('user "' + req.user.username + '" tried to request'+req.originalUrl+'with a fake id');
					return Promise.reject(new Error('Access denied'));
				}

				req.user = user;
				return Promise.resolve({
					req: req,
					res: res
				});
			})
			.catch(function(err){
				debug('user "' + req.user.username + '" request' + req.originalUrl + ' and get' + err.stack);
				return res.status(401).send(err.message);
			});
	};

	// can be a function that receives the groupId as a param
exports.admin = function admin (req, res, next){
		return ModelUser.scope( { method: ['inAdminGroup', ModelUserGroup]})
			.findOne({where: {id: req.user.id}})
			.then(function(user){
				if(!user){
					debug('user "' + req.user.username + '" tried to request'+req.originalUrl+'with a fake id');
					return Promise.reject(new Error('Access denied'));
				}

				req.user = user;
				return Promise.resolve({
					req: req,
					res: res
				});
			})
			.catch(function(err){
				debug('user "' + req.user.username + '" request' + req.originalUrl + ' and get' + err.stack);
				return res.status(401).send(err.message);
			});
	};

exports.anonymous = function anonymous (req, res){
		return Promise.resolve();
	},

exports.verifyToken = function verifyToken (accessLevel){
		if(accessLevel === 'anonymous'){
			return function(req, res, next){
				return next();
			};
		}
		debug('verifing token ...');

		return expressJwt({secret: config.get('jwtSecret')});
	};

exports.verifyAccessLevel = function verifyAccessLevel(accessLevel){

		debug('verifing access level ...');

		return function(req, res, next){
			this[accessLevel](req, res)
				.then(function (response) {
					return next();
				}).catch(function (err) {
					debug(err.error.stack);
					return res.status(err.status).send(err.error.message);
				});
		}.bind(this);
	};

exports.context = function(ctx){
		return [this.verifyToken(ctx), this.verifyAccessLevel(ctx)];
	};
