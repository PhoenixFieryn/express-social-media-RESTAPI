const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const { jwtSecret } = require('../util/secret.js');
const { clearImage } = require('../util/file');

const User = require('../models/user');
const Post = require('../models/post');

module.exports = {
	createUser: async function ({ userInput }, req) {
		const { email, name, password } = userInput;

		// Validation
		const errors = [];
		if (!validator.isEmail(email)) {
			errors.push({
				message: 'Email is invalid.',
			});
		}
		if (!validator.isLength(userInput.password, { min: 5 })) {
			errors.push({
				message: 'Password too short',
			});
		}
		if (errors.length > 0) {
			const error = new Error('Invalid input');
			error.data = errors;
			error.code = 422;
			throw error;
		}

		const existingUser = await User.findOne({ email: email });
		if (existingUser) {
			const error = new Error('User exists already!');
			throw error;
		}
		const hashedPw = await bcrypt.hash(password, 12);
		const user = new User({
			email: email,
			name: name,
			password: hashedPw,
		});
		const createdUser = await user.save();
		return {
			...createdUser._doc,
			_id: createdUser._id.toString(),
		};
	},

	login: async function ({ email, password }, req) {
		const user = await User.findOne({ email: email });
		if (!user) {
			const error = new Error('User not found!');
			error.code = 401;
			throw error;
		}
		const isEqual = await bcrypt.compare(password, user.password);
		if (!isEqual) {
			const error = new Error('Password is incorrect!');
			error.code = 401;
			throw error;
		}
		const token = jwt.sign(
			{
				userId: user._id.toString(),
				email: user.email,
			},
			jwtSecret,
			{
				expiresIn: '1h',
			}
		);
		return {
			token: token,
			userId: user._id.toString(),
		};
	},

	createPost: async function ({ postInput }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		const { title, content, imageUrl } = postInput;

		//Validation
		const errors = [];
		if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
			errors.push({ message: 'Title is invalid' });
		}
		if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
			errors.push({ message: 'Content is invalid' });
		}
		if (errors.length > 0) {
			const error = new Error('Invalid input');
			error.data = errors;
			error.code = 422;
			throw error;
		}
		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('Invalid user.');
			error.code = 401;
			throw error;
		}
		const post = new Post({
			title: title,
			content: content,
			imageUrl: imageUrl,
			creator: user,
		});
		const createdPost = await post.save();
		user.posts.push(createdPost);
		await user.save();
		return {
			...createdPost._doc,
			_id: createdPost._id.toString(),
			createdAt: createdPost.createdAt.toISOString(),
			updatedAt: createdPost.updatedAt.toISOString(),
		};
	},

	posts: async function ({ page }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		page = page || 1;
		const perPage = 2;

		const totalItems = await Post.find().countDocuments();
		const posts = await Post.find()
			.populate('creator')
			.sort({ createdAt: -1 })
			.skip((page - 1) * perPage)
			.limit(perPage);
		return {
			posts: posts.map((post) => {
				return {
					...post._doc,
					_id: post._id.toString(),
					createdAt: post.createdAt.toISOString(),
					updatedAt: post.updatedAt.toISOString(),
				};
			}),
			totalItems: totalItems,
		};
	},

	post: async function ({ id }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		const post = await Post.findById(id).populate('creator');
		if (!post) {
			const error = new Error('No post found.');
			error.code = 404;
			throw error;
		}
		return {
			...post._doc,
			_id: post._id.toString(),
			createdAt: post.createdAt.toISOString(),
			updatedAt: post.updatedAt.toISOString(),
		};
	},

	updatePost: async function ({ id, postInput }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		const post = await Post.findById(id).populate('creator');
		if (!post) {
			const error = new Error('No post found.');
			error.code = 404;
			throw error;
		}
		if (!post.creator._id.toString() === req.userId.toString()) {
			const error = new Error('Not authorized');
			error.code = 403;
			throw error;
		}
		const { title, content, imageUrl } = postInput;
		//Validation
		const errors = [];
		if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
			errors.push({ message: 'Title is invalid' });
		}
		if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
			errors.push({ message: 'Content is invalid' });
		}
		if (errors.length > 0) {
			const error = new Error('Invalid input');
			error.data = errors;
			error.code = 422;
			throw error;
		}
		post.title = title;
		post.content = content;
		if (postInput.imageUrl !== 'undefined') {
			post.imageUrl = imageUrl;
		}
		const updatedPost = await post.save();
		return {
			...updatedPost._doc,
			_id: updatedPost._id.toString(),
			createdAt: updatedPost.createdAt.toISOString(),
			updatedAt: updatedPost.updatedAt.toISOString(),
		};
	},

	deletePost: async function ({ id }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		const post = await Post.findById(id).populate('creator');
		if (!post) {
			const error = new Error('No post found.');
			error.code = 404;
			throw error;
		}
		if (!post.creator._id.toString() === req.userId.toString()) {
			const error = new Error('Not authorized');
			error.code = 403;
			throw error;
		}

		clearImage(post.imageUrl);
		await Post.findByIdAndRemove(id);
		const user = await User.findById(req.userId);
		user.posts.pull(id);
		await user.save();
		return true;
	},

	user: async function (args, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('User not found!');
			error.code = 401;
			throw error;
		}
		await user.save();
		return {
			...user._doc,
			_id: user._id.toString(),
		};
	},

	updateStatus: async function ({ status }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}

		if (!validator.isLength(status, { min: 5 })) {
			const error = new Error('Invalid status');
			error.code = 422;
			throw error;
		}

		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('User not found!');
			error.code = 401;
			throw error;
		}
		user.status = status;
		const updatedUser = await user.save();
		return {
			...user._doc,
			_id: user._id.toString(),
		};
	},
};
