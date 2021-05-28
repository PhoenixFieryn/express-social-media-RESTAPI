const path = require('path');

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { graphqlHTTP } = require('express-graphql');

const graphqlSchema = require('./graphql/schema');
const graphqlResolver = require('./graphql/resolvers');
const auth = require('./middleware/auth');
const { clearImage } = require('./util/file');

const MONGODB_URI = process.env.MONGO_URI;

const app = express();

const fileStorage = multer.diskStorage({
	destination: (req, file, cb) => {
		cb(null, 'images');
	},
	filename: (req, file, cb) => {
		cb(null, uuidv4());
	},
});

const fileFilter = (req, file, cb) => {
	if (
		file.mimetype === 'image/png' ||
		file.mimetype === 'image/jpeg' ||
		file.mimetype === 'image/jpg'
	) {
		cb(null, true);
	} else {
		cb(null, false);
	}
};

app.use(express.json());
app.use(multer({ storage: fileStorage, fileFilter: fileFilter }).single('image'));
app.use('/images', express.static(path.join(__dirname, 'images')));

app.use((req, res, next) => {
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
	if (req.method === 'OPTIONS') {
		return res.sendStatus(200);
	}
	next();
});

app.use(auth);

app.put('/post-image', (req, res, next) => {
	if (!req.isAuth) {
		throw new Error('Not Authenticated.');
	}
	if (!req.file) {
		return res.status(200).json({ message: 'No file provided' });
	}
	if (req.body.oldPath) {
		clearImage(req.body.oldPath);
	}

	return res
		.status(201)
		.json({ message: 'File stored', filePath: req.file.path.replace('\\', '/') });
});

app.use(
	'/graphql',
	graphqlHTTP({
		schema: graphqlSchema,
		rootValue: graphqlResolver,
		graphiql: true,
		formatError(err) {
			if (!err.originalError) {
				return err;
			}
			const { data, message = 'An error occurred.', code = 500 } = err.originalError;
			return {
				message: message,
				status: code,
				data: data,
			};
		},
	})
);

app.use((error, req, res, next) => {
	console.error(error);
	const status = error.statusCode || 500;
	const message = error.message;
	const data = error.data;
	res.status(status).json({ message: message, data: data });
});

mongoose
	.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
	.then((result) => {
		server = app.listen(process.env.PORT || 8080);
	})
	.catch((err) => {
		console.log(err);
	});
