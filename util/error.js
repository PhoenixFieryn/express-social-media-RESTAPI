exports.error = (next, error) => {
	if (!error.statusCode) {
		error.statusCode = 500;
	}
	next(error);
};
