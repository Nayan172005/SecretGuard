/**
 * Error Handler Middleware
 */

function errorHandler(err, req, res, next) {
  console.error('Error:', err.message);

  // Multer errors (file upload)
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: `File too large. Maximum size is ${process.env.MAX_UPLOAD_SIZE_MB || 100}MB`
    });
  }

  if (err.message === 'Only ZIP files are allowed') {
    return res.status(400).json({ error: err.message });
  }

  // Mongoose validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: err.message });
  }

  // Default server error
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  });
}

module.exports = { errorHandler };
