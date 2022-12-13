const express = require('express');
const { v4 } = require('uuid');
const session = require('express-session')

const app = express();

app.use(express.static('app'));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: false
    }
}));

app.get('/get-csrf-token', (req, res) => {
    const csrfToken = v4();
    req.session.csrfToken = csrfToken;
    req.session.save(err => {
        if (err) {
            res.status(400).json({
                error: 'server_error',
                error_message: err.message
            });
        }
        else {
            res.cookie('XSRF-TOKEN', csrfToken, {
                // TODO, add other props
                httpOnly: false
            });
            res.send();
        }
    });
});

app.post('/use-csrf-token', (req, res) => {
    const expectedToken = req.session.csrfToken;
    const providedToken = req.header('X-XSRF-TOKEN');
    if (!expectedToken) {
        res.status(400).json({
            error: 'server_error',
            error_message: 'CSRF token missing from session'
        });
    } else if (providedToken != expectedToken) {
        res.status(400).json({
            error: 'invalid_request',
            error_message: `CSRF token ${providedToken} did not match expected ${expectedToken}`
        });
    } else {
        res.send();
    }
});

app.listen(3000, () => {
    console.log('Listening on http://localhost:3000')
})