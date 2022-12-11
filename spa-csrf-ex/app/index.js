function setupCSRF() {
    // This sets up a new CSRF token + sets a cookie
    // Create an XMLHttpRequest object
    const xhttp = new XMLHttpRequest();

    xhttp.onreadystatechange = function (e) {
        const token = document.getElementById('token');
        if (xhttp.readyState == 4) {
            if (xhttp.status == 200) {
                const button = document.getElementById('test-request');
                const csrf_token = xhttp.responseText;
                function csrfSafeMethod(method) {
                    // these HTTP methods do not require CSRF protection
                    return (/^(GET|HEAD|OPTIONS)$/.test(method));
                }
                var o = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function () {
                    var res = o.apply(this, arguments);
                    var err = new Error();
                    if (!csrfSafeMethod(arguments[0])) {
                        this.setRequestHeader('anti-csrf-token', csrf_token);
                    }
                    return res;
                };
                token.innerText = 'Loaded csrf-token: ' + csrf_token;
                button.classList.remove('disabled');
            } else {
                token.innerText = 'Failed to load csrf-token. Response code: ' + xhttp.status;
            }
        }
    };

    // Send a request
    xhttp.open('GET', '/get-csrf-token');
    xhttp.send();
}

function submitRequest() {
    const xhttp = new XMLHttpRequest();
    xhttp.open('POST', '/use-csrf-token');
    xhttp.send();
}