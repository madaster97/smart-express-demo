function setupCSRF() {
    fetch('/get-csrf-token')
        .then(response => {
            if (response.status == 200) {
                const token = document.getElementById('token');
                const csrf_token = document.cookie
                    .split('; ')
                    .find((row) => row.startsWith('XSRF-TOKEN='))
                    ?.split('=')[1];
                if (!csrf_token) {
                    token.innerText = 'Could not find token in "XSRF-TOKEN" cookie';
                } else {
                    token.innerText = 'Set token with value ' + csrf_token;
                    const button = document.getElementById('test-request');
                    button.removeAttribute('disabled');
                }
            } else {
                return response.json().then(errJson => {
                    throw new Error(JSON.stringify(errJson, null, 2))
                })
            }
        }).catch(err => {
            const token = document.getElementById('token');
            token.innerText = 'Error fetching token: ' + err.message;
        });
}

function submitRequest() {
    const csrf_token = document.cookie
        .split('; ')
        .find((row) => row.startsWith('XSRF-TOKEN='))
        ?.split('=')[1];
    if (!csrf_token) {
        const result = document.getElementById('result');
        result.innerText = 'Error finding XSRF-TOKEN cookie';
    } else {
        fetch('/use-csrf-token', {
            method: 'POST',
            headers: {
                'X-XSRF-TOKEN': csrf_token
            }
        })
            .then(response => {
                if (response.status == 200) {
                    const result = document.getElementById('result');
                    result.innerText = 'Successful request!';
                } else {
                    return response.json().then(errJson => {
                        throw new Error(JSON.stringify(errJson, null, 2))
                    })
                }
            }).catch(err => {
                const result = document.getElementById('result');
                result.innerText = 'Error sumbitting request: ' + err.message;
            });
    }
}