import {getAccessToken, getCookie} from './jwt.js';
import {setAccessToken} from './jwt.js';

document.addEventListener('DOMContentLoaded', function() {
    alert('JavaScript file loaded successfully!');
});

document.getElementById('loginButton').addEventListener('click', function (message) {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    fetch('/login', {
        method: 'POST',
        headers: {
            Authorization: getAccessToken(),
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
    })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(text);
                });
            }

            // front-end에서 header로 넘어온 accessToken, refreshToken을 Cookie로 저장하거나 local Storage 이용
            setAccessToken(response.headers.get('Authorization'));
            let refreshToken = getCookie('Refresh-Authorization');

            //return response.json();
        })
        .then(data => {
            // Handle success
            console.log('Login successful:', data);
            //alert('Login successful!');

            // Example: Redirect to another page
            window.location.href = '/home';
        })
        .catch(error => {
            // Handle errors
            console.error('here Error:', error);
            alert('Login failed: ' + error.message);
        });
});

document.getElementById("signupButton").addEventListener("click", event => {
    window.location.href = "/home/signup";
})