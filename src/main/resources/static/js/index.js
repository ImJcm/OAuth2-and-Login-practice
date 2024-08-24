import {getAccessToken} from './jwt.js';
import {getRefreshToken} from './jwt.js';
import {setAccessToken} from "./jwt.js";

const jwt_reIssue_uri = '/api/jwt/reissue-token';
document.addEventListener('DOMContentLoaded', function() {
    alert('index Page!' + getAccessToken() + "/" + getRefreshToken());
});

const clickButton = document.getElementById("auth-btn");

if(clickButton) {
    clickButton.addEventListener('click', event => {
        let point = document.getElementById('point');
        let currentValue = parseInt(point.innerText);

        function success() {
            alert('인증된 사용자입니다.');
            currentValue += 1;
            point.innerText = currentValue;
        }

        function fail() {
            alert('인증되지 않은 사용자입니다.');
            window.location.href = '/home/login';
        }

        httpRequest('GET','/api/auth',null, success, fail);
    });
}

function httpRequest(method, url, body, success, fail) {
    fetch(url, {
        method: method,
        headers: {
            Authorization: getAccessToken(),
            'Content-Type': 'application/json',
        },
        body: body,
    }).then(response => {
        if(response.status === 200 || response.status === 201) {
            return success();
        }
        const refreshToken = getRefreshToken();

        if(response.status === 401 && refreshToken) {
            fetch(jwt_reIssue_uri, {
                method: 'POST',
                headers: {
                    Authorization: getAccessToken(),
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    refreshToken: refreshToken,
                }),
            })
                .then(res => {
                    // AccessToken이 유효하지 않지만, refreshToken으로 AccessToken과 RefreshToken 재발급
                    if(res.status === 201) {
                        setAccessToken(res.headers.get('Authorization'));
                        httpRequest(method, url, body, success, fail);
                    }

                    // AccessToken와 refreshToken 모두 유효하지 않은 상태
                    if(res.status === 401) {
                        return fail();
                    }
                })
                .then(result => {
                    // ResponseBody null이므로 empty
                })
                .catch(error => fail());
        } else {
            return fail();
        }
    });
}

function getCookie(name) {
    let cookieArr = document.cookie.split(";");

    for(let i = 0; i < cookieArr.length; i++) {
        let cookiePair = cookieArr[i].split("=");

        if(name === cookiePair[0].trim()) {
            return decodeURIComponent(cookiePair[1]);
        }
    }

    return null;
}