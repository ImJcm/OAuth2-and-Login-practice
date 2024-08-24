document.getElementById('signup-form').addEventListener('submit', async function(event) {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const nickname = document.getElementById('nickname').value;

    const response = await fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            email: email,
            password: password,
            nickname: nickname
        })
    });

    const resultElement = document.getElementById('result');

    if (response.ok) {
        resultElement.textContent = '회원가입이 성공적으로 완료되었습니다!';
        resultElement.style.color = 'green';
    } else {
        const errorData = await response.json();
        resultElement.textContent = `회원가입 실패: ${errorData.message || '알 수 없는 오류'}`;
        resultElement.style.color = 'red';
    }
});

document.getElementById("loginPage").addEventListener('click', event => {
    window.location.href = "/home/login";
})
