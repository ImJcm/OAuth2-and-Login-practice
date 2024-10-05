# OAuth2.0 + Login + JWT + Spring Security
***
## 📕 Tech Stacks ##
<div align= "left">
<h3> Backend</h3>
<img src="https://img.shields.io/badge/intelliJ-F80000?style=flat&logo=IntelliJ IDEA&logoColor=black">
<img src="https://img.shields.io/badge/Java 17-007396?style=flat&logo=Java&logoColor=white">
<img src="https://img.shields.io/badge/jsonwebtokens-000000?style=flat&logo=jsonwebtokens&logoColor=white">
<img src="https://img.shields.io/badge/gradle 8-02303A?style=flat&logo=gradle&logoColor=white">
<img src="https://img.shields.io/badge/SpringBoot 3.3.0-6db33f?style=flat&logo=springBoot&logoColor=white">
<img src="https://img.shields.io/badge/Spring Security-6db33f?style=flat&logo=SpringSecurity&logoColor=white">
<img src="https://img.shields.io/badge/Spring Data Jpa-EB5424?style=flat&logo=oauth&logoColor=white">
<img src="https://img.shields.io/badge/OAuth2.0-3B66BC?style=flat&logo=auth0&logoColor=white">
<img src="https://img.shields.io/badge/junit5-25A162?style=flat&logo=junit5&logoColor=white">
<img src="https://img.shields.io/badge/MySql 8-4479a1?style=flat&logo=mysql&logoColor=white">
</div>

## 목적
oAuth1.0와 자체 로그인을 spring security를 사용하지 않고 구현한 경험이 있었지만, 이번 기회에 oAuth2.0와 자체 로그인을 Spring Security를 활용하여 구현해보는 것이 좋다고 생각하여 Repo를 만들게 되었다.
더 나아가, 프로젝트에서 경험해보지 못한 refreshToken도 적용해볼 수 있도록 할 계획이다.

## 프로젝트 기능 및 설계 ##
- JWT 토큰 인증 방식과 Spring Security를 이용하여 oAuth2.0 + 자체 로그인을 구현한 Repo
  (oAuth의 경우, Google만 적용한 상태)
- JWT Token 방식으로 AccessToken + RefreshToken을 적용
- RefreshToken - Redis DB에 저장
- JWT Token 재발급 시, RefreshToken Rotation 적용
- 자체 로그인 & oAuth 로그인 Test code 작성
- 예상 화면 (인프런 로그인 화면 참고)

  ![image](https://github.com/ImJcm/OAuth2-and-Login-practice/assets/51190093/7051c759-a79f-44a2-b871-1ad5902bc7c9)

## 코드 설명 & 기능 정리
- https://cm97.notion.site/Spring-Security-JWT-OAuth2-8d844ed2fdd443f2928b913339d61cca?pvs=4
