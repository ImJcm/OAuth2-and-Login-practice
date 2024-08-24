package com.imjcm.oauth2andloginpractice.domain.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @GetMapping()
    public ResponseEntity<?> isAuthMember() {
        return ResponseEntity.status(HttpStatus.OK).body(null);
    }
}
