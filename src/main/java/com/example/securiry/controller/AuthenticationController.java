package com.example.securiry.controller;

import com.example.securiry.auth.AuthenticationRequest;
import com.example.securiry.auth.AuthenticationResponse;
import com.example.securiry.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.repository.query.Param;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@Param("token") String token) throws Exception {
        return ResponseEntity.ok(authenticationService.isValidToken(token));
    }
}
