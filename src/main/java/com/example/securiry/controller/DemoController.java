package com.example.securiry.controller;

import com.example.securiry.auth.AuthenticationRequest;
import com.example.securiry.auth.AuthenticationResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/demo")
public class DemoController {
    @GetMapping("/admin")
    public ResponseEntity<String> test(){
        return ResponseEntity.ok("admin success.......");
    }

    @GetMapping("/user")
    public ResponseEntity<String> test2(){
        return ResponseEntity.ok("user success.......");
    }
}
