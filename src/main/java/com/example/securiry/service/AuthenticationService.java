package com.example.securiry.service;

import com.example.securiry.auth.AuthenticationRequest;
import com.example.securiry.auth.AuthenticationResponse;
import com.example.securiry.entity.Role;
import com.example.securiry.entity.User;
import com.example.securiry.repository.RoleCustomRepo;
import com.example.securiry.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final RoleCustomRepo roleCustomRepo;
    private final JwtService jwtService;

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));
        User user = userRepository.findByEmail(request.getEmail());
        List<String> roles = null;
        if(user != null){
            roles = roleCustomRepo.getRoleNames(user);
        }
//        System.out.println(String.valueOf(roles.get(0).getName()));
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//        Set<Role> set = new HashSet<>();
//        roles.stream().forEach(c->set.add(new Role(c.getName())));
//        roles.forEach(c ->{
//            set.add(new Role(c.getName()));
//        });
//        for (int i = 0; i<roles.size();i++){
//            Role r = new Role(roles.get(i).getName());
//            set.add(r);
//        }
//        user.setRoles(new HashSet<>(roles));
        roles.stream().forEach(i-> authorities.add(new SimpleGrantedAuthority(i)));
//        set.stream().forEach(i-> authorities.add(new SimpleGrantedAuthority(i.getName())));
//        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
//        for (int i = 0; i<roles.size();i++){
//            Role r = roles.get(i);
//            String role = r.getName();
//            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);
//            authorities.add(simpleGrantedAuthority);
//        }
        String jwtToken = jwtService.generateToken(user,authorities);
        String jwtRefreshToken = jwtService.generateRefreshToken(user,authorities);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(jwtRefreshToken)
                .build();
    }
}
