package com.example.securiry.service;

import com.example.securiry.entity.Role;
import com.example.securiry.entity.User;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addToUser(String username, String rolename);
}
