package com.example.securiry.repository;

import com.example.securiry.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends   JpaRepository<Role, Long> {
    Role findByName(String role);
}
