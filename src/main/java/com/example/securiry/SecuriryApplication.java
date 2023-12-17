package com.example.securiry;

import com.example.securiry.entity.Role;
import com.example.securiry.entity.User;
import com.example.securiry.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@EnableWebSecurity
@EnableJpaRepositories
public class SecuriryApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuriryApplication.class, args);
	}

	@Bean
	BCryptPasswordEncoder bCryptPasswordEncoder(){
		return new BCryptPasswordEncoder();
	}

//	@Bean
//	CommandLineRunner run(UserService userService) {
//		return args -> {
//			userService.saveRole(new Role(null,"ROLE_USER"));
//			userService.saveRole(new Role(null,"ROLE_MANAGER"));
//			userService.saveRole(new Role(null,"ROLE_ADMIN"));
//			userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));
//
//			userService.saveUser(new User(null,"nhatkhuong" ,"nhatkhuong2001@gmail.com","nhatkhuong2001@gmail.com","123456"));
//			userService.saveUser(new User(null,"nhatkhuong2" ,"nhatkhuong20012@gmail.com","nhatkhuong20012@gmail.com","123457"));
//
//			userService.addToUser("nhatkhuong2001@gmail.com","ROLE_USER");
//			userService.addToUser("nhatkhuong20012@gmail.com","ROLE_ADMIN");
//
//		};
//	}
}
