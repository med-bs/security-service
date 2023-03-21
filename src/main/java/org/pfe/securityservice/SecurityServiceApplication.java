package org.pfe.securityservice;

import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;
import org.pfe.securityservice.security.RSAkeysConfig;
import org.pfe.securityservice.services.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
@EnableConfigurationProperties(RSAkeysConfig.class)
public class SecurityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    CommandLineRunner start(AccountService accountService, PasswordEncoder passwordEncoder){
        return args -> {
            if(accountService.allUsers().isEmpty()){
                accountService.addNewUser(AppUser.builder().username("admin")
                        .password(passwordEncoder.encode("root")).build());
                accountService.addNewUser(AppUser.builder().username("user")
                        .password(passwordEncoder.encode("1234")).build());
            }

            if(accountService.allRoles().isEmpty()) {
                accountService.addNewRole(AppRole.builder().roleName("USER").build());
                accountService.addNewRole(AppRole.builder().roleName("ADMIN").build());

                accountService.addRolesToUser("admin", List.of("USER","ADMIN"));
                accountService.addRolesToUser("user",List.of("USER"));
            }

        };
    }

}
