package ma.enset.authenticatedservice;

import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;
import ma.enset.authenticatedservice.security.services.SecurityServiceImpl;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class AuthenticatedServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticatedServiceApplication.class, args);
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner commandLineRunner(SecurityServiceImpl appService){
        return args -> {
            appService.addNewRole(new AppRole(null,"ADMIN"));
            appService.addNewRole(new AppRole(null,"RESPONSABLE"));
            appService.addNewRole(new AppRole(null,"SALARIE"));


            appService.addNewUser(new AppUser(null,"ouassima","ouassima@gmail.com","123456",new ArrayList<>()));
            appService.addNewUser(new AppUser(null,"mohamed","mohamed@gmail.com","12345",new ArrayList<>()));
            appService.addNewUser(new AppUser(null,"anass","anass@gmail.com","1234",new ArrayList<>()));
            appService.addNewUser(new AppUser(null,"jinan","jinan@gmail.com","123",new ArrayList<>()));

            appService.addRoleToUser("ADMIN","ouassima");
            appService.addRoleToUser("RESPONSABLE","mohamed");
            appService.addRoleToUser("SALARIE","anass");
            appService.addRoleToUser("SALARIE","jinan");


        };
    }
}
