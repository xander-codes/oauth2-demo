package dev.alexanghel.jwtdemo;

import dev.alexanghel.jwtdemo.config.RsaKeyProperties;
import dev.alexanghel.jwtdemo.model.AppUser;
import dev.alexanghel.jwtdemo.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder encoder){
        return args -> {
            userRepository.save(new AppUser("a", encoder.encode( "p"), "user"));
            userRepository.save(new AppUser("b", encoder.encode( "p"), "admin"));
        };
    }
}
