package dev.alexanghel.jwtdemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/")
public class HomeController {
//    @GetMapping()
//    public String home(Principal principal) {
//        System.out.println("principal = " + principal);
//        return "hello. " + principal.getName();
//    }

    @PreAuthorize("hasAuthority('SCOPE_read')")
    @GetMapping("/user")
    public String user(Principal principal) {
        System.out.println("principal = " + principal);
        return "hello. user " + principal.getName();
    }

    @PreAuthorize("hasAuthority('SCOPE_write')")
    @GetMapping("/admin")
    public String write(Principal principal) {
        System.out.println("principal = " + principal);
        return "hello. admin " + principal.getName();
    }

    @GetMapping("/")
    public String home() {
        return "Hello, World!";
    }

    @GetMapping("/private")
    public String secure(Authentication authentication) {
        System.out.println(authentication);
        return "secured";
    }


}
