package dev.alexanghel.jwtdemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/")
public class HomeController {
    @GetMapping()
    public String home(Principal principal) {
        System.out.println("principal = " + principal);
        return "hello. " + principal.getName();
    }
}
