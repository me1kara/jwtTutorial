package com.han.jwtTuto.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class HomeController {
    @GetMapping("/")
    public String home(){

        return "/home";
    }

    @GetMapping("/login")
    public String viewLogin(){

        return "/login";
    }

    @PostMapping("/login")
    public String login(){

        return "/";
    }
}
