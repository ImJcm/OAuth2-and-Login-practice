package com.imjcm.oauth2andloginpractice.domain.home;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class homeController {

    @GetMapping("/home")
    public String index() {
        return "index";
    }

    @GetMapping("/home/login")
    public String login() {
        return "login";
    }

    @GetMapping("/home/signup")
    public String signup() {
        return "signup";
    }
}
