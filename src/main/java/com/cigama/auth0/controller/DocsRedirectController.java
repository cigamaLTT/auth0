package com.cigama.auth0.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DocsRedirectController {

    @GetMapping("/api/docs")
    public String redirectToSwagger() {
        return "redirect:/swagger-ui/index.html";
    }
}
