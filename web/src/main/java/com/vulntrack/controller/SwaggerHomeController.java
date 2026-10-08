package com.vulntrack.controller;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@ConditionalOnProperty(name = "springdoc.swagger-ui.enabled", havingValue = "true")
public class SwaggerHomeController {

    @GetMapping("/")
    public String home() {
        return "redirect:/swagger-ui.html";
    }
}
