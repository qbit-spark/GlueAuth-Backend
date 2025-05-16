package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class SuccessController {

    @GetMapping("/success")
    public String successPage() {
        return "success";
    }

    @GetMapping("/")
    public String handleRootWithSuccess(@RequestParam(value = "success", required = false) String success) {
        if ("".equals(success) || "true".equals(success)) {
            return "redirect:/success";
        }

        return "home";
    }
}