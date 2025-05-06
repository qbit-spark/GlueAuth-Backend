package com.qbitspark.glueauthbackend.Oauth2Server.Clients.controller;

import com.qbitspark.glueauthbackend.Oauth2Server.Clients.repos.ClientAppRepo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@RequiredArgsConstructor
@Controller
public class LoginController {

    @GetMapping("/custom-login")
    public ModelAndView login(
            @RequestParam(name = "client_id", required = false) String clientIdParam,
            HttpServletRequest request) {

        ModelAndView mav = new ModelAndView("custom-login");

        return mav;
    }
}