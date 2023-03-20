package com.example.keycloakboot.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author yanxin
 * @Description:
 */
@RequestMapping("/")
@RestController
public class TestController {


    @GetMapping("hello")
    @PreAuthorize("hasRole('user_manager')")
    public String hello(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        return currentPrincipalName;
    }

    @GetMapping("hello1")
    @PreAuthorize("hasRole('user_manager1')")
    public String hello1(){
        return "hello1";
    }

    @GetMapping("anno")
    public String anno(){
        return "anno";
    }
}
