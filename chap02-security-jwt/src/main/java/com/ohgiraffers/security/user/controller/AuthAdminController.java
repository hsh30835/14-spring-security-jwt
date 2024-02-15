package com.ohgiraffers.security.user.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasAuthority('ADMIN')")
public class AuthAdminController {

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }
}
