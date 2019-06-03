package com.giulianobortolassi.jwt.manager;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/manager")
public class JwtManagerController {



    @RequestMapping(value = "/revoke", method = RequestMethod.POST )
    public ResponseEntity revokeToken(String token){
        return ResponseEntity.ok().body("token");
    }
}
