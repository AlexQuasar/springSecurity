package com.alexquasar.springSecurity.service;

import com.alexquasar.springSecurity.dto.User;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class GetTokenService {

    private UserDetailsService userDetailsService;

    private String key = "abc123";
    private Map<String, User> users = new HashMap<>();

    public GetTokenService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public TokenObject getToken(String username, String password) throws Exception {
        if (username == null || password == null)
            return null;
        User user = (User) userDetailsService.loadUserByUsername(username);
        Map<String, Object> tokenData = new HashMap<>();
        if (password.equals(user.getPassword())) {
            tokenData.put("clientType", "user");
            tokenData.put("userID", user.getId().toString());
            tokenData.put("username", user.getUsername());//authorizedUser.getUsername());
            tokenData.put("token_create_date", new Date().getTime());

            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.YEAR, 100);
            tokenData.put("token_expiration_date", calendar.getTime());

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setExpiration(calendar.getTime());
            jwtBuilder.setClaims(tokenData);
            String token = jwtBuilder.signWith(SignatureAlgorithm.HS512, key).compact();

            return token;
        } else {
            throw new Exception("Authentication error");
        }
    }
}
