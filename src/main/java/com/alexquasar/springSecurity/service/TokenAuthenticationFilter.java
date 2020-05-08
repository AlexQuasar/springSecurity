package com.alexquasar.springSecurity.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TokenAuthenticationFilter extends {

    public TokenAuthenticationFilter() {
        super("/rest/**");
        setAuthenticationSuccessHandler((request, response, authentication) ->
        {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.getRequestDispatcher(request.getServletPath() + request.getPathInfo()).forward(request, response);
        });
        setAuthenticationFailureHandler((request, response, authenticationException) -> {
            response.getOutputStream().print(authenticationException.getMessage());
        });
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String token = request.getHeader("token");
        if (token == null)
            token = request.getParameter("token");
        if (token == null) {
            TokenAuthentication authentication = new TokenAuthentication(null, null);
            authentication.setAuthenticated(false);
            return authentication;
        }
        TokenAuthentication tokenAuthentication = new TokenAuthentication(token);
        Authentication authentication = getAuthenticationManager().authenticate(tokenAuthentication);
        return authentication;
    }
}
