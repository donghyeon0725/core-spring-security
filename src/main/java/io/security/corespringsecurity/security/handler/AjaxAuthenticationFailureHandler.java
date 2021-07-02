package io.security.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMsg = "";

        // AuthenticationException 을 통해서 예외를 받을 수 있기 때문에 이것으로 상황에 따라서 다양한 예외 처리를 할 수 있다.
        if (exception instanceof BadCredentialsException)
            errorMsg = "Invalid Username or Password";
        else if (exception instanceof DisabledException)
            errorMsg = "Locked";
        else if (exception instanceof CredentialsExpiredException)
            errorMsg = "Expired Password";


        new ObjectMapper().writeValue(response.getWriter(), errorMsg);
    }
}
