package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMsg = "";

        // AuthenticationException 을 통해서 예외를 받을 수 있기 때문에 이것으로 상황에 따라서 다양한 예외 처리를 할 수 있다.
        if (exception instanceof BadCredentialsException)
            errorMsg = "Invalid Username or Password";
        else if (exception instanceof InsufficientAuthenticationException)
            errorMsg = "Invalid Security Key";
        else if (exception instanceof UsernameNotFoundException)
            errorMsg = "Username does not found";


        // redirect 하는 부분이 없기 때문에 나머지는 기존 부모의 onAuthenticationFailure 메소드를 호출해서 페이지 이동 처리를 꼭 해줘야 한다.
        // 가는 url을 지정해주기 위해서 setDefaultFailureUrl 메소드를 호출했다.
        setDefaultFailureUrl("/login?error=true&exception=" + errorMsg);
        super.onAuthenticationFailure(request, response, exception);
    }
}
