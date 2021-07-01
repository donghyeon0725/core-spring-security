package io.security.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // 사용자 이전 요청에 대한
    private RequestCache requestCache = new HttpSessionRequestCache();
    // 사용자 페이지 제어에 사용할 수 있다.
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Authentication 객체를 받기 때문에 원하는 작업을 추가적으로 할 수도 있을 것이다.
     * */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // default url 설정하기
        setDefaultTargetUrl("/");

        SavedRequest savedRequest = requestCache.getRequest(request, response);

        // 바로 로그인 페이지로 왔던 경우에는 null 일수 있기 때문에 check 해야함
        if (savedRequest != null) {
            String target = savedRequest.getRedirectUrl();

            redirectStrategy.sendRedirect(request, response, target);
        } else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
