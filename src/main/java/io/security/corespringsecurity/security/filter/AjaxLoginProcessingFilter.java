package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.common.ModelMapperUtil;
import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDTO;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    public AjaxLoginProcessingFilter() {
        // 작동하는 url pattern 조건을 줄 수 있음
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!isAjax(request))
            throw new IllegalStateException("Authentication is not supported");

        AccountDTO accountDTO = new ObjectMapper().readValue(request.getReader(), AccountDTO.class);
        if (StringUtils.isEmpty(accountDTO.getUsername()) || StringUtils.isEmpty(accountDTO.getPassword()))
            throw new IllegalArgumentException("IllegalArgumentException");

        // 인증 객체 set, 이 때 detail 도 setting 해주어야 함
        AjaxAuthenticationToken authRequest
                = new AjaxAuthenticationToken(accountDTO.getUsername(), accountDTO.getPassword());
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * request 로부터 헤더를 가져와 ajax 요청인지 확인을 할 수 있음
     * */
    private boolean isAjax(HttpServletRequest request) {
        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With")))
            return true;
        return false;
    }
}
