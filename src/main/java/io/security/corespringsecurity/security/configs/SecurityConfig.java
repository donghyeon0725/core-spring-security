package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.domain.RoleHierarchy;
import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.voter.IpAddressVoter;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@Slf4j
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    private final AuthenticationDetailsSource authenticationDetailsSource;

    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    private final AuthenticationFailureHandler authenticationFailureHandler;

    private final SecurityResourceService securityResourceService;

    private final String[] permitAllResources = {"/", "/login", "/user/login/**"};

    /**
     * 인증을 위해서, 인증 과정을 우리가 직접 정의할 수 있다.
     * 이렇게 Bean 으로 등록하면 우리가 만든 CustomAuthenticationProvider를 스프링 시큐리티가 사용한다.
     * */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
    }

    /**
     * Security 계정 DB 연동
     * */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*
        사용자를 직접 세팅하는 것 대신, 우리가 만든 UserDetailService를 기반으로 Security 에서 사용할 수 있는 유저를 가져온다.
        String password = passwordEncoder().encode("1234");

        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password(password).roles("USER","MANAGER");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("USER","MANAGER","ADMIN");
        */
        // auth.userDetailsService(userDetailsService);
        // 우리가 직접 만든 Provider 를 사용할 수 있다.
        // ProviderManager(AuthenticationManager 구현체) 를 디버깅 해서 우리가 만든 객체가 사용되는지 확인
        auth.authenticationProvider(authenticationProvider());
    }

    /**
     * PasswordEncoder interface를 구현한 클래스 중 하나로,
     * 이것을 사용해서 create (insert) 할 때 encoding 하고
     * prefix는 자동으로 앞에 붙는다. => 어떤 알고리즘으로 인코딩 되었는지
     * 비밀번호를 찾을 때 이 bean으로 encoding 해서 비밀번호가 맞는지 확인한다.
     * */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 인코딩 공장에 있는 PasswordEncoder interface 중 하나를 꺼내서 Encoding에 사용한다.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()

        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll();

        http
                .addFilterBefore(filterSecurityInterceptor(), FilterSecurityInterceptor.class);

        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler().setErrorPage("/errorPage");
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    @Bean
    public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
        PermitAllFilter interceptor = new PermitAllFilter(permitAllResources);

        interceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        interceptor.setAccessDecisionManager(affirmativeBased());
        interceptor.setAuthenticationManager(authenticationManagerBean());

        return interceptor;
    }

    @Bean
    public UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
        return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
    }

    /**
     * 하나라도 접근 거부가 뜨면
     * 허가 거부
     * */
    @Bean
    public AffirmativeBased affirmativeBased() {
        return new AffirmativeBased(getAccessDecisionVoters());
    }

    /**
     * 보터 리스트
     * */
    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {

        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        // ip address 심의를 가장 먼저 할 수 있도록 맨 처음에 추가 => AffirmativeBased AbstractAccessDecisionManager 를 달고 있기 때문에(하나라도 허가시 허가), IpAddressVoter를 가장 먼저 달아주어야 한다.
        voters.add(new IpAddressVoter(securityResourceService));
        voters.add(roleVoter());
        return voters;
    }

    /**
     * 권한 계층의 정보를 setting 한 voter
     * */
    @Bean
    public AccessDecisionVoter<?> roleVoter() {
        return new RoleHierarchyVoter(roleHierarchy());
    }

    /**
     * 권한 계층
     * */
    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        return new RoleHierarchyImpl();
    }


    private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
        UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
        urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return urlResourcesMapFactoryBean;
    }

}
