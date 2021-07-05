package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.aop.CustomMethodSecurityInterceptor;
import io.security.corespringsecurity.security.factory.MethodResourcesMapFactoryBean;
import io.security.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity
@RequiredArgsConstructor
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    private final    SecurityResourceService securityResourceService;

    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return getMapBasedMethodSecurityMetadataSource();
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource getMapBasedMethodSecurityMetadataSource() {
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
    }

    @Bean
    public MethodResourcesMapFactoryBean methodResourcesMapFactoryBean() {
        MethodResourcesMapFactoryBean methodResourcesMapFactoryBean
                = new MethodResourcesMapFactoryBean();
        methodResourcesMapFactoryBean.setResourceType("method");
        methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return methodResourcesMapFactoryBean;
    }

    @Bean
    public MethodResourcesMapFactoryBean pointcutResourcesMapFactoryBean() {
        MethodResourcesMapFactoryBean methodResourcesMapFactoryBean
                = new MethodResourcesMapFactoryBean();
        methodResourcesMapFactoryBean.setResourceType("pointcut");
        methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);

        return methodResourcesMapFactoryBean;
    }


    /**
     * 빈 후 처리기, 포인트 컷 보안을 위함
     * */
    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor() {
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(getMapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());

        return protectPointcutPostProcessor;
    }

    @Bean
    public CustomMethodSecurityInterceptor customMethodSecurityInterceptor(MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource) {
        CustomMethodSecurityInterceptor interceptor = new CustomMethodSecurityInterceptor();
        interceptor.setAccessDecisionManager(accessDecisionManager());
        interceptor.setAfterInvocationManager(afterInvocationManager());
        interceptor.setSecurityMetadataSource(mapBasedMethodSecurityMetadataSource);
        RunAsManager runAsManager = runAsManager();
        if (runAsManager != null)
            interceptor.setRunAsManager(runAsManager);

        return interceptor;
    }

/*    @Bean
    public BeanPostProcessor protectPointcutPostProcessor() throws Exception {
        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
        declaredConstructor.setAccessible(true);
        Object instance = declaredConstructor.newInstance(getMapBasedMethodSecurityMetadataSource());
        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
        setPointcutMap.setAccessible(true);
        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());

        return (BeanPostProcessor) instance;
    }*/
}
