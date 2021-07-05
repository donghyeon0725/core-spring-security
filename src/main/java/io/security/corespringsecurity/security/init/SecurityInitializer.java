package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.service.impl.RoleHierarchyServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityInitializer implements ApplicationRunner {
    private final RoleHierarchyService roleHierarchyService;

    private final RoleHierarchyImpl roleHierarchy;


    @Override
    public void run(ApplicationArguments args) throws Exception {
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchy.setHierarchy(allHierarchy);
    }
}
