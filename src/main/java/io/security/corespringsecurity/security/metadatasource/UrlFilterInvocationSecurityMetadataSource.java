package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * 1. 요청 정보에 대해 어떤 권한을 가지고 있는지 검사
 * 2. 요청 정보에 대한 권한 매핑 정보 리로드
 * */
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;

    private SecurityResourceService securityResourceService;

    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap, SecurityResourceService securityResourceService) {
        this.requestMap = requestMap;
        this.securityResourceService = securityResourceService;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {

        HttpServletRequest request = ((FilterInvocation) o).getRequest();

        // requestMap 에 DB에서 추출한 권한 정보를 넣어놔야 한다.
        if (requestMap != null)
            for ( Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                RequestMatcher matcher = entry.getKey();

                if (matcher.matches(request))
                    return entry.getValue();

            }

        return null;
    }


    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet();
        Iterator var2 = this.requestMap.entrySet().iterator();

        while(var2.hasNext()) {
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = (Map.Entry)var2.next();
            allAttributes.addAll((Collection)entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }



    public void reload() {
        requestMap = securityResourceService.getResourceList();
    }
}
