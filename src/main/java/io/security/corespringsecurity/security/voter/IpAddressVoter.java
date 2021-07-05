package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class IpAddressVoter implements AccessDecisionVoter {

    private final SecurityResourceService securityResourceService;


    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    /**
     * 여기서 심의를 허용할지 말지 결정을 하여야 합니다.
     * */
    @Override
    public int vote(Authentication authentication, Object o, Collection collection) {

        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        List<String> accessIpList = securityResourceService.getAccessIpList();

        int result = ACCESS_DENIED;

        for (String ipAddress : accessIpList) {
            if (remoteAddress.equals(ipAddress)) {
                return ACCESS_ABSTAIN;
            }
        }

        if (result == ACCESS_DENIED)
            throw new AccessDeniedException("Invalid IpAddress");

        return result;
    }

    @Override
    public boolean supports(Class aClass) {
        return true;
    }
}
