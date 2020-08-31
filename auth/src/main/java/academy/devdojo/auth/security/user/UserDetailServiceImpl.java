package academy.devdojo.auth.security.user;

import academy.devdojo.core.model.ApplicationUser;
import academy.devdojo.core.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.Objects;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @_(@Autowired))
public class UserDetailServiceImpl implements UserDetailsService {

    private final ApplicationUserRepository applicationUserRepository;

    @Override
    public UserDetails loadUserByUsername(String userName) {
        log.info("Searching in the DB the user by name '{}' ", userName);
        ApplicationUser applicationUser = applicationUserRepository.findByUsername(userName);
        log.info("Application User found '{}' ", applicationUser);

        if (Objects.isNull(applicationUser)) {
            throw new UsernameNotFoundException(String.format("Application User '%s' not found", userName));
        }
        return new CustomUserDetail(applicationUser);
    }

    private static final class CustomUserDetail extends ApplicationUser implements UserDetails {

        public CustomUserDetail(@NotNull ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_" + this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
