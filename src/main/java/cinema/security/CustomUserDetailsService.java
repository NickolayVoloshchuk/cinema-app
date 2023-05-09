package cinema.security;

import static org.springframework.security.core.userdetails.User.withUsername;

import cinema.model.Role;
import cinema.model.User;
import cinema.service.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserService userService;

    public CustomUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findByEmail(username).orElseThrow(
                () -> new UsernameNotFoundException("Can`t find user by login: " + username));
        return withUsername(username)
                .password(user.getPassword())
                .authorities(user
                        .getRoles()
                        .stream()
                        .map(Role::getRoleName)
                        .toArray(String[]::new))
                .build();
    }
}
