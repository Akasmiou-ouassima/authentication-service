package ma.enset.authenticatedservice.security.services;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import ma.enset.authenticatedservice.security.dtos.LoginRequest;
import ma.enset.authenticatedservice.security.dtos.LoginResponse;
import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;
import ma.enset.authenticatedservice.security.exceptions.IncorrectCredentialsException;
import ma.enset.authenticatedservice.security.repositories.AppRoleRepository;
import ma.enset.authenticatedservice.security.repositories.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.util.Date;
import java.util.List;

import static ma.enset.authenticatedservice.security.Util.JwtUtil.*;


@Service
@Transactional
public class SecurityServiceImpl implements ISecurityService {
    private AppRoleRepository appRoleRepository;
    private AppUserRepository appUserRepository;
    private PasswordEncoder passwordEncoder;

    public SecurityServiceImpl(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appRoleRepository = appRoleRepository;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String password = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(password));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppUser findUserByUsername(String username) {
        return appUserRepository.findAppUserByUsername(username);
    }
    @Override
    public AppUser findUserByEmail(String email){
        return appUserRepository.findAppUserByEmail(email);
    }
    @Override
    public AppRole findRoleByRoleName(String role){
        return appRoleRepository.findAppRoleByRoleName(role);
    }

    @Override
    public AppUser addRoleToUser(String roleName, String username) {
        AppUser user = appUserRepository.findAppUserByUsername(username);
        AppRole role  = appRoleRepository.findAppRoleByRoleName(roleName);
        user.getUserRoles().add(role);
        return user;
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public List<AppUser> userList() {
        return appUserRepository.findAll();
    }
    @Override
    public List<AppRole> roleList(){
        return appRoleRepository.findAll();
    }

    @Override
    public LoginResponse authenticate(LoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();
        AppUser user = appUserRepository.findAppUserByEmail(email);
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new IncorrectCredentialsException();
        }
        String accessToken = AccessToken(user);
        String refreshToken = RefreshToken(user);
        return new LoginResponse(accessToken, refreshToken);
    }
    @Override
    public LoginResponse refreshToken(String refreshToken) {
        String userId = JWT.require(Algorithm.HMAC256(SECRET)).build().verify(refreshToken).getSubject();
        AppUser user = appUserRepository.findById(Long.valueOf(userId)).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        String newAccessToken = AccessToken(user);
        return new LoginResponse(newAccessToken, refreshToken);
    }


    public String AccessToken(AppUser user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE_ACCESS_TOKEN))
                .withClaim("roles", user.getUserRoles()
                        .stream()
                        .map(
                                AppRole::getRoleName
                        ).toList())
                .sign(Algorithm.HMAC256(SECRET));
    }

    public String RefreshToken(AppUser user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE_REFRESH_TOKEN))
                .sign(Algorithm.HMAC256(SECRET));
    }
}
