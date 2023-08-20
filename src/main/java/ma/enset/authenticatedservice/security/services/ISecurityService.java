package ma.enset.authenticatedservice.security.services;


import ma.enset.authenticatedservice.security.dtos.LoginRequest;
import ma.enset.authenticatedservice.security.dtos.LoginResponse;
import ma.enset.authenticatedservice.security.entities.AppRole;
import ma.enset.authenticatedservice.security.entities.AppUser;

import java.util.List;

public interface ISecurityService {
    AppUser addNewUser(AppUser appUser);

    AppUser findUserByUsername(String username);

    AppUser findUserByEmail(String email);

    AppRole findRoleByRoleName(String role);

    AppUser addRoleToUser(String roleName, String email);
    AppRole addNewRole(AppRole appRole);
    List<AppUser> userList();

    List<AppRole> roleList();


    LoginResponse authenticate(LoginRequest loginRequest);

    LoginResponse refreshToken(String refreshToken);
}
