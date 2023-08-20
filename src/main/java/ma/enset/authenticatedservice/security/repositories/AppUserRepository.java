package ma.enset.authenticatedservice.security.repositories;

import ma.enset.authenticatedservice.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findAppUserByEmail(String email);
    AppUser findAppUserByUsername(String username);
}
