package ma.enset.authenticatedservice;

import ma.enset.authenticatedservice.security.entities.AppUser;
import ma.enset.authenticatedservice.security.repositories.AppUserRepository;
import ma.enset.authenticatedservice.security.services.SecurityServiceImpl;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@SpringBootTest
public class UserServiceTest {

    @Mock
    private AppUserRepository appUserRepository;

    @InjectMocks
    private SecurityServiceImpl userService;

    @Test
    public void testFindUserByEmail() {
        // Définir le comportement simulé de l'appUserRepository
        String email = "ouassima@gmail.com";
        AppUser expectedUser = new AppUser();
        expectedUser.setEmail(email);
        when(appUserRepository.findAppUserByEmail(email)).thenReturn(expectedUser);

        // Appeler la méthode à tester
        AppUser resultUser = userService.findUserByEmail(email);

        // Vérifier que la méthode appUserRepository.findAppUserByEmail a été appelée avec le bon argument
        verify(appUserRepository).findAppUserByEmail(email);

        // Vérifier le résultat
        assertEquals(expectedUser, resultUser);
    }
}
