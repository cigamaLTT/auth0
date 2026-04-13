package com.cigama.auth0.repository;

import com.cigama.auth0.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

    Optional<User> findByUsername(String username);

    @EntityGraph(attributePaths = {"clientApps"})
    @Query("SELECT u FROM User u WHERE u.email = :emailOrUsername OR u.username = :emailOrUsername")
    Optional<User> findWithClientAppsByEmailOrUsername(@Param("emailOrUsername") String emailOrUsername);

    @EntityGraph(attributePaths = {"clientApps"})
    Optional<User> findById(UUID id);
}
