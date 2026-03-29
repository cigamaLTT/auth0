package com.cigama.auth0.entity;

import com.cigama.auth0.security.annotation.RegisterField;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @RegisterField
    @Column(name = "email", nullable = false, unique = true, updatable = false)
    private String email;

    @RegisterField
    @Column(name = "phone_number")
    private String phoneNumber;

    @RegisterField
    @Column(name = "first_name")
    private String firstName;

    @RegisterField
    @Column(name = "last_name")
    private String lastName;

    @RegisterField
    @Column(name = "username")
    private String username;

    @RegisterField
    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "is_authorized", nullable = false)
    private Boolean isAuthorized = true;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_clients",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "client_id")
    )
    private Set<ClientApp> clientApps = new HashSet<>();
}
