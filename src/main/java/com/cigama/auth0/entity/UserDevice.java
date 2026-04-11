package com.cigama.auth0.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_devices")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDevice extends BaseAuditEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String deviceId;

    private String deviceSignature; // Hash of browser/hardware fingerprints

    private String ipAddress;

    private String userAgent;

    private LocalDateTime lastLoginAt;

    private boolean isTrusted;
}
