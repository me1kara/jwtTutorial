package com.han.jwtTuto.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import com.han.jwtTuto.entity.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities")
    @Query("select u from User u left join fetch u.authorities where u.username = :username")
    Optional<User> findOneWithAuthoritiesByUsername(@Param("username") String username);
}
