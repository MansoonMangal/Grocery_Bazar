package com.groceryBazar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.model.Wishlist;

public interface WishlistRepository extends JpaRepository<Wishlist, Long> {
    Wishlist findByUserId(Long userId);
}
