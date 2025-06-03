package com.groceryBazar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.model.HomeCategory;

public interface HomeCategoryRepository extends JpaRepository<HomeCategory,Long> {
}
