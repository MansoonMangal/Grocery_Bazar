package com.groceryBazar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.domain.PayoutsStatus;
import com.groceryBazar.model.Payouts;

import java.util.List;

public interface PayoutsRepository extends JpaRepository<Payouts,Long> {

    List<Payouts> findPayoutsBySellerId(Long sellerId);
    List<Payouts> findAllByStatus(PayoutsStatus status);
}
