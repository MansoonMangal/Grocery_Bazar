package com.groceryBazar.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.groceryBazar.dto.RevenueChart;
import com.groceryBazar.exception.SellerException;
import com.groceryBazar.model.Seller;
import com.groceryBazar.service.RevenueService;
import com.groceryBazar.service.SellerService;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/seller/revenue/chart")
public class RevenueController {
    private final RevenueService revenueService;
    private final SellerService sellerService;

    @GetMapping()
    public ResponseEntity<List<RevenueChart>> getRevenueChart(
            @RequestParam(defaultValue = "today") String type,
            @RequestHeader("Authorization") String jwt) throws SellerException {
        Seller seller = sellerService.getSellerProfile(jwt);
        List<RevenueChart> revenue = revenueService
                .getRevenueChartByType(type, seller.getId());
        return ResponseEntity.ok(revenue);
    }

}
