package com.groceryBazar.service;

import java.util.List;
import java.util.Optional;

import com.groceryBazar.model.Seller;
import com.groceryBazar.model.SellerReport;

public interface SellerReportService {
    SellerReport getSellerReport(Seller seller);
    SellerReport updateSellerReport( SellerReport sellerReport);

}
