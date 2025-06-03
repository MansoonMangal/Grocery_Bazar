package com.groceryBazar.service;

import java.util.List;

import com.groceryBazar.model.Order;
import com.groceryBazar.model.Seller;
import com.groceryBazar.model.Transaction;
import com.groceryBazar.model.User;

public interface TransactionService {

    Transaction createTransaction(Order order);
    List<Transaction> getTransactionBySeller(Seller seller);
    List<Transaction>getAllTransactions();
}
